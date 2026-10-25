# 🛰️ DLP Proxy Server

외부 LLM 트래픽을 네트워크 레벨에서 가로채 DLP 판정을 **집행**하는 투명 MITM 프록시 (Go · TLS · QUIC/HTTP3 · gRPC)

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white)
![gRPC](https://img.shields.io/badge/gRPC-244c5a?style=flat-square&logo=google&logoColor=white)
![QUIC](https://img.shields.io/badge/QUIC-HTTP%2F3-6E4AFF?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

직원 PC에서 ChatGPT · Claude · Gemini로 나가는 HTTPS 트래픽은 암호화되어 있어 기존 네트워크 DLP가 내용을 볼 수 없습니다. dlp-proxy-server는 **검사 대상 도메인만 골라 TLS를 종단**하고, 평문 요청·응답을 [dlp-server](https://github.com/GenAI-DLP/dlp-server)에 넘겨 받은 판정(`allow` / `block` / `transform`)을 그대로 집행합니다.

**판단은 dlp-server가, 집행은 프록시가** 하도록 역할을 명확히 나눴습니다. 프록시에는 PII 탐지나 정책 로직이 전혀 없고, 대신 네트워크 계층에서만 할 수 있는 일(목적지 판별, 인증서 발급, TLS 종단, 중계, 장애 대응)에 집중합니다.


## 🗺️ 동작 흐름

```
[직원 PC] ──TLS(ClientHello)──▶ [dlp-proxy-server :8443]
                                    │
                                    ├─ SNI 추출 → allowlist?
                                    │     ├─ No  → 복호화 없이 TCP 그대로 중계 (passthrough)
                                    │     └─ Yes → SNI별 leaf 인증서 즉석 발급 → TLS 종단(MITM)
                                    │
                                    ├─ HTTP 파싱 · 세션 ID 추출
                                    ├─ gRPC Inspect(input)  ──▶ [dlp-server]
                                    │     block     → 403 반환, 업스트림 호출 안 함
                                    │     transform → 변환된 본문으로 교체
                                    │
                                    ├─ 실제 LLM에 새 TLS 연결로 중계 (응답 전체 버퍼링)
                                    │
                                    ├─ gRPC Inspect(output) ──▶ [dlp-server]
                                    │     block     → 403 반환
                                    │     transform → 변환된(복원된) 응답으로 교체
                                    ▼
                               [직원 PC]  + X-Dlp-Input-Action / X-Dlp-Output-Action 헤더
```

## ✨ 구현한 기능

| 기능 | 모듈 | 내용 |
|---|---|---|
| **SNI 기반 목적지 판별** | `internal/proxy/tcp/sni.go` | 투명 프록시로 들어온 연결에서 TLS ClientHello만 **엿보고(peek)** SNI를 추출한 뒤, 읽은 바이트를 그대로 앞에 붙여 재생하는 `net.Conn`을 돌려줍니다. 클라이언트는 아직 아무 응답도 받지 않은 상태라 이후 MITM이든 passthrough든 자연스럽게 이어집니다 |
| **allowlist 선택적 검사** | `internal/config` | `chatgpt.com`, `claude.ai`, `gemini.google.com`, `generativelanguage.googleapis.com`만 TLS 종단. 그 외 도메인은 **복호화 없이** 양방향 TCP 중계만 해서 업무 외 트래픽의 프라이버시와 성능을 지킵니다 |
| **동적 인증서 발급** | `internal/cert` | 사내 루트 CA로 SNI별 leaf 인증서를 즉석 서명하고 `sync.Map`으로 캐싱. TCP·QUIC 핸드셰이크에 `GetCertificate` 콜백으로 바로 연결 |
| **TCP(HTTP/1.1) MITM 프록시** | `internal/proxy/tcp` | TLS 종단 → HTTP 요청 파싱 → input 검사 → 업스트림에 새 TLS 연결로 중계 → 응답 전체 수신 → output 검사 → 응답 재작성 |
| **QUIC(HTTP/3) MITM 프록시** | `internal/proxy/quic` | `quic-go/http3` 기반 UDP `:8443` 리스너. TCP와 같은 Inspector를 공유해 동일한 판정 로직을 HTTP/3 트래픽에도 적용 |
| **판정 집행기 (Inspector)** | `internal/inspector` | gRPC 호출 + 타임아웃 + fail-policy만 담당하는 얇은 계층. 정의되지 않은 action이 오면 차단. TCP·QUIC 프록시가 모두 이 결과만 보고 실행 |
| **gRPC 클라이언트** | `internal/dlpclient` | [dlp-proto](https://github.com/GenAI-DLP/dlp-proto) 계약 기반 순수 통신 계층. 판정 로직과 분리 |
| **세션 식별** | `internal/session` | `X-Corp-User-Id` 헤더 → 서비스 세션 쿠키 → 원격 주소 순으로 세션 ID를 추출해 dlp-server의 멀티턴 분석 키로 전달 |
| **fail-closed 장애 정책** | `internal/inspector` | dlp-server 타임아웃(3초)·연결 실패 시 기본 **차단**. 결과에 `FailPolicyApplied` 플래그를 남겨 "DLP 판단에 의한 차단"과 "장애 대응 차단"을 로그·대시보드에서 구분 |
| **개발 도구** | `cmd/gen-ca`, `cmd/mock-dlp-server` | 로컬용 자체 서명 루트 CA 생성기, allow/block/transform을 골라 반환하는 DLP 서버 대역 |


## 🔍 설계하며 고민한 지점

1. **차단 응답에 판정 근거를 노출하지 않음**
   - 처음에는 `reason`을 403 본문에 실었지만, 어떤 패턴에 걸렸는지 알려주면 우회 방법을 가르쳐주는 셈이라 제거했습니다.
   - 클라이언트에는 `blocked by DLP policy`만 돌려주고, 상세 근거는 서버 로그와 dlp-server 감사 로그에만 남깁니다.
2. **대신 최소 신호는 헤더로**
   - UI가 "허용 / 변환 / 차단" 배지를 그릴 수 있도록 `X-Dlp-Input-Action`, `X-Dlp-Output-Action` 응답 헤더만 실어 보냅니다.
3. **업스트림에도 별도 상한**
   - 지연 예산(3초)은 dlp-server 호출에만 걸려 있어서, 연결은 됐는데 응답이 느리게 흘러나오는 업스트림에 무한정 묶일 수 있었습니다.
   - 업스트림 연결에 30초 deadline을 따로 두었습니다.
4. **graceful shutdown 수정**
   - `log.Fatalf`가 정리 전에 프로세스를 죽이던 문제를 고치고, SIGINT/SIGTERM 수신 시 QUIC → TCP 리스너 → gRPC 커넥션 순서로 닫습니다.
   -  이를 위해 QUIC 서버가 `*http3.Server`를 돌려주도록 구조를 바꿨습니다.
5. **CA 개인키 보호**
   - `gen-ca`는 기존 CA를 덮어쓰지 않으며(이미 신뢰 저장소에 설치된 CA 무효화 방지), `certs/`는 `.gitignore`와 `.dockerignore`에 넣고 Docker에서는 읽기 전용 볼륨으로만 마운트합니다.
6. **leaf 인증서 유효기간 24시간 → 90일**
   - 장시간 시연 중 캐시된 인증서가 만료되어 핸드셰이크가 깨지는 문제를 해결했습니다.
7. **proto 계약은 독립 저장소로**
   - 처음엔 레포 안에 두었다가, dlp-server · gateway와 같은 계약을 공유하도록 [dlp-proto](https://github.com/GenAI-DLP/dlp-proto) 서브모듈로 전환했습니다.


## 🚀 빠른 시작

### 요구사항

- Go 1.26+
- 실행 중인 [dlp-server](https://github.com/GenAI-DLP/dlp-server) (없으면 `mock-dlp-server`로 대체)

### 1. 루트 CA 생성 (최초 1회)

```bash
go run ./cmd/gen-ca
```

`certs/ca.pem`, `certs/ca-key.pem`이 생성됩니다. 출력되는 명령으로 `ca.pem`을 OS 신뢰 저장소에 설치하세요. 이 CA는 **개발 전용**이며, 운영 환경에서는 사내 PKI가 발급한 정식 CA를 사용해야 합니다.

### 2. 실행

반드시 **DLP 서버(또는 mock)를 먼저** 띄우세요. 프록시가 먼저 뜨면 gRPC 재연결 백오프 때문에 한동안 실패한 것처럼 보일 수 있습니다.

```bash
# 터미널 ① — 실제 dlp-server 또는 mock
go run ./cmd/mock-dlp-server -action allow      # allow | block | transform

# 터미널 ② — 프록시 (TCP + QUIC 모두 :8443)
go run ./cmd/dlp-proxy -config configs/config.yaml
```

### 3. 스모크 테스트

```bash
# MITM + 판정 경로 (allowlist 도메인)
curl --resolve chatgpt.com:8443:127.0.0.1 https://chatgpt.com:8443 --cacert certs/ca.pem -v

# passthrough 경로 (allowlist 밖 도메인 — 원본 인증서 그대로)
curl --resolve example.com:8443:127.0.0.1 https://example.com:8443 -v
```

| 확인할 경로 | 방법 | 기대 결과 |
|---|---|---|
| allow | mock `-action allow` | 실제 업스트림 응답, mock에 input·output 로그 2회 |
| block | mock `-action block` | `403` + `X-Dlp-Input-Action: block` |
| transform | mock `-action transform -transformed-body ...` | 지정한 본문이 그대로 반환 |
| fail-closed | mock 없이 실행 | `403` (장애 대응 차단) |
| passthrough | allowlist 밖 도메인 | 복호화 없이 원본 응답 |

Windows/PowerShell 환경의 상세 절차는 [TCP 로컬 테스트 가이드](docs/tcp-local-testing-guide.md)를 참고하세요.

### Docker

```bash
docker build -t dlp-proxy-server .
docker run -p 8443:8443/tcp -p 8443:8443/udp \
  -v $(pwd)/certs:/app/certs:ro \
  dlp-proxy-server -config configs/config.docker.yaml
```

distroless 이미지로 빌드되며, `certs/`는 이미지에 포함하지 않습니다.

## ⚙️ 설정 (`configs/config.yaml`)

```yaml
listen:
  tcp_addr: ":8443"            # TLS (HTTP/1.1)
  udp_addr: ":8443"            # QUIC (HTTP/3)

dlp_server:
  addr: "localhost:50051"      # Docker에서는 "dlp-server:50051" (config.docker.yaml)
  timeout: "3s"                # 아키텍처 §2.4 프록시 deadline

ca:
  cert_path: "./certs/ca.pem"
  key_path: "./certs/ca-key.pem"

allowlist:                     # TLS 종단(검사) 대상 도메인
  - "chatgpt.com"
  - "claude.ai"
  - "gemini.google.com"
  - "generativelanguage.googleapis.com"

fail_policy: "closed"          # closed(기본, 차단) | open(통과)
```

## 🧪 Test

```bash
go test ./...
```

| 패키지 | 검증 내용 |
|---|---|
| `internal/cert` | 루트 CA 로드·오류 케이스, SNI별 leaf 발급, CA 서명 검증, 캐싱, SNI 누락 |
| `internal/config` | yaml 로딩, fail_policy·timeout 기본값, 잘못된 값 검증, allowlist 매칭 |
| `internal/dlpclient` | Inspect allow/block 왕복, gRPC 오류 전파, HTTP 헤더 → proto map 변환 |
| `internal/inspector` | allow/block/transform 매핑, 미정의 action 차단, DLP 미응답 시 fail-closed/open |
| `internal/proxy/tcp` | ClientHello에서 SNI 추출 후 읽은 바이트 재생 |


## 📁 프로젝트 폴더 구조

```
cmd/
├── dlp-proxy/          # 엔트리포인트 — TCP·QUIC 리스너 기동 + graceful shutdown
├── gen-ca/             # 개발용 루트 CA 생성
└── mock-dlp-server/    # DLP 서버 대역 (판정 고정 반환)
internal/
├── config/             # yaml 설정 로더, allowlist
├── cert/               # 루트 CA 로드, SNI별 leaf 인증서 발급·캐시
├── session/            # 세션 ID 추출
├── dlpclient/          # gRPC 클라이언트 (+ pb 생성물)
├── inspector/          # 판정 집행 · fail-policy
└── proxy/
    ├── tcp/            # SNI peek, passthrough, TLS MITM, 업스트림 중계
    └── quic/           # HTTP/3 MITM 핸들러·서버
configs/                # config.yaml (로컬) / config.docker.yaml
docs/                   # 로컬 테스트 가이드
```


## ⚠️ 현재 한계

- 목적지 포트를 항상 443으로 가정합니다.
- ECH/ESNI로 SNI가 숨겨진 연결은 목적지를 판별할 수 없어 처리하지 않습니다.
- TCP 경로는 HTTP/1.1만 협상하며, 연결당 요청 하나를 처리합니다.
- 스트리밍 응답(SSE)은 전체를 버퍼링한 뒤 한 번에 검사합니다. 청크 단위 검사는 양방향 스트리밍 gRPC가 필요해 범위 밖입니다.
- 네트워크 레벨 투명 리다이렉트(WinDivert, iptables 등)는 이 레포 범위 밖이며, 로컬에서는 `--resolve`로 대체해 검증합니다.

## 📚 관련 문서

- [dlp-proxy-server 아키텍처](https://github.com/GenAI-DLP/docs/blob/main/architecture/dlp-proxy-server-architecture.md)
- [gRPC 계약 (dlp-proto)](https://github.com/GenAI-DLP/docs/blob/main/architecture/dlp-proto.md)
- [전체 프로젝트 소개](https://github.com/GenAI-DLP)
