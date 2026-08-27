# DLP Proxy Server — 로컬 테스트 가이드

> `internal/proxy/tcp` (투명 프록시 + MITM)가 실제로 동작하는지 로컬 PC에서 확인하는 방법입니다.
> FastAPI DLP 서버가 아직 없으므로 `cmd/mock-dlp-server`로 대체합니다.
> Windows + PowerShell 기준으로 작성했습니다.

---

## 1. 터미널 3개 구성

동시에 떠 있어야 하는 프로세스가 3개라 터미널도 3개 필요합니다.

| 터미널 | 실행 명령 | 역할 |
|--------|-----------|------|
| ① | `go run ./cmd/mock-dlp-server -action allow` | DLP 서버 대역 (기본 `:50051`) |
| ② | `go run ./cmd/dlp-proxy` | TCP 프록시 (기본 `:8443`) — **①을 먼저 띄운 뒤에 실행할 것** (아래 "주의" 참고) |
| ③ | curl 등 클라이언트 명령 실행용 | — |

**주의(gRPC 재연결 백오프)**: `dlp-proxy`가 뜬 시점에 `mock-dlp-server`가 아직 안 떠 있으면, 첫 DLP 호출이 실패하면서 gRPC 클라이언트가 지수 백오프(최대 120초 간격)로 재연결을 시도합니다. 그 상태에서 `mock-dlp-server`를 나중에 띄워도 다음 백오프 주기가 돌아올 때까지 계속 실패한 것처럼 보일 수 있습니다 — 항상 **①(mock) → ②(proxy) 순서로 띄우세요.** 순서를 놓쳤다면 ②를 Ctrl+C 후 재실행하면 바로 해결됩니다.

## 2. 준비 단계 (최초 1회)

```bash
go run ./cmd/gen-ca
```
`certs/ca.pem`, `certs/ca-key.pem` 생성. 이미 있으면 에러(덮어쓰지 않음 — 신뢰 저장소에 이미 설치된 CA 무효화 방지).

출력되는 `Import-Certificate` 명령을 **관리자 권한 PowerShell**에서 실행해 Windows 신뢰 저장소에 설치.

## 3. 실행

```bash
# 터미널 ①
go run ./cmd/mock-dlp-server -action allow

# 터미널 ②
go run ./cmd/dlp-proxy
```

## 4. 스모크 테스트 (터미널 ③)

**PowerShell 기본 `curl`은 `Invoke-WebRequest` 별칭이라 아래 플래그를 못 씁니다 — 반드시 `curl.exe`로 명시하세요.**

### 4.1 MITM + allow 경로 (mock이 `allow` 반환 중)

```bash
curl.exe --resolve chatgpt.com:8443:127.0.0.1 https://chatgpt.com:8443 --cacert certs/ca.pem --ssl-no-revoke -v
```

- `--resolve host:PORT:IP`의 `PORT`는 **URL에 명시한 포트와 같아야 적용됨** — URL에 포트를 안 쓰면 기본 443로 나가버려서 우리 프록시(`:8443`)를 그냥 지나쳐 진짜 인터넷으로 나감. 그래서 URL에도 `:8443`을 붙임.
- `--ssl-no-revoke`: Windows schannel이 로컬 self-signed 개발용 CA는 CRL/OCSP 폐기 목록이 없어서 "revocation status unknown"으로 막는 것을 우회. 실제 신뢰 체인 문제 아님.
- 기대 결과: mock이 `allow`를 반환하므로 프록시가 실제 `chatgpt.com`에 연결해 받아온 응답을 그대로 돌려줌. 터미널 ①(mock)에 `direction=input`, `direction=output` 두 번 로그가 찍힘.

### 4.2 block / transform 경로

터미널 ①을 껐다가 다른 `-action`으로 재실행(이후 터미널 ②도 재시작 — 위 "주의" 참고):
```bash
go run ./cmd/mock-dlp-server -action block
go run ./cmd/mock-dlp-server -action transform
```
`block`이면 403 + `-reason`으로 지정한 문구, `transform`이면 `-transformed-body`로 지정한 본문이 그대로 클라이언트에 돌아오는지 확인.

### 4.3 fail-closed 경로 (mock 없이)

터미널 ①을 안 띄운 상태(또는 꺼진 상태)로 4.1과 같은 curl 실행 → `403 Forbidden` + `blocked by DLP policy: dlp_unreachable: ...` 응답이 정상(`configs/config.yaml`의 `fail_policy: closed` 기본값 동작 확인).

### 4.4 passthrough 경로 (allowlist 밖 도메인)

우리 CA가 필요 없음(TLS 종단을 안 하므로 원본 서버 인증서 그대로 검증됨):
```bash
curl.exe --resolve example.com:8443:127.0.0.1 https://example.com:8443 -v
```

## 5. 한계

- **실제 투명 리다이렉트**: 여기서는 curl에게 `--resolve`로 목적지를 직접 프록시(`127.0.0.1:8443`)로 겨냥해준 것이지, 네트워크 레벨 투명 리다이렉트(Windows WinDivert 등)를 테스트하는 게 아닙니다.
- **목적지 포트가 443이 아닌 경우**: `ResolveTarget`이 포트를 항상 443으로 가정하므로 다른 포트로 가는 allowlist 트래픽은 지원하지 않습니다.
