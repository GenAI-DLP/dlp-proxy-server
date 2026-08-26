# DLP Proxy Server

Go로 작성된 DLP(Data Loss Prevention) 프록시 서버입니다.
TCP/UDP 트래픽을 검사하여 민감 정보 유출을 탐지 및 차단합니다.

## 주요 기능

- **TCP Proxy 검사**: TCP 트래픽을 가로채 DLP 정책에 따라 검사
- **UDP Proxy 검사**: UDP 트래픽을 가로채 DLP 정책에 따라 검사

## 폴더 구조

```
dlp-proxy-server/
├── cmd/
│   └── dlp-proxy/          # 엔트리포인트 (main.go)
├── internal/
│   ├── config/             # 설정 로드 (yaml/env 파싱)
│   ├── proxy/
│   │   ├── tcp/            # 기능 a: TCP Proxy 검사
│   │   └── udp/            # 기능 b: UDP Proxy 검사
│   ├── inspector/          # 공통 DLP 검사 로직
│   └── logger/             # 로깅
├── configs/                # 설정 파일 (config.yaml 등)
├── go.mod
├── go.sum
└── README.md
```

## 시작하기

```bash
go mod tidy
go run ./cmd/dlp-proxy
```
