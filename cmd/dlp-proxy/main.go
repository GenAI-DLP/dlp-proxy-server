// cmd/dlp-proxy/main.go
package main

import (
	"log"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/cert"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/config"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/inspector"
	quicproxy "github.com/GenAI-DLP/dlp-proxy-server/internal/proxy/quic"
)

func main() {
	// 1. 설정 로드 (configs/config.yaml)
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		log.Fatalf("설정 로드 실패: %v", err)
	}

	// 2. 사내 루트 CA 로드 (없으면 cmd/gen-ca로 먼저 생성해야 함)
	rootCA, err := cert.LoadRootCA(cfg.CA.CertPath, cfg.CA.KeyPath)
	if err != nil {
		log.Fatalf("루트 CA 로드 실패: %v", err)
	}
	issuer := cert.NewIssuer(rootCA)

	// 3. FastAPI DLP 서버 gRPC 클라이언트 생성 (순수 통신 계층)
	dlp, err := dlpclient.NewGRPCClient(cfg.DLPServer.Addr)
	if err != nil {
		log.Fatalf("DLP 서버 연결 실패: %v", err)
	}
	defer dlp.Close()

	// 4. Inspector 생성 (DLP 서버 호출 + fail-policy 적용을 담당)
	insp := inspector.New(dlp, cfg)

	// 5. QUIC(HTTP/3) 프록시 기동
	log.Printf("DLP Proxy(QUIC) 기동 준비 완료, listen=%s", cfg.Listen.UDPAddr)
	if err := quicproxy.Start(cfg, issuer, insp); err != nil {
		log.Fatalf("QUIC 프록시 실행 실패: %v", err)
	}
}