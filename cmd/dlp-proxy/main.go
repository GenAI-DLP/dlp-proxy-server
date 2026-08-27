// cmd/dlp-proxy/main.go
package main

import (
	"log"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/cert"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/config"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/inspector"
	quicproxy "github.com/GenAI-DLP/dlp-proxy-server/internal/proxy/quic"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/proxy/tcp"
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
	log.Printf("DLP Proxy Server 준비 완료 (fail_policy=%s, allowlist=%v)", cfg.FailPolicy, cfg.Allowlist)

	tcpServer := tcp.NewServer(cfg, issuer, insp)
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("TCP 프록시 리스너 실패: %v", err)
		}
	}()

	// TODO(UDP 담당): internal/proxy/udp 리스너를 cfg.Listen.UDPAddr, issuer, insp로 기동

	waitForShutdown(dlp, tcpServer)
}

func waitForShutdown(dlp *dlpclient.GRPCClient, tcpServer *tcp.Server) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("종료 시그널 수신(%v), graceful shutdown 시작", sig)

	// TODO: UDP 리스너 정리(Close/Shutdown)도 여기 추가
	if err := tcpServer.Close(); err != nil {
		log.Printf("TCP 프록시 리스너 종료 중 에러: %v", err)
	}
	if err := dlp.Close(); err != nil {
		log.Printf("DLP 서버 gRPC 커넥션 종료 중 에러: %v", err)
	}
}
