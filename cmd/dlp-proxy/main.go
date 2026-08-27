package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/cert"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/config"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/inspector"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/proxy/tcp"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "설정 파일 경로")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("설정 로드 실패: %v", err)
	}

	rootCA, err := cert.LoadRootCA(cfg.CA.CertPath, cfg.CA.KeyPath)
	if err != nil {
		log.Fatalf("루트 CA 로드 실패: %v", err)
	}
	issuer := cert.NewIssuer(rootCA)

	dlp, err := dlpclient.NewGRPCClient(cfg.DLPServer.Addr)
	if err != nil {
		log.Fatalf("DLP 서버 연결 실패: %v", err)
	}

	insp := inspector.New(dlp, cfg)

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
