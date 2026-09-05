// cmd/dlp-proxy/main.go
package main

import (
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/cert"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/config"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/inspector"
	quicproxy "github.com/GenAI-DLP/dlp-proxy-server/internal/proxy/quic"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/proxy/tcp"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	cfg, err := config.Load("configs/config.yaml")
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
	defer dlp.Close()

	insp := inspector.New(dlp, cfg)

	log.Printf("DLP Proxy Server 준비 완료 (fail_policy=%s, allowlist=%v)", cfg.FailPolicy, cfg.Allowlist)

	// TCP 프록시 기동
	tcpServer := tcp.NewServer(cfg, issuer, insp)
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Fatalf("TCP 프록시 리스너 실패: %v", err)
		}
	}()

	// QUIC(HTTP/3) 프록시 기동
	quicServer, err := quicproxy.Start(cfg, issuer, insp)
	if err != nil {
		log.Fatalf("QUIC 프록시 준비 실패: %v", err)
	}
	go func() {
		if err := quicServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("QUIC 프록시 리스너 실패: %v", err)
		}
	}()

	waitForShutdown(dlp, tcpServer, quicServer)
}

func waitForShutdown(dlp *dlpclient.GRPCClient, tcpServer *tcp.Server, quicServer *http3.Server) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("종료 시그널 수신(%v), graceful shutdown 시작", sig)

	if err := quicServer.Close(); err != nil {
		log.Printf("QUIC 프록시 리스너 종료 중 에러: %v", err)
	}
	if err := tcpServer.Close(); err != nil {
		log.Printf("TCP 프록시 리스너 종료 중 에러: %v", err)
	}
	if err := dlp.Close(); err != nil {
		log.Printf("DLP 서버 gRPC 커넥션 종료 중 에러: %v", err)
	}
}