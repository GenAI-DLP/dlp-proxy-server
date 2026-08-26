// internal/proxy/tcp/server.go
package tcp

import (
	"log"
	"net"
	"sync/atomic"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/cert"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/config"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/inspector"
)

// Server는 TCP/TLS 트래픽을 가로채는 투명 프록시 리스너입니다.
type Server struct {
	cfg       *config.Config
	issuer    *cert.Issuer
	inspector *inspector.Inspector

	listener net.Listener
	closed   atomic.Bool
}

func NewServer(cfg *config.Config, issuer *cert.Issuer, insp *inspector.Inspector) *Server {
	return &Server{cfg: cfg, issuer: issuer, inspector: insp}
}

// ListenAndServe는 cfg.Listen.TCPAddr에서 accept 루프를 블로킹으로 실행합니다.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen.TCPAddr)
	if err != nil {
		return err
	}
	s.listener = ln
	log.Printf("tcp: 프록시 리스닝 시작 (%s)", s.cfg.Listen.TCPAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			log.Printf("tcp: accept 실패: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) Close() error {
	s.closed.Store(true)
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}
