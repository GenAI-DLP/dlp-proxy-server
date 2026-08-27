package quic

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/cert"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/config"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/inspector"
	"github.com/quic-go/quic-go/http3"
)

// Start는 QUIC 리스너를 열고 직원 PC의 HTTP/3 요청을 받기 시작합니다.
func Start(cfg *config.Config, issuer *cert.Issuer, insp *inspector.Inspector) error {
	proxy := &DLPProxy{
		Inspector: insp,
		Upstream:  &http3.Transport{}, 
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// allowlist 체크를 TLS 핸드셰이크 단계에서 먼저 수행합니다.
			// 감시 대상이 아닌 도메인은 인증서 발급 자체를 거부해서 MITM하지 않습니다.
			if !cfg.IsAllowlisted(hello.ServerName) {
				return nil, fmt.Errorf("SNI %s는 검사 대상이 아님, MITM 거부", hello.ServerName)
			}
			return issuer.GetCertificate(hello)
		},
	}

	server := &http3.Server{
		Addr:      cfg.Listen.UDPAddr,
		TLSConfig: tlsConfig,
		Handler:   proxy,
	}

	log.Printf("QUIC DLP 프록시 시작: %s (fail_policy=%s, 감시 대상 %d개)",
		cfg.Listen.UDPAddr, cfg.FailPolicy, len(cfg.Allowlist))
	return server.ListenAndServe()
}