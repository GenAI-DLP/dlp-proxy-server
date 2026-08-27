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
// 호출부(main.go)가 graceful shutdown 시 Close할 수 있도록 *http3.Server를 리턴합니다.
// ListenAndServe는 블로킹 호출이므로 반드시 별도 고루틴에서 호출해야 합니다.
func Start(cfg *config.Config, issuer *cert.Issuer, insp *inspector.Inspector) (*http3.Server, error) {
	proxy := &DLPProxy{
		Inspector: insp,
		Upstream:  &http3.Transport{},
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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

	log.Printf("QUIC DLP 프록시 준비: %s (fail_policy=%s, 감시 대상 %d개)",
		cfg.Listen.UDPAddr, cfg.FailPolicy, len(cfg.Allowlist))

	return server, nil
}