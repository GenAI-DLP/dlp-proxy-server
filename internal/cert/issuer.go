// internal/cert/issuer.go
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// Issuer는 SNI별 leaf 인증서를 발급하고 캐싱합니다.
type Issuer struct {
	ca    *RootCA
	cache sync.Map // key: SNI(string) -> value: *tls.Certificate
}

func NewIssuer(ca *RootCA) *Issuer {
	return &Issuer{ca: ca}
}

// GetCertificate는 tls.Config.GetCertificate에 바로 연결하는 콜백입니다.
// QUIC 핸드셰이크 시 클라이언트가 보낸 SNI(예: chatgpt.com)를 보고
// 그 이름으로 서명된 인증서를 캐시에서 찾거나 즉석 발급합니다.
func (iss *Issuer) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := hello.ServerName
	if sni == "" {
		return nil, fmt.Errorf("SNI 없음, 인증서 발급 불가")
	}

	if cached, ok := iss.cache.Load(sni); ok {
		cert := cached.(*tls.Certificate)
		// 만료 임박 체크는 생략(운영 시 추가 권장)
		return cert, nil
	}

	cert, err := iss.issue(sni)
	if err != nil {
		return nil, err
	}
	iss.cache.Store(sni, cert)
	return cert, nil
}

func (iss *Issuer) issue(sni string) (*tls.Certificate, error) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("leaf 키 생성 실패: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		DNSNames:     []string{sni},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour), // 짧게 잡고 캐시 만료 시 재발급 권장
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, iss.ca.Cert, &leafKey.PublicKey, iss.ca.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("leaf 인증서 서명 실패: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{leafDER, iss.ca.Cert.Raw}, // leaf + CA 체인
		PrivateKey:  leafKey,
	}, nil
}