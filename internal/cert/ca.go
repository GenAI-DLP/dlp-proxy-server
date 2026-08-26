// internal/cert/ca.go
package cert

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// RootCA는 사내에서 미리 발급받아 직원 PC에 배포해둔 루트 CA
type RootCA struct {
	Cert    *x509.Certificate
	PrivKey *rsa.PrivateKey
}

// LoadRootCA는 PEM 형식의 CA 인증서와 개인키 파일을 읽어옵니다.
func LoadRootCA(certPath, keyPath string) (*RootCA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("CA 인증서 읽기 실패: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("CA 개인키 읽기 실패: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("CA 인증서 PEM 디코딩 실패")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA 인증서 파싱 실패: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("CA 개인키 PEM 디코딩 실패")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA 개인키 파싱 실패: %w", err)
	}

	return &RootCA{Cert: caCert, PrivKey: caKey}, nil
}

// tlsCertFromRootCA는 RootCA 자체를 서버 인증서로도 쓸 수 있게 변환 (fallback용)
func (ca *RootCA) AsTLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{ca.Cert.Raw},
		PrivateKey:  ca.PrivKey,
	}
}