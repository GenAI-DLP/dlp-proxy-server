// cmd/gen-ca/main.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// gen-ca는 로컬/개발 환경에서 DLP 프록시의 MITM에 쓸 자체 서명 루트 CA를 생성합니다.
// 운영 환경에서는 사내 PKI 팀이 발급한 정식 CA를 써야 하며, 이 도구는 개발용입니다.
func main() {
	outDir := "certs"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("certs 디렉터리 생성 실패: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096) // 루트 CA는 leaf보다 긴 키 사용
	if err != nil {
		log.Fatalf("CA 키 생성 실패: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		log.Fatalf("일련번호 생성 실패: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "DLP Proxy Local Root CA (DEV ONLY)",
			Organization: []string{"GenAI-DLP"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0), // 5년
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("CA 인증서 생성 실패: %v", err)
	}

	certPath := filepath.Join(outDir, "ca.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		log.Fatalf("%s 생성 실패: %v", certPath, err)
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyPath := filepath.Join(outDir, "ca-key.pem")
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // 개인키는 권한 제한
	if err != nil {
		log.Fatalf("%s 생성 실패: %v", keyPath, err)
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	log.Printf("루트 CA 생성 완료: %s, %s", certPath, keyPath)
	log.Println("주의: 이 CA는 개발/테스트 전용입니다. 직원 PC에 신뢰하도록 설치해야 MITM이 성립합니다.")
}