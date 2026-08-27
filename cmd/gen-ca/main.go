// cmd/gen-ca는 로컬 개발/데모용 MITM 루트 CA(인증서+개인키)를 생성합니다.
//
// 주의: 생성되는 개인키(ca-key.pem) git 커밋 금지
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	outDir := flag.String("out", "certs", "생성된 CA 인증서/개인키를 저장할 디렉토리")
	commonName := flag.String("cn", "GenAI-DLP Local Dev Root CA (배포 금지)", "루트 CA Common Name")
	flag.Parse()

	if err := run(*outDir, *commonName); err != nil {
		fmt.Fprintln(os.Stderr, "CA 생성 실패:", err)
		os.Exit(1)
	}
}

func run(outDir, commonName string) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("출력 디렉토리 생성 실패: %w", err)
	}

	certPath := filepath.Join(outDir, "ca.pem")
	keyPath := filepath.Join(outDir, "ca-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("%s가 이미 존재합니다. 기존 CA를 덮어쓰면 신뢰 저장소에 이미 설치된 인증서가 무효화됩니다 — 지우고 다시 실행하세요", certPath)
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("루트 키 생성 실패: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fmt.Errorf("시리얼 번호 생성 실패: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"GenAI-DLP (로컬 개발용)"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:               time.Now().AddDate(2, 0, 0), // 2년
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("인증서 서명 실패: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600); err != nil {
		return err
	}

	fmt.Printf(`루트 CA 생성 완료:
  인증서: %s  (신뢰 저장소에 설치, 배포용 — 민감하지 않음)
  개인키: %s  (반드시 로컬에만 보관, 절대 git에 올리지 말 것)

다음 단계 (Windows 신뢰 저장소에 설치, 로컬 브라우저 테스트용):
  PowerShell에서 관리자 권한으로:
    Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\LocalMachine\Root
`, certPath, keyPath, certPath)
	return nil
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("%s 쓰기 실패: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
