package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCAFiles는 테스트용 CA 인증서/키를 임시 디렉터리에 PEM 파일로 만들어서
// LoadRootCA가 실제 파일 읽기 경로 그대로 테스트되게 합니다.
func writeTestCAFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("테스트 키 생성 실패: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:                pkix.Name{CommonName: "Test Root CA"},
		NotBefore:              time.Now().Add(-time.Hour),
		NotAfter:               time.Now().Add(time.Hour),
		IsCA:                   true,
		KeyUsage:               x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid:  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("테스트 인증서 생성 실패: %v", err)
	}

	dir := t.TempDir() // 테스트 종료 시 자동 삭제됨

	certPath = filepath.Join(dir, "ca.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("cert 파일 생성 실패: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("cert PEM 인코딩 실패: %v", err)
	}

	keyPath = filepath.Join(dir, "ca-key.pem")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("key 파일 생성 실패: %v", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("key PEM 인코딩 실패: %v", err)
	}

	return certPath, keyPath
}

func TestLoadRootCA_Success(t *testing.T) {
	certPath, keyPath := writeTestCAFiles(t)

	ca, err := LoadRootCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadRootCA 실패: %v", err)
	}
	if ca.Cert == nil {
		t.Error("Cert가 nil입니다")
	}
	if ca.PrivKey == nil {
		t.Error("PrivKey가 nil입니다")
	}
	if ca.Cert.Subject.CommonName != "Test Root CA" {
		t.Errorf("CommonName = %q, 원하는 값 = Test Root CA", ca.Cert.Subject.CommonName)
	}
}

func TestLoadRootCA_MissingCertFile(t *testing.T) {
	_, keyPath := writeTestCAFiles(t)

	_, err := LoadRootCA("존재하지않는파일.pem", keyPath)
	if err == nil {
		t.Error("존재하지 않는 인증서 파일인데 에러가 안 남")
	}
}

func TestLoadRootCA_MissingKeyFile(t *testing.T) {
	certPath, _ := writeTestCAFiles(t)

	_, err := LoadRootCA(certPath, "존재하지않는파일.pem")
	if err == nil {
		t.Error("존재하지 않는 키 파일인데 에러가 안 남")
	}
}

func TestLoadRootCA_InvalidCertPEM(t *testing.T) {
	dir := t.TempDir()
	badCertPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badCertPath, []byte("이건 PEM이 아님"), 0644); err != nil {
		t.Fatalf("테스트 파일 생성 실패: %v", err)
	}

	_, keyPath := writeTestCAFiles(t)

	_, err := LoadRootCA(badCertPath, keyPath)
	if err == nil {
		t.Error("잘못된 PEM 형식인데 에러가 안 남")
	}
}

func TestRootCA_AsTLSCertificate(t *testing.T) {
	certPath, keyPath := writeTestCAFiles(t)

	ca, err := LoadRootCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadRootCA 실패: %v", err)
	}

	tlsCert := ca.AsTLSCertificate()
	if len(tlsCert.Certificate) == 0 {
		t.Error("AsTLSCertificate의 Certificate가 비어있음")
	}
	if tlsCert.PrivateKey == nil {
		t.Error("AsTLSCertificate의 PrivateKey가 nil")
	}
}