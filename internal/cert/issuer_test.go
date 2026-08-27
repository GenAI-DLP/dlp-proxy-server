package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// generateTestCA는 실제 파일을 안 거치고 테스트용 RootCA를 메모리에서 바로 생성합니다.
func generateTestCA(t *testing.T) *RootCA {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("테스트 CA 키 생성 실패: %v", err)
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
		t.Fatalf("테스트 CA 인증서 생성 실패: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("테스트 CA 파싱 실패: %v", err)
	}

	return &RootCA{Cert: cert, PrivKey: key}
}

func TestIssuer_GetCertificate_IssuesForSNI(t *testing.T) {
	ca := generateTestCA(t)
	issuer := NewIssuer(ca)

	hello := &tls.ClientHelloInfo{ServerName: "chatgpt.com"}
	cert, err := issuer.GetCertificate(hello)
	if err != nil {
		t.Fatalf("인증서 발급 실패: %v", err)
	}
	if cert == nil {
		t.Fatal("인증서가 nil입니다")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("발급된 leaf 인증서 파싱 실패: %v", err)
	}
	if leaf.Subject.CommonName != "chatgpt.com" {
		t.Errorf("CommonName = %q, 원하는 값 = chatgpt.com", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "chatgpt.com" {
		t.Errorf("DNSNames = %v, 원하는 값 = [chatgpt.com]", leaf.DNSNames)
	}
}

func TestIssuer_GetCertificate_SignedByCA(t *testing.T) {
	ca := generateTestCA(t)
	issuer := NewIssuer(ca)

	cert, err := issuer.GetCertificate(&tls.ClientHelloInfo{ServerName: "claude.ai"})
	if err != nil {
		t.Fatalf("인증서 발급 실패: %v", err)
	}

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])

	// leaf 인증서가 실제로 우리 CA가 서명했는지 검증
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName: "claude.ai",
		Roots:   roots,
	})
	if err != nil {
		t.Errorf("발급된 인증서가 CA 체인 검증 실패: %v", err)
	}
}

func TestIssuer_GetCertificate_NoSNI(t *testing.T) {
	ca := generateTestCA(t)
	issuer := NewIssuer(ca)

	_, err := issuer.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	if err == nil {
		t.Error("SNI 없을 때 에러가 나야 하는데 nil 리턴됨")
	}
}

func TestIssuer_GetCertificate_Caching(t *testing.T) {
	ca := generateTestCA(t)
	issuer := NewIssuer(ca)

	hello := &tls.ClientHelloInfo{ServerName: "gemini.google.com"}

	cert1, err := issuer.GetCertificate(hello)
	if err != nil {
		t.Fatalf("첫 발급 실패: %v", err)
	}
	cert2, err := issuer.GetCertificate(hello)
	if err != nil {
		t.Fatalf("두번째 발급 실패: %v", err)
	}

	// 캐시가 동작하면 같은 인증서(같은 serial number)가 나와야 함
	leaf1, _ := x509.ParseCertificate(cert1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(cert2.Certificate[0])
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Error("같은 SNI인데 캐시 안 타고 매번 새로 발급됨 (serial number가 다름)")
	}
}

func TestIssuer_GetCertificate_DifferentSNI_DifferentCert(t *testing.T) {
	ca := generateTestCA(t)
	issuer := NewIssuer(ca)

	certA, _ := issuer.GetCertificate(&tls.ClientHelloInfo{ServerName: "chatgpt.com"})
	certB, _ := issuer.GetCertificate(&tls.ClientHelloInfo{ServerName: "claude.ai"})

	leafA, _ := x509.ParseCertificate(certA.Certificate[0])
	leafB, _ := x509.ParseCertificate(certB.Certificate[0])

	if leafA.Subject.CommonName == leafB.Subject.CommonName {
		t.Error("서로 다른 SNI인데 같은 인증서가 나옴")
	}
}