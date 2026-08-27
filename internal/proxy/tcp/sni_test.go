package tcp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestResolveTarget_ExtractsSNIAndReplaysBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("리스너 생성 실패: %v", err)
	}
	defer ln.Close()

	type result struct {
		target *Target
		err    error
	}
	resCh := make(chan result, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- result{nil, err}
			return
		}
		defer conn.Close()

		replayed, target, err := ResolveTarget(conn)
		if err != nil {
			resCh <- result{nil, err}
			return
		}

		// replay된 conn의 첫 바이트가 TLS 핸드셰이크 레코드(0x16)로 시작하는지 확인
		// -> ResolveTarget이 읽어들인 ClientHello 바이트가 유실 없이 재생되는지 검증.
		header := make([]byte, 5)
		if _, err := io.ReadFull(replayed, header); err != nil {
			resCh <- result{nil, err}
			return
		}
		if header[0] != 0x16 {
			resCh <- result{nil, fmt.Errorf("TLS handshake record type 아님: %#x", header[0])}
			return
		}

		resCh <- result{target, nil}
	}()

	clientConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("클라이언트 연결 실패: %v", err)
	}
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(2 * time.Second))

	tlsClient := tls.Client(clientConn, &tls.Config{ServerName: "chatgpt.com", InsecureSkipVerify: true})
	// 서버(ResolveTarget)가 의도적으로 핸드셰이크를 중단하므로 클라이언트 쪽은 에러가 나는 게 정상
	handshakeErr := tlsClient.Handshake()
	if handshakeErr == nil {
		t.Fatalf("클라이언트 핸드셰이크가 예상과 달리 성공함")
	}
	if strings.Contains(handshakeErr.Error(), "remote error") {
		t.Fatalf("SNI peek 중 클라이언트에게 TLS alert가 새어나감: %v", handshakeErr)
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("SNI 추출 실패: %v", res.err)
	}
	if res.target.Host != "chatgpt.com" {
		t.Fatalf("SNI 불일치: got %q, want %q", res.target.Host, "chatgpt.com")
	}
	if res.target.Port != defaultTLSPort {
		t.Fatalf("포트 불일치: got %q, want %q", res.target.Port, defaultTLSPort)
	}
}
