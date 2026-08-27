// internal/proxy/tcp/sni.go
package tcp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
)

const defaultTLSPort = "443"

type Target struct {
	Host string
	Port string
}

func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, t.Port)
}

// ResolveTarget은 투명 프록시로 들어온 연결에서 목적지를 판별합니다.
func ResolveTarget(conn net.Conn) (net.Conn, *Target, error) {
	peeked, sni, err := peekClientHelloSNI(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("SNI 추출 실패: %w", err)
	}
	if sni == "" {
		return nil, nil, errors.New("ClientHello에 SNI 없음(ESNI/ECH 등) - 목적지 판별 불가")
	}
	return peeked, &Target{Host: sni, Port: defaultTLSPort}, nil
}

// peekClientHelloSNI는 conn에서 TLS ClientHello만큼만 읽어 SNI를 추출하고,
// 읽은 바이트를 그대로 앞에 붙여 재생하는 net.Conn을 돌려줍니다.
// 클라이언트 입장에서는 아직 아무 응답도 못 받은 상태입니다.
func peekClientHelloSNI(conn net.Conn) (net.Conn, string, error) {
	var captured bytes.Buffer
	tee := &teeReadConn{Conn: conn, tee: &captured}

	var sni string
	errStop := errors.New("stop after clienthello peek")

	cfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, errStop
		},
	}

	err := tls.Server(tee, cfg).Handshake()
	if err == nil {
		return nil, "", errors.New("예상치 못하게 핸드셰이크가 끝까지 진행됨")
	}
	if !strings.Contains(err.Error(), errStop.Error()) {
		return nil, "", fmt.Errorf("ClientHello 파싱 실패: %w", err)
	}

	replay := &replayConn{Conn: conn, buf: bytes.NewReader(captured.Bytes())}
	return replay, sni, nil
}

// teeReadConn은 Read를 통해 흘러가는 바이트를 buf에도 그대로 복사합니다.
// Write는 의도적으로 no-op
// 에러가 클라이언트로 전달되면 연결이 끊기기 때문
type teeReadConn struct {
	net.Conn
	tee *bytes.Buffer
}

func (c *teeReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.tee.Write(p[:n])
	}
	return n, err
}

func (c *teeReadConn) Write(p []byte) (int, error) {
	return len(p), nil
}

// replayConn은 버퍼에 남은 것을 먼저 -> 소진되면 원본 conn을 줍니다.
// 목적지 판별 과정에서 미리 읽어버린 바이트를 잃지 않기 위한 용도.
type replayConn struct {
	net.Conn
	buf *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.buf.Len() > 0 {
		return c.buf.Read(p)
	}
	return c.Conn.Read(p)
}
