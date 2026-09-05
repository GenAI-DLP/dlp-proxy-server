// internal/proxy/tcp/handler.go
package tcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/inspector"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/session"
)

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	resolved, target, err := ResolveTarget(conn)
	if err != nil {
		log.Printf("tcp: 목적지 판별 실패(%s): %v", conn.RemoteAddr(), err)
		return
	}

	if !s.cfg.IsAllowlisted(target.Host) {
		s.passthrough(resolved, target)
		return
	}

	s.inspect(resolved, target)
}

// passthrough는 allowlist에 없는 목적지로 가는 트래픽을 그대로 중계합니다.
func (s *Server) passthrough(client net.Conn, target *Target) {
	upstream, err := net.DialTimeout("tcp", target.Addr(), 10*time.Second)
	if err != nil {
		log.Printf("tcp: passthrough 업스트림(%s) 연결 실패: %v", target.Addr(), err)
		return
	}
	defer upstream.Close()

	relay(client, upstream)
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); a.Close(); done <- struct{}{} }()
	go func() { io.Copy(b, a); b.Close(); done <- struct{}{} }()
	<-done
	<-done
}

// inspect는 allowlist 대상 목적지에 대해 TLS를 종단하고 HTTP 요청/응답을
// DLP 서버 판정에 따라 검사·집행합니다.
func (s *Server) inspect(client net.Conn, target *Target) {
	tlsConn := tls.Server(client, &tls.Config{
		GetCertificate: s.issuer.GetCertificate,
		NextProtos:     []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("tcp: 클라이언트 TLS 핸드셰이크 실패(%s): %v", target.Host, err)
		return
	}
	defer tlsConn.Close()

	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		if err != io.EOF {
			log.Printf("tcp: HTTP 요청 파싱 실패(%s): %v", target.Host, err)
		}
		return
	}
	defer req.Body.Close()

	sessionID := session.ExtractSessionID(req)

	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("tcp: 요청 바디 읽기 실패(%s): %v", target.Host, err)
		return
	}

	ctx := context.Background()
	reqResult, err := s.inspector.Enforce(ctx, sessionID, "input", req.Method, req.URL.Path, req.Header, reqBody)
	if err != nil {
		log.Printf("tcp: inspector.Enforce(input) 실패(%s): %v", target.Host, err)
		writeBlockedOrLog(tlsConn, "internal_error", nil)
		return
	}
	if reqResult.Action == inspector.ActionBlock {
		log.Printf("tcp: 요청 차단(session=%s, host=%s, reason=%s, fail_policy=%v)",
			sessionID, target.Host, reqResult.Reason, reqResult.FailPolicyApplied)
		writeBlockedOrLog(tlsConn, reqResult.Reason, map[string]string{
			"X-Dlp-Input-Action": reqResult.Action,
		})
		return
	}
	if reqResult.Action == inspector.ActionTransform {
		reqBody = reqResult.TransformedBody
	}

	upstreamResp, respBody, err := s.forwardToUpstream(req, target, reqBody)
	if err != nil {
		log.Printf("tcp: 업스트림(%s) 요청 실패: %v", target.Addr(), err)
		writeBlockedOrLog(tlsConn, "upstream_unreachable", nil)
		return
	}

	respResult, err := s.inspector.Enforce(ctx, sessionID, "output", req.Method, req.URL.Path, upstreamResp.Header, respBody)
	if err != nil {
		log.Printf("tcp: inspector.Enforce(output) 실패(%s): %v", target.Host, err)
		writeBlockedOrLog(tlsConn, "internal_error", map[string]string{
			"X-Dlp-Input-Action": reqResult.Action,
		})
		return
	}
	if respResult.Action == inspector.ActionBlock {
		log.Printf("tcp: 응답 차단(session=%s, host=%s, reason=%s, fail_policy=%v)",
			sessionID, target.Host, respResult.Reason, respResult.FailPolicyApplied)
		writeBlockedOrLog(tlsConn, respResult.Reason, map[string]string{
			"X-Dlp-Input-Action":  reqResult.Action,
			"X-Dlp-Output-Action": respResult.Action,
		})
		return
	}
	if respResult.Action == inspector.ActionTransform {
		respBody = respResult.TransformedBody
	}

	log.Printf(
		"tcp: 처리 완료(session=%s, host=%s, input_action=%s, output_action=%s, input_fail_policy=%v, output_fail_policy=%v)",
		sessionID, target.Host, reqResult.Action, respResult.Action,
		reqResult.FailPolicyApplied, respResult.FailPolicyApplied,
	)

	if err := writeResponse(tlsConn, upstreamResp, respBody, map[string]string{
		"X-Dlp-Input-Action":  reqResult.Action,
		"X-Dlp-Output-Action": respResult.Action,
	}); err != nil {
		log.Printf("tcp: 클라이언트로 응답 전송 실패(%s): %v", target.Host, err)
	}
}

// forwardToUpstream은 실제 목적지에 새 TLS 연결을 맺어 요청을 전달하고,
// 응답 본문까지 전부 읽어서 돌려줍니다.
func (s *Server) forwardToUpstream(orig *http.Request, target *Target, body []byte) (*http.Response, []byte, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	upstreamConn, err := tls.DialWithDialer(dialer, "tcp", target.Addr(), &tls.Config{
		ServerName: target.Host,
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("업스트림 TLS 연결 실패: %w", err)
	}
	defer upstreamConn.Close()

	// 연결은 됐는데 응답이 안 오거나 느리게 트리클되는 경우까지 방어.
	// 문서 §2.4의 지연 예산(soft budget 2.5초)은 dlp-server 호출에만 적용되고
	// 업스트림 자체엔 없었으므로, 별도로 30초 상한을 둔다.
	if err := upstreamConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, nil, fmt.Errorf("업스트림 데드라인 설정 실패: %w", err)
	}

	outReq := orig.Clone(context.Background())
	outReq.RequestURI = ""
	outReq.Body = io.NopCloser(bytes.NewReader(body))
	outReq.ContentLength = int64(len(body))
	outReq.Header.Set("Content-Length", strconv.Itoa(len(body)))

	if err := outReq.Write(upstreamConn); err != nil {
		return nil, nil, fmt.Errorf("업스트림 요청 전송 실패: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstreamConn), outReq)
	if err != nil {
		return nil, nil, fmt.Errorf("업스트림 응답 파싱 실패: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("업스트림 응답 바디 읽기 실패: %w", err)
	}

	return resp, respBody, nil
}

// writeBlockedOrLog는 writeBlocked를 호출하고 실패하면 로그만 남깁니다
func writeBlockedOrLog(w io.Writer, reason string, extraHeaders map[string]string) {
	if err := writeBlocked(w, reason, extraHeaders); err != nil {
		log.Printf("tcp: 차단 응답 전송 실패: %v", err)
	}
}

// writeBlocked는 DLP 판정으로 차단된 요청/응답 대신 클라이언트에 돌려줄
// 간단한 403 응답을 작성합니다. extraHeaders로 X-Dlp-*-Action 같은 최소
// 판정 시그널을 실어 보낼 수 있다 (상세 reason은 여전히 로그에만 남긴다).
func writeBlocked(w io.Writer, reason string, extraHeaders map[string]string) error {
	body := fmt.Sprintf("blocked by DLP policy: %s", reason)
	header := http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}
	for k, v := range extraHeaders {
		header.Set(k, v)
	}
	resp := &http.Response{
		StatusCode:    http.StatusForbidden,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	return resp.Write(w)
}

// writeResponse는 업스트림 응답을 body(검사/치환 결과)로 교체해 클라이언트에 씁니다.
// extraHeaders로 X-Dlp-*-Action 같은 최소 판정 시그널을 함께 실어 보낼 수 있다.
func writeResponse(w io.Writer, resp *http.Response, body []byte, extraHeaders map[string]string) error {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Transfer-Encoding")
	for k, v := range extraHeaders {
		resp.Header.Set(k, v)
	}
	return resp.Write(w)
}