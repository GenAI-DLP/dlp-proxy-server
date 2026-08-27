package quic

import (
	"bytes"
	"io"
	"net/http"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/inspector"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/session"
	"github.com/quic-go/quic-go/http3"
)

// DLPProxy는 QUIC(HTTP/3) 요청을 가로채 Inspector의 판정을 받고 그대로 집행합니다.
// 판단 로직은 여기 없습니다 — inspector.Enforce가 이미 fail-policy까지 처리해서
// 항상 유효한 inspector.Result를 리턴하므로, 여기서는 result.Action만 보고 실행만 합니다.
type DLPProxy struct {
	Inspector *inspector.Inspector
	Upstream  *http3.Transport  
}

func (p *DLPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionID := session.ExtractSessionID(r)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// 1. input 가드레일 (기능 c: 양방향 가드레일 中 입력 쪽)
	result, err := p.Inspector.Enforce(r.Context(), sessionID, "input", r.Method, r.URL.Path, r.Header, bodyBytes)
	if err != nil {
		// Enforce는 DLP 서버 장애까지 fail-policy로 흡수하므로,
		// 여기 도달하는 건 context 취소 같은 예외적인 경우뿐입니다.
		http.Error(w, "internal inspection error", http.StatusInternalServerError)
		return
	}

	switch result.Action {
	case inspector.ActionBlock:
		http.Error(w, "요청이 보안 정책에 의해 차단되었습니다: "+result.Reason, http.StatusForbidden)
		return
	case inspector.ActionTransform:
		bodyBytes = result.TransformedBody
	}

	// upstream 목적지는 클라이언트가 실제 접속하려던 도메인(r.Host)을 그대로 사용합니다.
	// 이미 TLS 핸드셰이크 단계(server.go의 GetCertificate)에서 allowlist 검증을 통과한 도메인입니다.
	upstreamURL := "https://" + r.Host + r.URL.Path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	upstreamReq.Header = r.Header.Clone()

	resp, err := p.Upstream.RoundTrip(upstreamReq)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "upstream read error", http.StatusBadGateway)
		return
	}

	// 2. output 가드레일 (기능 c: 양방향 가드레일 中 출력 쪽)
	outResult, err := p.Inspector.Enforce(r.Context(), sessionID, "output", r.Method, r.URL.Path, resp.Header, respBody)
	if err == nil {
		switch outResult.Action {
		case inspector.ActionBlock:
			http.Error(w, "응답이 보안 정책에 의해 차단되었습니다: "+outResult.Reason, http.StatusForbidden)
			return
		case inspector.ActionTransform:
			respBody = outResult.TransformedBody
		}
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}