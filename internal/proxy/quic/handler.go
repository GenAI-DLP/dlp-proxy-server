package quic

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

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
		log.Printf("quic: 요청 차단(session=%s, host=%s, reason=%s)", sessionID, r.Host, result.Reason)
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

	// 업스트림이 느리거나 응답이 없을 때 무기한 블로킹되는 것을 방지.
	// 문서 §2.4의 지연 예산(soft budget 2.5초)은 dlp-server 호출에만 적용되므로,
	// 별도로 상한을 둔다 (TCP 경로의 forwardToUpstream과 동일 기준).
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	upstreamReq.Header = r.Header.Clone()

	resp, err := p.Upstream.RoundTrip(upstreamReq)
	if err != nil {
		log.Printf("quic: 업스트림(%s) 요청 실패: %v", r.Host, err)
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
	// 이전엔 err != nil일 때 검사를 건너뛰고 원본을 그대로 흘려보내는
	// fail-open 구조였다 — input 쪽과 방향이 반대라 위험했다. 지금은
	// input과 동일하게 에러 시 차단한다.
	outResult, err := p.Inspector.Enforce(r.Context(), sessionID, "output", r.Method, r.URL.Path, resp.Header, respBody)
	if err != nil {
		http.Error(w, "internal inspection error", http.StatusInternalServerError)
		return
	}

	switch outResult.Action {
	case inspector.ActionBlock:
		log.Printf("quic: 응답 차단(session=%s, host=%s, reason=%s)", sessionID, r.Host, outResult.Reason)
		http.Error(w, "응답이 보안 정책에 의해 차단되었습니다: "+outResult.Reason, http.StatusForbidden)
		return
	case inspector.ActionTransform:
		respBody = outResult.TransformedBody
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	// transform으로 바디 길이가 바뀔 수 있으므로 Content-Length를 다시 맞춘다.
	// 안 맞추면 클라이언트가 마스킹된 바디를 다 못 받거나 다음 응답을 기다리며 멈출 수 있다.
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.Header().Del("Transfer-Encoding")

	log.Printf(
		"quic: 처리 완료(session=%s, host=%s, input_action=%s, output_action=%s, input_fail_policy=%v, output_fail_policy=%v)",
		sessionID, r.Host, result.Action, outResult.Action,
		result.FailPolicyApplied, outResult.FailPolicyApplied,
	)

	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}