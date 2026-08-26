// 판단 로직은 DLP 서버 담당한다. Inspector는
//   1. 요청/응답을 그대로 DLP 서버에 전달하고
//   2. 돌아온 판정(action)을 프록시가 실행 가능한 형태로 변환하고
//   3. DLP 서버가 응답하지 않을 때 무엇을 할지(fail-open/closed)만 결정합니다.
package inspector

import (
	"context"
	"net/http"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/config"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient"
)

const (
	ActionAllow     = "allow"
	ActionBlock     = "block"
	ActionTransform = "transform"
)

// Result는 프록시(proxy/tcp, proxy/udp)가 그대로 집행할 수 있는 판정 결과입니다.
type Result struct {
	Action          string
	TransformedBody []byte
	Reason          string

    // 대시보드에서 DLP 서버 장애/미응답으로 인한 fail인지 실제 DLP 판단 fail인지 구분
    // FailPolicyApplied가 true -> DLP 서버의 장애/미응답
	FailPolicyApplied bool
}

type Inspector struct {
	dlp *dlpclient.GRPCClient
	cfg *config.Config
}

func New(dlp *dlpclient.GRPCClient, cfg *config.Config) *Inspector {
	return &Inspector{dlp: dlp, cfg: cfg}
}

// Enforce는 이미 검사 대상으로 확정된(allowlist 통과한) 요청/응답만 받습니다.
// allowlist 체크는 TLS 핸드셰이크 단계에서 proxy가 config.IsAllowlisted로 직접 수행합니다.
func (i *Inspector) Enforce(ctx context.Context, sessionID, direction, method, path string,
	headers http.Header, body []byte) (*Result, error) {

	ctx, cancel := context.WithTimeout(ctx, i.cfg.DLPServer.Timeout)
	defer cancel()

	verdict, err := i.dlp.Inspect(ctx, &dlpclient.InspectRequest{
		SessionID: sessionID,
		Direction: direction, //"input", "output"
		Method:    method,
		Path:      path,
		Headers:   headers,
		Body:      body,
	})
	if err != nil {
		return i.failPolicyResult("dlp_unreachable: " + err.Error()), nil
	}

	switch verdict.Action {
	case ActionAllow, ActionBlock, ActionTransform:
		return &Result{
			Action:          verdict.Action,
			TransformedBody: verdict.TransformedBody,
			Reason:          verdict.Reason,
		}, nil
	default:
		// DLP 서버가 정의되지 않은 action을 보내는 경우 차단
		return i.failPolicyResult("dlp_unknown_action: " + verdict.Action), nil
	}
}

func (i *Inspector) failPolicyResult(reason string) *Result {
	if i.cfg.FailPolicy == config.FailPolicyOpen {
		return &Result{Action: ActionAllow, Reason: reason, FailPolicyApplied: true}
	}
	return &Result{Action: ActionBlock, Reason: reason, FailPolicyApplied: true}
}
