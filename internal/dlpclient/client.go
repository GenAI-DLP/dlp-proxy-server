package dlpclient

import (
	"context"
	"fmt"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient/pb"
)

// InspectRequest는 프록시가 DLP 서버에 검사를 요청할 때 담는 평문 데이터입니다.
type InspectRequest struct {
	SessionID string
	Direction string // "input" | "output"
	Method    string
	Path      string
	Headers   http.Header
	Body      []byte
}

// Verdict는 DLP 서버의 판정 결과 그 자체입니다. (fail-open/closed 판단은 여기 없음)
type Verdict struct {
	Action          string // "allow" | "block" | "transform"
	TransformedBody []byte
	Reason          string
}

// GRPCClient는 FastAPI DLP 서버와 gRPC로 통신하는 순수 transport 계층입니다.
// 타임아웃/fail-policy는 여기서 다루지 않고 inspector.Inspector가 담당합니다.
type GRPCClient struct {
	conn   *grpc.ClientConn
	client pb.DLPInspectorClient
}

func NewGRPCClient(addr string) (*GRPCClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("DLP 서버 연결 실패: %w", err)
	}
	return &GRPCClient{conn: conn, client: pb.NewDLPInspectorClient(conn)}, nil
}

func (c *GRPCClient) Close() error {
	return c.conn.Close()
}

// Inspect는 요청받은 ctx를 그대로 사용합니다. 타임아웃은 호출부(inspector.Enforce)가
// context.WithTimeout으로 이미 감싸서 넘겨주므로 여기서 별도로 걸지 않습니다.
// 통신 실패 시 에러를 그대로 리턴하고, fail-open/closed 판단은 inspector가 합니다.
func (c *GRPCClient) Inspect(ctx context.Context, req *InspectRequest) (*Verdict, error) {
	headers := map[string]string{}
	for k, v := range req.Headers {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	resp, err := c.client.Inspect(ctx, &pb.InspectRequest{
		SessionId: req.SessionID,
		Direction: req.Direction,
		Method:    req.Method,
		Path:      req.Path,
		Headers:   headers,
		Body:      req.Body,
	})
	if err != nil {
		return nil, fmt.Errorf("DLP 검사 요청 실패: %w", err)
	}

	return &Verdict{
		Action:          resp.Action,
		TransformedBody: resp.TransformedBody,
		Reason:          resp.Reason,
	}, nil
}