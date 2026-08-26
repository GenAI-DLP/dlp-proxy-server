package dlpclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient/pb"
)

type InspectRequest struct {
	SessionID string
	Direction string
	Method    string
	Path      string
	Headers   http.Header
	Body      []byte
}

type Verdict struct {
	Action          string
	TransformedBody []byte
	Reason          string
}

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

func (c *GRPCClient) Inspect(ctx context.Context, req *InspectRequest) (*Verdict, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

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