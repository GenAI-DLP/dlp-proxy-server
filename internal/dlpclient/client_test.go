package dlpclient

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient/pb"
)

// fakeInspectorClient는 pb.DLPInspectorClient 인터페이스를 흉내내는 테스트용 가짜 구현체입니다.
// 실제 gRPC 연결 없이 Inspect() 응답을 원하는 대로 조작할 수 있습니다.
type fakeInspectorClient struct {
	resp    *pb.Verdict
	err     error
	lastReq *pb.InspectRequest // 어떤 요청이 들어왔는지 검증용으로 캡처
}

func (f *fakeInspectorClient) Inspect(ctx context.Context, in *pb.InspectRequest, opts ...grpc.CallOption) (*pb.Verdict, error) {
	f.lastReq = in
	return f.resp, f.err
}

func TestInspect_Allow(t *testing.T) {
	fake := &fakeInspectorClient{
		resp: &pb.Verdict{Action: "allow", Reason: "정상 요청"},
	}
	c := &GRPCClient{client: fake}

	verdict, err := c.Inspect(context.Background(), &InspectRequest{
		SessionID: "test-session",
		Direction: "input",
		Method:    "POST",
		Path:      "/v1/chat",
		Headers:   http.Header{"Content-Type": []string{"application/json"}},
		Body:      []byte(`{"msg":"hello"}`),
	})

	if err != nil {
		t.Fatalf("예상치 못한 에러: %v", err)
	}
	if verdict.Action != "allow" {
		t.Errorf("Action = %q, 원하는 값 = allow", verdict.Action)
	}
}

func TestInspect_Block(t *testing.T) {
	fake := &fakeInspectorClient{
		resp: &pb.Verdict{Action: "block", Reason: "계좌번호 탐지됨"},
	}
	c := &GRPCClient{client: fake}

	verdict, err := c.Inspect(context.Background(), &InspectRequest{
		SessionID: "test-session",
		Direction: "input",
		Body:      []byte(`제 계좌번호는 123-456-789입니다`),
	})

	if err != nil {
		t.Fatalf("예상치 못한 에러: %v", err)
	}
	if verdict.Action != "block" {
		t.Errorf("Action = %q, 원하는 값 = block", verdict.Action)
	}
	if verdict.Reason != "계좌번호 탐지됨" {
		t.Errorf("Reason = %q", verdict.Reason)
	}
}

func TestInspect_GRPCError(t *testing.T) {
	fake := &fakeInspectorClient{
		err: errors.New("connection refused"),
	}
	c := &GRPCClient{client: fake}

	// client.go는 정책 판단 없이 gRPC 에러를 그대로 리턴해야 합니다.
	// (fail-open/closed 판단은 internal/inspector.Enforce 몫)
	_, err := c.Inspect(context.Background(), &InspectRequest{
		SessionID: "test-session",
		Direction: "input",
	})

	if err == nil {
		t.Fatal("gRPC 통신 실패 시 에러가 리턴되어야 하는데 nil이 반환됨")
	}
}

func TestInspect_HeaderConversion(t *testing.T) {
	fake := &fakeInspectorClient{
		resp: &pb.Verdict{Action: "allow"},
	}
	c := &GRPCClient{client: fake}

	_, err := c.Inspect(context.Background(), &InspectRequest{
		SessionID: "test-session",
		Headers:   http.Header{"X-Corp-User-Id": []string{"user-123"}},
	})
	if err != nil {
		t.Fatalf("예상치 못한 에러: %v", err)
	}

	if fake.lastReq.Headers["X-Corp-User-Id"] != "user-123" {
		t.Errorf("헤더 변환 실패: %+v", fake.lastReq.Headers)
	}
}