package inspector

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/config"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient"
	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient/pb"
)

// fakeDLPServer는 실제 FastAPI DLP 서버 대신 쓰는 테스트용 gRPC mock입니다.
// 항상 미리 정해둔 verdict를 반환하거나(delay로 지연 시뮬레이션), unreachable 테스트를 위해
// 아예 기동시키지 않고 존재하지 않는 주소를 사용합니다.
type fakeDLPServer struct {
	pb.UnimplementedDLPInspectorServer
	verdict *pb.Verdict
	delay   time.Duration
}

func (f *fakeDLPServer) Inspect(ctx context.Context, _ *pb.InspectRequest) (*pb.Verdict, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.verdict, nil
}

func startFakeDLPServer(t *testing.T, srv *fakeDLPServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock 리스너 생성 실패: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterDLPInspectorServer(s, srv)
	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

func newTestInspector(t *testing.T, addr, failPolicy string, timeout time.Duration) *Inspector {
	t.Helper()
	dlp, err := dlpclient.NewGRPCClient(addr)
	if err != nil {
		t.Fatalf("gRPC client 생성 실패: %v", err)
	}
	cfg := &config.Config{FailPolicy: failPolicy}
	cfg.DLPServer.Addr = addr
	cfg.DLPServer.Timeout = timeout
	return New(dlp, cfg)
}

func TestEnforce_Allow(t *testing.T) {
	addr := startFakeDLPServer(t, &fakeDLPServer{verdict: &pb.Verdict{Action: "allow"}})
	insp := newTestInspector(t, addr, config.FailPolicyClosed, time.Second)

	result, err := insp.Enforce(context.Background(), "sess-1", "input", "POST", "/v1/chat", http.Header{}, []byte("hello"))
	if err != nil {
		t.Fatalf("Enforce 에러: %v", err)
	}
	if result.Action != ActionAllow {
		t.Errorf("action = %q, want %q", result.Action, ActionAllow)
	}
	if result.FailPolicyApplied {
		t.Errorf("FailPolicyApplied = true, want false (정상 DLP 응답)")
	}
}

func TestEnforce_Block(t *testing.T) {
	addr := startFakeDLPServer(t, &fakeDLPServer{
		verdict: &pb.Verdict{Action: "block", Reason: "주민등록번호 탐지"},
	})
	insp := newTestInspector(t, addr, config.FailPolicyClosed, time.Second)

	result, err := insp.Enforce(context.Background(), "sess-1", "input", "POST", "/v1/chat", http.Header{}, []byte("123456-1234567"))
	if err != nil {
		t.Fatalf("Enforce 에러: %v", err)
	}
	if result.Action != ActionBlock {
		t.Errorf("action = %q, want %q", result.Action, ActionBlock)
	}
	if result.FailPolicyApplied {
		t.Errorf("FailPolicyApplied = true, want false (DLP가 직접 block 판단한 케이스)")
	}
}

func TestEnforce_Transform(t *testing.T) {
	addr := startFakeDLPServer(t, &fakeDLPServer{
		verdict: &pb.Verdict{Action: "transform", TransformedBody: []byte("[MASKED]")},
	})
	insp := newTestInspector(t, addr, config.FailPolicyClosed, time.Second)

	result, err := insp.Enforce(context.Background(), "sess-1", "output", "POST", "/v1/chat", http.Header{}, []byte("원본"))
	if err != nil {
		t.Fatalf("Enforce 에러: %v", err)
	}
	if result.Action != ActionTransform {
		t.Errorf("action = %q, want %q", result.Action, ActionTransform)
	}
	if string(result.TransformedBody) != "[MASKED]" {
		t.Errorf("TransformedBody = %q, want %q", result.TransformedBody, "[MASKED]")
	}
}

func TestEnforce_UnknownAction_TreatedAsFailPolicy(t *testing.T) {
	addr := startFakeDLPServer(t, &fakeDLPServer{verdict: &pb.Verdict{Action: "mask"}}) // 정의되지 않은 값
	insp := newTestInspector(t, addr, config.FailPolicyClosed, time.Second)

	result, err := insp.Enforce(context.Background(), "sess-1", "input", "POST", "/v1/chat", http.Header{}, []byte("x"))
	if err != nil {
		t.Fatalf("Enforce 에러: %v", err)
	}
	if result.Action != ActionBlock || !result.FailPolicyApplied {
		t.Errorf("알 수 없는 action은 안전하게 block 처리돼야 함, got %+v", result)
	}
}

func TestEnforce_DLPUnreachable_FailClosed(t *testing.T) {
	// 아무도 듣고 있지 않은 주소로 연결해서 반드시 실패시킴
	insp := newTestInspector(t, "127.0.0.1:1", config.FailPolicyClosed, 200*time.Millisecond)

	result, err := insp.Enforce(context.Background(), "sess-1", "input", "GET", "/", http.Header{}, nil)
	if err != nil {
		t.Fatalf("Enforce 에러(자체는 nil이어야 함, Result로 감싸서 반환): %v", err)
	}
	if result.Action != ActionBlock || !result.FailPolicyApplied {
		t.Errorf("DLP 서버 unreachable + fail_policy=closed면 block 처리돼야 함, got %+v", result)
	}
}

func TestEnforce_DLPUnreachable_FailOpen(t *testing.T) {
	insp := newTestInspector(t, "127.0.0.1:1", config.FailPolicyOpen, 200*time.Millisecond)

	result, err := insp.Enforce(context.Background(), "sess-1", "input", "GET", "/", http.Header{}, nil)
	if err != nil {
		t.Fatalf("Enforce 에러: %v", err)
	}
	if result.Action != ActionAllow || !result.FailPolicyApplied {
		t.Errorf("DLP 서버 unreachable + fail_policy=open이면 allow로 통과해야 함, got %+v", result)
	}
}
