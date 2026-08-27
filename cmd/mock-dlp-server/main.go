// cmd/mock-dlp-server는 FastAPI DLP 서버가 아직 없을 때
// 로컬에서 테스트를 위한 gRPC mock입니다.
// 모든 요청에 항상 같은 판정(-action)을 돌려줍니다.
package main

import (
	"context"
	"flag"
	"log"
	"net"

	"google.golang.org/grpc"

	"github.com/GenAI-DLP/dlp-proxy-server/internal/dlpclient/pb"
)

type mockServer struct {
	pb.UnimplementedDLPInspectorServer
	action          string
	reason          string
	transformedBody []byte
}

func (m *mockServer) Inspect(ctx context.Context, req *pb.InspectRequest) (*pb.Verdict, error) {
	log.Printf("mock-dlp: 요청 수신 session=%s direction=%s method=%s path=%s body_len=%d -> action=%s",
		req.SessionId, req.Direction, req.Method, req.Path, len(req.Body), m.action)

	return &pb.Verdict{
		Action:          m.action,
		Reason:          m.reason,
		TransformedBody: m.transformedBody,
	}, nil
}

func main() {
	addr := flag.String("addr", ":50051", "리스닝 주소")
	action := flag.String("action", "allow", `항상 반환할 판정: "allow" | "block" | "transform"`)
	reason := flag.String("reason", "mock-dlp-server: 항상 이 판정을 반환하도록 설정됨", "block/transform 시 함께 반환할 reason")
	transformedBody := flag.String("transformed-body", "[MASKED BY MOCK]", `action=transform일 때 반환할 본문`)
	flag.Parse()

	if *action != "allow" && *action != "block" && *action != "transform" {
		log.Fatalf(`-action은 "allow", "block", "transform" 중 하나여야 합니다: %q`, *action)
	}

	srv := &mockServer{action: *action, reason: *reason}
	if *action == "transform" {
		srv.transformedBody = []byte(*transformedBody)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("리스너 생성 실패(%s): %v", *addr, err)
	}

	s := grpc.NewServer()
	pb.RegisterDLPInspectorServer(s, srv)

	log.Printf("mock-dlp-server 시작 (%s) - 모든 요청에 action=%q 반환", *addr, *action)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("서버 종료: %v", err)
	}
}
