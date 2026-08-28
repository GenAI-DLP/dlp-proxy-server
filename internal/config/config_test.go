package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("테스트 config 파일 생성 실패: %v", err)
	}
	return path
}

func TestLoad_Success(t *testing.T) {
	path := writeTestConfig(t, `
listen:
  tcp_addr: ":8443"
  udp_addr: ":8443"
dlp_server:
  addr: "localhost:50051"
  timeout: "3s"
ca:
  cert_path: "./certs/ca.pem"
  key_path: "./certs/ca-key.pem"
allowlist:
  - "chatgpt.com"
  - "claude.ai"
fail_policy: "closed"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load 실패: %v", err)
	}
	if cfg.Listen.UDPAddr != ":8443" {
		t.Errorf("UDPAddr = %q", cfg.Listen.UDPAddr)
	}
	if cfg.DLPServer.Addr != "localhost:50051" {
		t.Errorf("DLPServer.Addr = %q", cfg.DLPServer.Addr)
	}
	if cfg.DLPServer.Timeout != 3_000_000_000 { // 3s in nanoseconds
		t.Errorf("Timeout = %v, 원하는 값 = 3s", cfg.DLPServer.Timeout)
	}
	if len(cfg.Allowlist) != 2 {
		t.Errorf("Allowlist 길이 = %d, 원하는 값 = 2", len(cfg.Allowlist))
	}
	if cfg.FailPolicy != FailPolicyClosed {
		t.Errorf("FailPolicy = %q", cfg.FailPolicy)
	}
}

func TestLoad_DefaultFailPolicy_WhenOmitted(t *testing.T) {
	// fail_policy를 아예 안 적었을 때, 금융권 기본값인 "closed"로 채워지는지 확인
	path := writeTestConfig(t, `
dlp_server:
  addr: "localhost:50051"
allowlist:
  - "chatgpt.com"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load 실패: %v", err)
	}
	if cfg.FailPolicy != FailPolicyClosed {
		t.Errorf("fail_policy 생략 시 기본값 = %q, 원하는 값 = %q (fail-closed가 기본이어야 함)", cfg.FailPolicy, FailPolicyClosed)
	}
}

func TestLoad_DefaultTimeout_WhenOmitted(t *testing.T) {
	path := writeTestConfig(t, `
dlp_server:
  addr: "localhost:50051"
allowlist:
  - "chatgpt.com"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load 실패: %v", err)
	}
	if cfg.DLPServer.Timeout != defaultDLPTimeout {
		t.Errorf("Timeout = %v, 원하는 기본값 = %v", cfg.DLPServer.Timeout, defaultDLPTimeout)
	}
}

func TestLoad_InvalidFailPolicy(t *testing.T) {
	path := writeTestConfig(t, `
dlp_server:
  addr: "localhost:50051"
allowlist:
  - "chatgpt.com"
fail_policy: "이상한값"
`)

	_, err := Load(path)
	if err == nil {
		t.Error("잘못된 fail_policy 값인데 에러가 안 남")
	}
}

func TestLoad_MissingDLPServerAddr(t *testing.T) {
	path := writeTestConfig(t, `
allowlist:
  - "chatgpt.com"
`)

	_, err := Load(path)
	if err == nil {
		t.Error("dlp_server.addr가 없는데 에러가 안 남")
	}
}

func TestLoad_InvalidTimeoutFormat(t *testing.T) {
	path := writeTestConfig(t, `
dlp_server:
  addr: "localhost:50051"
  timeout: "이건시간이아님"
allowlist:
  - "chatgpt.com"
`)

	_, err := Load(path)
	if err == nil {
		t.Error("잘못된 timeout 형식인데 에러가 안 남")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("존재하지않는파일.yaml")
	if err == nil {
		t.Error("존재하지 않는 파일인데 에러가 안 남")
	}
}

func TestIsAllowlisted(t *testing.T) {
	cfg := &Config{Allowlist: []string{"chatgpt.com", "claude.ai"}}

	if !cfg.IsAllowlisted("chatgpt.com") {
		t.Error("chatgpt.com은 allowlist에 있는데 false 리턴됨")
	}
	if cfg.IsAllowlisted("evil.com") {
		t.Error("evil.com은 allowlist에 없는데 true 리턴됨")
	}
}