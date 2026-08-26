package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	FailPolicyClosed = "closed"
	FailPolicyOpen   = "open"

	defaultDLPTimeout = 3 * time.Second
)

// Config는 TCP/UDP 프록시가 공통으로 참조하는 설정입니다.
// 판단(무엇이 민감정보인지)은 DLP 서버 몫이고, 여기 담기는 값은
// "어디로 연결할지", "어떤 도메인을 검사 대상으로 볼지", "DLP 서버가
// 응답하지 않을 때 어떻게 할지" 같은 운영/배포 설정입니다.
type Config struct {
	Listen struct {
		TCPAddr string `yaml:"tcp_addr"`
		UDPAddr string `yaml:"udp_addr"`
	} `yaml:"listen"`

	DLPServer struct {
		Addr       string `yaml:"addr"`
		TimeoutRaw string `yaml:"timeout"`
		Timeout    time.Duration `yaml:"-"`
	} `yaml:"dlp_server"`

	CA struct {
		CertPath string `yaml:"cert_path"`
		KeyPath  string `yaml:"key_path"`
	} `yaml:"ca"`

	// Allowlist: MITM/검사 대상 도메인(SNI) 목록. (임시-yaml파일)
	Allowlist []string `yaml:"allowlist"`

	// FailPolicy: DLP 서버가 타임아웃/장애일 때의 동작. 기본은 "closed"(차단).
	FailPolicy string `yaml:"fail_policy"`
}

// Load는 YAML 설정 파일을 읽어 Config로 파싱하고, 누락된 값에 안전한 기본값을 채웁니다.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("설정 파일 읽기 실패(%s): %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("설정 파일 파싱 실패(%s): %w", path, err)
	}

	if err := cfg.applyDefaultsAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaultsAndValidate() error {
	if c.FailPolicy == "" {
		c.FailPolicy = FailPolicyClosed
	}
	if c.FailPolicy != FailPolicyClosed && c.FailPolicy != FailPolicyOpen {
		return fmt.Errorf("fail_policy 값이 올바르지 않음: %q (%q 또는 %q만 허용)",
			c.FailPolicy, FailPolicyClosed, FailPolicyOpen)
	}

	if c.DLPServer.Addr == "" {
		return fmt.Errorf("dlp_server.addr는 필수입니다")
	}

	if c.DLPServer.TimeoutRaw == "" {
		c.DLPServer.Timeout = defaultDLPTimeout
	} else {
		d, err := time.ParseDuration(c.DLPServer.TimeoutRaw)
		if err != nil {
			return fmt.Errorf("dlp_server.timeout 파싱 실패(%q): %w", c.DLPServer.TimeoutRaw, err)
		}
		c.DLPServer.Timeout = d
	}

	return nil
}

// IsAllowlisted는 주어진 도메인(SNI)이 검사 대상인지 확인합니다.
// TLS 핸드셰이크 이전 단계에서 proxy/tcp, proxy/udp가 직접 호출합니다.
func (c *Config) IsAllowlisted(domain string) bool {
	for _, d := range c.Allowlist {
		if d == domain {
			return true
		}
	}
	return false
}
