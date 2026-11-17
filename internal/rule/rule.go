package rule

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Verdict 为规则判定结果。
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictAlert Verdict = "alert"
	VerdictBlock Verdict = "block"
)

// Severity 为告警严重级别。
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Condition 为单条匹配条件。
type Condition struct {
	Field string `yaml:"field"` // comm/argv/envp/qname/server_name/ino/data/pid 等
	Op    string `yaml:"op"`    // eq/contains/prefix/suffix
	Value string `yaml:"value"`
}

// Rule 为一条判定规则。
type Rule struct {
	ID         string      `yaml:"id"`
	Name       string      `yaml:"name"`
	EventType  string      `yaml:"event_type"` // exec/exit/fork/pipe/dns/sni
	Conditions []Condition `yaml:"conditions"`
	Verdict    Verdict     `yaml:"verdict"`
	Severity   Severity    `yaml:"severity"`
	AgentType  uint32      `yaml:"agent_type,omitempty"` // 命中时标记为 Agent 进程（接管 agent 识别）
}

// Ruleset 为规则文件根结构。
type Ruleset struct {
	Rules []Rule `yaml:"rules"`
}

// Parse 解析 YAML 规则内容并校验。
func Parse(data []byte) ([]Rule, error) {
	var rs Ruleset
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("解析规则 YAML: %w", err)
	}
	if err := rs.validate(); err != nil {
		return nil, err
	}
	return rs.Rules, nil
}

// LoadFile 读取并解析规则文件。
func LoadFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件 %s: %w", path, err)
	}
	return Parse(data)
}

// validate 校验规则集完整性。
func (rs *Ruleset) validate() error {
	seen := make(map[string]bool, len(rs.Rules))
	for i, r := range rs.Rules {
		if r.ID == "" {
			return fmt.Errorf("第 %d 条规则缺少 id", i+1)
		}
		if seen[r.ID] {
			return fmt.Errorf("规则 id 重复: %s", r.ID)
		}
		seen[r.ID] = true
		if r.EventType == "" {
			return fmt.Errorf("规则 %s 缺少 event_type", r.ID)
		}
		switch r.Verdict {
		case VerdictAllow, VerdictAlert, VerdictBlock:
		default:
			return fmt.Errorf("规则 %s 的 verdict 非法: %s", r.ID, r.Verdict)
		}
		for j, c := range r.Conditions {
			if c.Field == "" || c.Op == "" {
				return fmt.Errorf("规则 %s 第 %d 个条件缺少 field/op", r.ID, j+1)
			}
		}
	}
	return nil
}
