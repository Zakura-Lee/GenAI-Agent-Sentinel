package rule

import "testing"

const sampleYAML = `
rules:
  - id: test-exec
    name: 测试规则
    event_type: exec
    conditions:
      - field: comm
        op: eq
        value: bash
    verdict: alert
    severity: high
`

// TestParse 验证 YAML 解析与校验。
func TestParse(t *testing.T) {
	rules, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("规则数 = %d，期望 1", len(rules))
	}
	if rules[0].ID != "test-exec" || rules[0].Verdict != VerdictAlert {
		t.Fatalf("规则解析错误: %+v", rules[0])
	}
}

// TestParseInvalid 验证非法规则被拒绝。
func TestParseInvalid(t *testing.T) {
	cases := []string{
		`rules: [{id: "", event_type: exec, verdict: alert}]`,                                           // 缺 id
		`rules: [{id: a, event_type: exec, verdict: bogus}]`,                                            // verdict 非法
		`rules: [{id: a, event_type: exec, verdict: alert}, {id: a, event_type: exec, verdict: alert}]`, // id 重复
	}
	for i, c := range cases {
		if _, err := Parse([]byte(c)); err == nil {
			t.Fatalf("用例 %d 应解析失败", i)
		}
	}
}
