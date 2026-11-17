package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIdentifyAgent 验证 Agent 识别（comm / cmdline 特征）。
func TestIdentifyAgent(t *testing.T) {
	cases := []struct {
		name string
		info *ProcInfo
		want string
	}{
		{"claude-comm", &ProcInfo{Comm: "claude"}, "claude-code"},
		{"cursor-comm", &ProcInfo{Comm: "cursor"}, "cursor"},
		{"codex-comm", &ProcInfo{Comm: "codex"}, "codex"},
		{"aider-cmdline", &ProcInfo{Comm: "python3", Cmdline: []string{"python3", "-m", "aider"}}, "aider"},
		{"bash", &ProcInfo{Comm: "bash", Cmdline: []string{"bash", "-c", "ls"}}, ""},
	}
	for _, c := range cases {
		if got, _, _ := IdentifyAgent(c.info); got != c.want {
			t.Errorf("%s: IdentifyAgent = %q，期望 %q", c.name, got, c.want)
		}
	}
}

// TestInferProvider 验证厂商推断优先级。
func TestInferProvider(t *testing.T) {
	cases := []struct {
		name           string
		harness        string
		configProvider string
		model          string
		envKeys        []string
		apiHosts       []string
		want           string
	}{
		{"config-provider", "claude-code", "deepseek", "", nil, nil, "deepseek"},
		{"model-prefix", "claude-code", "", "gpt-4o", nil, nil, "openai"},
		{"env-key", "aider", "", "", []string{"ANTHROPIC_API_KEY"}, nil, "anthropic"},
		{"api-host", "cursor", "", "", nil, []string{"api.deepseek.com"}, "deepseek"},
		{"harness-fallback", "claude-code", "", "", nil, nil, "anthropic"},
	}
	for _, c := range cases {
		got := InferProvider(c.harness, c.configProvider, c.model, c.envKeys, c.apiHosts)
		if got != c.want {
			t.Errorf("%s: InferProvider = %q，期望 %q", c.name, got, c.want)
		}
	}
}

// TestModelFromConfig 验证配置文件 model 字段解析（JSON / YAML）。
func TestModelFromConfig(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(jsonPath, []byte(`{"model":"claude-sonnet-4","provider":"anthropic"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(dir, ".aider.conf.yml")
	if err := os.WriteFile(yamlPath, []byte("model: deepseek-chat\nprovider: deepseek\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, p := ModelFromConfig([]string{jsonPath})
	if m != "claude-sonnet-4" || p != "anthropic" {
		t.Fatalf("JSON: model=%q provider=%q", m, p)
	}

	m, p = ModelFromConfig([]string{yamlPath})
	if m != "deepseek-chat" || p != "deepseek" {
		t.Fatalf("YAML: model=%q provider=%q", m, p)
	}
}

// TestModelFromCmdline 验证 --model 参数提取。
func TestModelFromCmdline(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"claude", "--model", "claude-opus-4"}, "claude-opus-4"},
		{[]string{"aider", "--model=gpt-4o"}, "gpt-4o"},
		{[]string{"ls"}, ""},
	}
	for _, c := range cases {
		if got := ModelFromCmdline(c.args); got != c.want {
			t.Errorf("ModelFromCmdline(%v) = %q，期望 %q", c.args, got, c.want)
		}
	}
}

// TestExistingFilesDedup 验证同一配置文件不会被重复列出。
func TestExistingFilesDedup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := existingFiles([]string{cfg, ".claude/settings.json"}, dir)
	if len(got) != 1 {
		t.Fatalf("config_files = %v，期望去重为 1 个", got)
	}
}
