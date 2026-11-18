package fingerprint

import (
	"os"
	"path/filepath"
	"strings"
)

// agentSignature 描述一个已知 Agent/Harness 的识别特征。
type agentSignature struct {
	Name    string   // harness 名
	Comms   []string // 进程名特征（小写包含匹配）
	Cmdline []string // 命令行特征（小写包含匹配）
	Configs []string // 配置文件路径（`~` 展开；相对路径基于进程 cwd）
	EnvKeys []string // 环境变量特征（存在性）
}

// agentSignatures 为已知 Agent/Harness 白名单。
var agentSignatures = []agentSignature{
	{
		Name:    "claude-code",
		Comms:   []string{"claude"},
		Cmdline: []string{"claude"},
		Configs: []string{"~/.claude/settings.json", ".claude/settings.json"},
		EnvKeys: []string{"ANTHROPIC_API_KEY", "ANTHROPIC_MODEL", "CLAUDE_MODEL"},
	},
	{
		Name:    "cursor",
		Comms:   []string{"cursor"},
		Cmdline: []string{"cursor"},
		Configs: []string{"~/.cursor/", ".cursorrules", ".cursor/rules"},
		EnvKeys: []string{"CURSOR_API_KEY"},
	},
	{
		Name:    "codex",
		Comms:   []string{"codex"},
		Cmdline: []string{"codex"},
		Configs: []string{"~/.codex/", ".codex/"},
		EnvKeys: []string{"OPENAI_API_KEY", "OPENAI_MODEL"},
	},
	{
		Name:    "cline",
		Comms:   []string{"cline"},
		Cmdline: []string{"cline"},
		Configs: []string{".clinerules", "~/.cline/", ".cline/"},
		EnvKeys: []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
	},
	{
		Name:    "aider",
		Comms:   []string{"aider"},
		Cmdline: []string{"aider"},
		Configs: []string{".aider.conf.yml", "~/.aider.conf.yml"},
		EnvKeys: []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"},
	},
	{
		Name:    "continue",
		Comms:   []string{"continue"},
		Cmdline: []string{"continue"},
		Configs: []string{"~/.continue/config.json", ".continue/"},
		EnvKeys: []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
	},
	{
		Name:    "windsurf",
		Comms:   []string{"windsurf"},
		Cmdline: []string{"windsurf"},
		Configs: []string{"~/.codeium/windsurf/"},
		EnvKeys: []string{"CODEIUM_API_KEY"},
	},
	{
		Name:    "zed",
		Comms:   []string{"zed"},
		Cmdline: []string{"zed"},
		Configs: []string{"~/.config/zed/settings.json", ".zed/settings.json"},
		EnvKeys: []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
	},
	{
		Name:    "reasonix-studio",
		Comms:   []string{"reasonix-studio", "reasonix studio"},
		Cmdline: []string{"reasonix-studio"},
		Configs: []string{"~/.reasonix/config.toml", "~/.config/Reasonix Studio/"},
		EnvKeys: []string{"REASONIX_API_KEY"},
	},
}

// IdentifyAgent 识别进程属于哪个 Agent/Harness，返回 harness 名、存在的配置文件与命中的环境变量名。
func IdentifyAgent(info *ProcInfo) (string, []string, []string) {
	comm := strings.ToLower(info.Comm)
	cmdline := strings.ToLower(strings.Join(info.Cmdline, " "))

	for _, sig := range agentSignatures {
		if !matchesAgent(sig, comm, cmdline) {
			continue
		}
		return sig.Name, existingFiles(sig.Configs, info.Cwd), existingEnvKeys(sig.EnvKeys, info)
	}
	return "", nil, nil
}

// matchesAgent 判断进程名/命令行是否命中特征。
func matchesAgent(sig agentSignature, comm, cmdline string) bool {
	for _, c := range sig.Comms {
		if c != "" && strings.Contains(comm, c) {
			return true
		}
	}
	for _, c := range sig.Cmdline {
		if c != "" && strings.Contains(cmdline, c) {
			return true
		}
	}
	return false
}

// existingFiles 返回存在的配置路径（`~` 与相对 cwd 展开），按完整路径去重。
func existingFiles(paths []string, cwd string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		full := expandPath(p, cwd)
		if seen[full] {
			continue
		}
		if _, err := os.Stat(full); err == nil {
			seen[full] = true
			out = append(out, full)
		}
	}
	return out
}

// existingEnvKeys 返回 environ 中命中的环境变量名。
func existingEnvKeys(keys []string, info *ProcInfo) []string {
	present := make(map[string]bool, len(info.Environ)+len(info.EnvKeys))
	for k := range info.Environ {
		present[k] = true
	}
	for _, k := range info.EnvKeys {
		present[k] = true
	}

	var out []string
	for _, k := range keys {
		if present[k] {
			out = append(out, k)
		}
	}
	return out
}

// expandPath 展开 `~` 与相对路径（相对进程 cwd）。
func expandPath(p, cwd string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	if !filepath.IsAbs(p) && cwd != "" {
		return filepath.Join(cwd, p)
	}
	return p
}
