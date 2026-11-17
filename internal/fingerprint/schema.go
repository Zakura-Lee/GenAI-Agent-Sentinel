package fingerprint

// AgentSession 为一条 AI Agent/Harness 会话：谁在跑、用哪个厂商的哪个模型。
type AgentSession struct {
	// 进程维度
	Pid        uint32            `json:"pid"`
	Ppid       uint32            `json:"ppid,omitempty"`
	Comm       string            `json:"comm,omitempty"`
	Exe        string            `json:"exe,omitempty"`
	Cmdline    []string          `json:"cmdline,omitempty"`
	Cwd        string            `json:"cwd,omitempty"`
	UID        uint32            `json:"uid,omitempty"`
	GID        uint32            `json:"gid,omitempty"`
	StartTicks uint64            `json:"start_ticks,omitempty"`
	Cgroup     string            `json:"cgroup,omitempty"`
	NsInodes   map[string]string `json:"ns_inodes,omitempty"`

	// Agent 维度
	Harness     string   `json:"harness"`                // claude-code / cursor / codex / cline / aider / continue / windsurf / zed
	ConfigFiles []string `json:"config_files,omitempty"` // 命中的 Agent 配置文件路径
	EnvKeys     []string `json:"env_keys,omitempty"`     // 命中的 API key 环境变量名（只名字，不取值）

	// 厂商 / 模型维度
	Provider string   `json:"provider,omitempty"`  // anthropic / openai / deepseek / google / ...
	Model    string   `json:"model,omitempty"`     // claude-sonnet-4 / gpt-4o / deepseek-chat
	APIHosts []string `json:"api_hosts,omitempty"` // 运行时由 eBPF SNI/DNS 观察到的 API 域名

	// Source 标记会话来源：proc-scan / config-scan
	Source string `json:"source"`
}
