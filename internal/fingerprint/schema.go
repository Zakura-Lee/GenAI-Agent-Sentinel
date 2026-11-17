package fingerprint

// Asset 为一条 AI 资产记录（对齐 CycloneDX ML-BOM 字段）。
type Asset struct {
	// 进程维度
	Pid        uint32            `json:"pid,omitempty"`
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

	// 文件维度
	ModelFiles []ModelFile `json:"model_files,omitempty"`

	// 网络维度
	ListenPorts []PortInfo `json:"listen_ports,omitempty"`

	// 运行时维度
	DSOs []string `json:"dsos,omitempty"`
	GPU  *GPUInfo `json:"gpu,omitempty"`

	// 环境（白名单）
	Env map[string]string `json:"env,omitempty"`

	// Source 标记资产来源：proc-scan / ebpf-event
	Source string `json:"source"`
}

// ModelFile 为模型文件指纹（对齐 CycloneDX ML-BOM 的 component 字段）。
type ModelFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Format string `json:"format"` // gguf / safetensors / onnx / hdf5 / pytorch / pickle
	Arch   string `json:"arch,omitempty"`
	Quant  string `json:"quant,omitempty"`
	Hash   string `json:"hash,omitempty"` // 采样哈希（头 1MB + 尾 1MB + size）
}

// PortInfo 为监听端口与探测结果。
type PortInfo struct {
	Protocol string   `json:"protocol"` // tcp / tcp6 / udp
	Port     uint32   `json:"port"`
	Addr     string   `json:"addr,omitempty"`
	Service  string   `json:"service,omitempty"` // ollama / openai-compat / unknown
	Models   []string `json:"models,omitempty"`
}

// GPUInfo 为 GPU 占用。
type GPUInfo struct {
	Device     string `json:"device"`
	UsedMemory uint64 `json:"used_memory_mb"`
}
