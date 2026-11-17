package egress

// 事件类型枚举（对应 C 侧 enum adr_event_type）。
const (
	EventTypeExec = 1
	EventTypeExit = 2
	EventTypeFork = 3
	EventTypePipe = 4
	EventTypeDNS  = 5
	EventTypeSNI  = 6
	EventTypeFile = 7
	EventTypeNet  = 8
)

// AdrEventHeaderSize 为事件公共头字节大小。
const AdrEventHeaderSize = 64

// AdrTaint 对应 C 侧 struct adr_taint（32 字节）。
type AdrTaint struct {
	SessionID uint64 // agent 会话 id，0 表示未污染
	ToolID    uint64 // 工具调用 id，0 表示会话根
	AgentType uint32
	Depth     uint32
	Reserved  uint32
	Pad       uint32
}

// TaintKey 对应 C 侧 struct adr_taint_key（16 字节，StartBoottime 为 boottime 时钟 tick 数）。
type TaintKey struct {
	Tgid          uint32
	Pad           uint32
	StartBoottime uint64
}

// AdrEventHeader 对应 C 侧 struct adr_event_header（64 字节）。
type AdrEventHeader struct {
	TsNs     uint64
	Type     uint32
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Gid      uint32
	Reserved uint32
	Taint    AdrTaint
}

// ExecPayload 对应 C 侧 struct adr_exec_payload。
type ExecPayload struct {
	Comm [16]byte
	Argv [6][64]byte
	Envp [6][64]byte
}

// PipePayload 对应 C 侧 struct adr_pipe_payload。
type PipePayload struct {
	Ino  uint64
	Len  uint32
	Dir  uint32
	Data [128]byte
}

// DnsPayload 对应 C 侧 struct adr_dns_payload。
type DnsPayload struct {
	Qname [256]byte
}

// SniPayload 对应 C 侧 struct adr_sni_payload。
type SniPayload struct {
	ServerName [256]byte
}

// ExitPayload 对应 C 侧 struct adr_exit_payload。
type ExitPayload struct {
	ExitCode   uint32
	Pad        uint32
	DurationNs uint64
}

// ForkPayload 对应 C 侧 struct adr_fork_payload。
type ForkPayload struct {
	ChildPid   uint32
	Pad        uint32
	CloneFlags uint64
}

// FilePayload 对应 C 侧 struct adr_file_payload（openat / mmap）。
type FilePayload struct {
	Op    uint32 // 0=open, 1=mmap
	Dirfd uint32
	Flags uint32
	Fd    uint32
	Len   uint32
	Path  [256]byte
}

// NetPayload 对应 C 侧 struct adr_net_payload（connect / bind / listen）。
type NetPayload struct {
	Op     uint32 // 0=connect, 1=bind, 2=listen
	Family uint32
	Port   uint32
	Fd     uint32
	Addr   [16]byte
}

// Event 为一条已解析的事件：公共头 + 按 type 解析的 payload。
type Event struct {
	Header AdrEventHeader
	Exec   *ExecPayload
	Pipe   *PipePayload
	Dns    *DnsPayload
	Sni    *SniPayload
	Exit   *ExitPayload
	Fork   *ForkPayload
	File   *FilePayload
	Net    *NetPayload
}
