package egress

// 事件类型枚举（对应 C 侧 enum adr_event_type）。
const (
	EventTypeExec = 1
	EventTypeExit = 2
	EventTypeFork = 3
	EventTypePipe = 4
	EventTypeDNS  = 5
	EventTypeSNI  = 6
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
	Argv [8][32]byte
	Envp [16][32]byte
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

// Event 为一条已解析的事件：公共头 + 按 type 解析的 payload。
type Event struct {
	Header AdrEventHeader
	Exec   *ExecPayload
	Pipe   *PipePayload
	Dns    *DnsPayload
	Sni    *SniPayload
}
