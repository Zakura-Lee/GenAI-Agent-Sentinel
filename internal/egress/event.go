package egress

// ExecveEventSize 为 ExecveEvent 与 eBPF 侧 struct execve_event 的字节大小。
const ExecveEventSize = 4*4 + 16 + 256 + 512

// ExecveEvent 对应 eBPF 侧 struct execve_event（定义于 ebpf/src/trace_execve.bpf.c）。
// 两侧字节布局必须一致，由 TestExecveEventSize 锁定。
type ExecveEvent struct {
	Pid  uint32    // 进程 id（tgid）
	Ppid uint32    // 父进程 id
	Uid  uint32    // 真实 uid
	Gid  uint32    // 真实 gid
	Comm [16]byte  // 进程名（TASK_COMM_LEN）
	Argv [256]byte // 拼接后的参数列表（空格分隔）
	Envp [512]byte // 拼接后的环境变量（可能含敏感信息，上报前需过滤）
}
