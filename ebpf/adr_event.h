// SPDX-License-Identifier: GPL-2.0
// adr_event.h - ADR eBPF 层事件 ABI（对应 docs/ebpf-protocol.md v0.1.0）。
// 事件 = adr_event_header（64 字节）+ 类型特定 payload。
// 依赖调用方已 include "vmlinux.h"。
#ifndef __ADR_EVENT_H
#define __ADR_EVENT_H

// 事件类型枚举
enum adr_event_type {
	ADR_EVENT_EXEC = 1,
	ADR_EVENT_EXIT = 2,
	ADR_EVENT_FORK = 3,
	ADR_EVENT_PIPE = 4,
	ADR_EVENT_DNS  = 5,
	ADR_EVENT_SNI  = 6,
	ADR_EVENT_FILE = 7,
	ADR_EVENT_NET  = 8,
};

// adr_taint 污点信息（32 字节，8 对齐）
struct adr_taint {
	__u64 session_id; // agent 会话 id，0 表示未污染
	__u64 tool_id;    // 工具调用 id，0 表示会话根
	__u32 agent_type; // agent 类型枚举
	__u32 depth;      // 继承深度（根进程为 1）
	__u32 reserved;   // 保留，置 0
	__u32 pad;        // 对齐
};

// adr_taint_key taint 表键：tgid + 进程启动时间（boottime 时钟 tick 数，与 /proc/<pid>/stat 的 starttime 对齐），避免 pid 复用串号。
struct adr_taint_key {
	__u32 tgid;
	__u32 pad;
	__u64 start_boottime;
};

// adr_event_header 事件公共头（64 字节，8 对齐）
struct adr_event_header {
	__u64 ts_ns;            // 时间戳 bpf_ktime_get_ns()
	__u32 type;             // adr_event_type
	__u32 pid;              // 进程 id（tgid）
	__u32 ppid;             // 父进程 id
	__u32 uid;
	__u32 gid;
	__u32 reserved;         // 保留，置 0
	struct adr_taint taint; // 污点信息
};

// payload 常量
#define ADR_COMM_LEN 16
#define ADR_ARGV_LEN 256
#define ADR_ENVP_LEN 512
#define ADR_PIPE_DATA_LEN 128
#define ADR_NAME_LEN 256

// 参数槽位：每个 argv/envp 元素读入固定大小槽，避免动态偏移导致 verifier 无法追踪边界。
#define ARGV_SLOTS 6
#define ENVP_SLOTS 6
#define SLOT_SIZE  64

// adr_exec_payload EXEC 事件 payload
struct adr_exec_payload {
	char comm[ADR_COMM_LEN];
	char argv[ARGV_SLOTS][SLOT_SIZE];
	char envp[ENVP_SLOTS][SLOT_SIZE];
};

// adr_exit_payload EXIT 事件 payload
struct adr_exit_payload {
	__u32 exit_code;
	__u32 pad;
	__u64 duration_ns;
};

// adr_fork_payload FORK 事件 payload（头中 pid 为父进程）
struct adr_fork_payload {
	__u32 child_pid;
	__u32 pad;
	__u64 clone_flags; // sched_process_fork tracepoint 暂不提供，置 0
};

// adr_pipe_payload PIPE 事件 payload
struct adr_pipe_payload {
	__u64 ino; // pipe inode 号（配对键）
	__u32 len; // 数据长度
	__u32 dir; // 0=读，1=写
	char data[ADR_PIPE_DATA_LEN];
};

// adr_dns_payload DNS 事件 payload
struct adr_dns_payload {
	char qname[ADR_NAME_LEN];
};

// adr_sni_payload SNI 事件 payload
struct adr_sni_payload {
	char server_name[ADR_NAME_LEN];
};

// adr_file_payload FILE 事件 payload（openat / mmap）
struct adr_file_payload {
	__u32 op;                 // 0=open, 1=mmap
	__u32 dirfd;              // openat 的 dirfd（AT_FDCWD=-100）
	__u32 flags;              // openat flags / mmap prot
	__u32 fd;                 // mmap 的 fd（open 为 0）
	__u32 len;                // mmap 长度（open 为 0）
	char  path[ADR_NAME_LEN]; // open 的 filename（可能相对）；mmap 留空由用户态补
};

// adr_net_payload NET 事件 payload（connect / bind / listen）
struct adr_net_payload {
	__u32 op;       // 0=connect, 1=bind, 2=listen
	__u32 family;   // AF_INET / AF_INET6
	__u32 port;     // 端口（主机字节序）
	__u32 fd;       // 关联 fd
	__u8  addr[16]; // IPv4 用前 4 字节，IPv6 全 16
};

#endif // __ADR_EVENT_H
