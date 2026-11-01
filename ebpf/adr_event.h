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

// adr_exec_payload EXEC 事件 payload
struct adr_exec_payload {
	char comm[ADR_COMM_LEN];
	char argv[ADR_ARGV_LEN];
	char envp[ADR_ENVP_LEN];
};

// adr_pipe_payload PIPE 事件 payload
struct adr_pipe_payload {
	__u64 ino; // pipe inode 号（配对键）
	__u32 len; // 数据长度
	__u32 dir; // 0=读，1=写
	char data[ADR_PIPE_DATA_LEN];
};

#endif // __ADR_EVENT_H
