// SPDX-License-Identifier: GPL-2.0
// 捕获 execve 行为事件：pid/ppid/uid/gid/comm/argv，经 ring buffer 上报用户态。
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define ARG_MAX 256
#define MAX_ARGS 16

// execve_event 为上报给用户态的事件，字段布局需与 Go 侧 ExecveEvent 保持一致。
struct execve_event {
	__u32 pid;                // 进程 id（tgid）
	__u32 ppid;               // 父进程 id
	__u32 uid;                // 真实 uid
	__u32 gid;                // 真实 gid
	char comm[TASK_COMM_LEN]; // 进程名
	char argv[ARG_MAX];       // 拼接后的参数列表（空格分隔）
};

// events 为 BPF ring buffer，用于向用户态上报事件。
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// read_argv 读取用户态 argv 字符串数组并拼接进 dst，返回写入字节数（不含结尾 '\0'）。
static __always_inline long read_argv(char *dst, long size, const char **argv)
{
	long off = 0;

	for (int i = 0; i < MAX_ARGS; i++) {
		const char *argp = NULL;

		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp)
			break;
		if (off >= size - 1)
			break;
		if (i > 0)
			dst[off++] = ' ';

		long n = bpf_probe_read_user_str(dst + off, size - off, argp);
		if (n <= 0)
			break;
		off += n - 1; // 返回值含结尾 '\0'
	}

	if (off >= size)
		off = size - 1;
	dst[off] = '\0';
	return off;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct execve_event *e;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = (__u32)(pid_tgid >> 32);
	e->ppid = (__u32)BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)(uid_gid & 0xffffffff);
	e->gid = (__u32)(uid_gid >> 32);
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	read_argv(e->argv, sizeof(e->argv), (const char **)ctx->args[1]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
