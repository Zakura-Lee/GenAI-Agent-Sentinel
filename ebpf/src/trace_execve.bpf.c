// SPDX-License-Identifier: GPL-2.0
// 最小可编译示例：通过 tracepoint 捕获 execve 系统调用，用于验证 eBPF 工具链。
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
	bpf_printk("ADR: execve called\n");
	return 0;
}
