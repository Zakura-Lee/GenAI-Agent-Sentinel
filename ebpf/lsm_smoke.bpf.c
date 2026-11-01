// SPDX-License-Identifier: GPL-2.0
// LSM 冒烟测试：对 /tmp/adr-deny-test 的打开返回 -EPERM，验证 lsm=bpf 环境可 attach 且返回值生效。
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

SEC("lsm.s/file_open")
int BPF_PROG(deny_file_open, struct file *file, int ret)
{
	char path[256];
	long n = bpf_d_path((struct path *)&file->f_path, path, sizeof(path));

	if (n == 19 && __builtin_memcmp(path, "/tmp/adr-deny-test", 19) == 0)
		return -EPERM;
	return 0;
}
