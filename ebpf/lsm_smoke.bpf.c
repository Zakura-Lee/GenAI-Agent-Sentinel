// SPDX-License-Identifier: GPL-2.0
// LSM 冒烟测试：对文件名 adr-deny-test 的打开返回 -EPERM，验证 lsm=bpf 环境可 attach 且返回值生效。
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

// is_deny_name 判断文件名是否为 adr-deny-test（dentry 名，不含路径）。
static __always_inline int is_deny_name(const char *name)
{
	const char magic[] = "adr-deny-test";
#pragma unroll
	for (int i = 0; i < (int)sizeof(magic) - 1; i++) {
		if (name[i] != magic[i])
			return 0;
	}
	return 1;
}

SEC("lsm/file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	char name[16] = {};
	const unsigned char *n = NULL;

	if (bpf_core_read(&n, sizeof(n), &file->f_path.dentry->d_name.name) < 0)
		return 0;

	bpf_probe_read_kernel_str(name, sizeof(name), n);
	if (is_deny_name(name))
		return -EPERM;
	return 0;
}
