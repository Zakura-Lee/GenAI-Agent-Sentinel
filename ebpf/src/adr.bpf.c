// SPDX-License-Identifier: GPL-2.0
// ADR eBPF 程序集：execve 观测 + pipe 读写关联（MCP stdio），共享 events ring buffer。
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "adr_event.h"

char LICENSE[] SEC("license") = "GPL";

#define MAX_VEC 32
#define S_IFMT  0xF000
#define S_IFIFO 0x1000

// events 为共享的 BPF ring buffer，所有事件经此上报用户态。
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// read_strvec 读取用户态 char** 字符串数组并拼接进 dst，返回写入字节数（不含结尾 '\0'）。
static __always_inline long read_strvec(char *dst, long size, const char **vec)
{
	long off = 0;

	for (int i = 0; i < MAX_VEC; i++) {
		const char *p = NULL;

		if (bpf_probe_read_user(&p, sizeof(p), &vec[i]) < 0 || !p)
			break;
		if (off >= size - 1)
			break;
		if (i > 0)
			dst[off++] = ' ';

		long n = bpf_probe_read_user_str(dst + off, size - off, p);
		if (n <= 0)
			break;
		off += n - 1; // 返回值含结尾 '\0'
	}

	if (off >= size)
		off = size - 1;
	dst[off] = '\0';
	return off;
}

// handle_pipe_io 判定 file 是否为 pipe，若是则上报 PIPE 事件。dir: 0=读，1=写。
static __always_inline int handle_pipe_io(struct file *file, const char *buf, size_t len, __u32 dir)
{
	umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
	if ((mode & S_IFMT) != S_IFIFO)
		return 0;

	__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
	__u32 size = sizeof(struct adr_event_header) + sizeof(struct adr_pipe_payload);

	struct adr_event_header *hdr = bpf_ringbuf_reserve(&events, size, 0);
	if (!hdr)
		return 0;

	hdr->ts_ns = bpf_ktime_get_ns();
	hdr->type = ADR_EVENT_PIPE;
	hdr->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	hdr->ppid = 0;
	hdr->uid = 0;
	hdr->gid = 0;
	hdr->reserved = 0;
	__builtin_memset(&hdr->taint, 0, sizeof(hdr->taint));

	struct adr_pipe_payload *p = (struct adr_pipe_payload *)((void *)hdr + sizeof(*hdr));
	p->ino = ino;
	p->dir = dir;
	p->len = len > ADR_PIPE_DATA_LEN ? ADR_PIPE_DATA_LEN : len;
	if (p->len > 0)
		bpf_probe_read_user(p->data, p->len, buf);

	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct adr_event_header *hdr;
	struct adr_exec_payload *payload;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 size = sizeof(*hdr) + sizeof(*payload);

	hdr = bpf_ringbuf_reserve(&events, size, 0);
	if (!hdr)
		return 0;

	hdr->ts_ns = bpf_ktime_get_ns();
	hdr->type = ADR_EVENT_EXEC;
	hdr->pid = (__u32)(pid_tgid >> 32);
	hdr->ppid = (__u32)BPF_CORE_READ(task, real_parent, tgid);
	hdr->uid = (__u32)(uid_gid & 0xffffffff);
	hdr->gid = (__u32)(uid_gid >> 32);
	hdr->reserved = 0;
	__builtin_memset(&hdr->taint, 0, sizeof(hdr->taint));

	payload = (struct adr_exec_payload *)((void *)hdr + sizeof(*hdr));
	bpf_get_current_comm(payload->comm, sizeof(payload->comm));
	read_strvec(payload->argv, sizeof(payload->argv), (const char **)ctx->args[1]);
	read_strvec(payload->envp, sizeof(payload->envp), (const char **)ctx->args[2]);

	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(vfs_write_entry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
	return handle_pipe_io(file, buf, count, 1);
}

SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit, struct file *file, char *buf, size_t count, loff_t *pos, ssize_t ret)
{
	if (ret <= 0)
		return 0;
	return handle_pipe_io(file, buf, (size_t)ret, 0);
}

// handle_dns 解析 DNS query 报文（跳过 12 字节头）提取 qname 并上报 DNS 事件。
static __always_inline int handle_dns(const char *dns, long remain)
{
	__u32 size = sizeof(struct adr_event_header) + sizeof(struct adr_dns_payload);

	struct adr_event_header *hdr = bpf_ringbuf_reserve(&events, size, 0);
	if (!hdr)
		return 0;

	hdr->ts_ns = bpf_ktime_get_ns();
	hdr->type = ADR_EVENT_DNS;
	hdr->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	hdr->ppid = 0;
	hdr->uid = 0;
	hdr->gid = 0;
	hdr->reserved = 0;
	__builtin_memset(&hdr->taint, 0, sizeof(hdr->taint));

	struct adr_dns_payload *p = (struct adr_dns_payload *)((void *)hdr + sizeof(*hdr));
	int off = 12; // 跳过 DNS header
	int dst = 0;

	for (int i = 0; i < 64; i++) {
		u8 lbl;

		if (off >= remain || dst >= ADR_NAME_LEN - 1)
			break;
		if (bpf_probe_read_user(&lbl, 1, dns + off) < 0)
			break;
		if (lbl == 0)
			break;
		off++;
		if (dst > 0)
			p->qname[dst++] = '.';
		if (dst + lbl >= ADR_NAME_LEN - 1)
			break;
		if (bpf_probe_read_user(p->qname + dst, lbl, dns + off) < 0)
			break;
		dst += lbl;
		off += lbl;
	}
	p->qname[dst] = '\0';

	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(udp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
	__be16 dport = 0;
	if (bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport) < 0)
		return 0;
	if (dport != bpf_htons(53))
		return 0;

	const struct iovec *iov = NULL;
	size_t iov_off = 0;
	if (bpf_core_read(&iov, sizeof(iov), &msg->msg_iter.__iov) < 0)
		return 0;
	if (bpf_core_read(&iov_off, sizeof(iov_off), &msg->msg_iter.iov_offset) < 0)
		return 0;

	const char *base = NULL;
	size_t iov_len = 0;
	if (bpf_probe_read_user(&base, sizeof(base), &iov[0].iov_base) < 0)
		return 0;
	if (bpf_probe_read_user(&iov_len, sizeof(iov_len), &iov[0].iov_len) < 0)
		return 0;

	if (!base || iov_off >= iov_len || iov_len - iov_off < 13)
		return 0;

	return handle_dns(base + iov_off, (long)(iov_len - iov_off));
}
