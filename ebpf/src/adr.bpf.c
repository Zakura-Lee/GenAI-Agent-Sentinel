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

// handle_tls_sni 解析 TLS ClientHello 提取 SNI 并上报 SNI 事件。
static __always_inline int handle_tls_sni(const char *data, long len)
{
	u8 content_type;
	u8 handshake_type;
	u8 sid_len;
	u8 comp_len;
	__be16 cs_len_be;
	__be16 ext_len_be;
	u16 cs_len;
	u16 ext_len;
	int off;
	int ext_end;

	// 至少：record(5) + handshake(4) + client_version(2) + random(32) + sid_len(1)
	if (len < 44)
		return 0;

	if (bpf_probe_read_user(&content_type, 1, data + 0) < 0)
		return 0;
	if (content_type != 0x16) // TLS handshake record
		return 0;
	if (bpf_probe_read_user(&handshake_type, 1, data + 5) < 0)
		return 0;
	if (handshake_type != 0x01) // ClientHello
		return 0;

	if (bpf_probe_read_user(&sid_len, 1, data + 43) < 0)
		return 0;
	off = 44 + sid_len;

	if ((long)off + 2 > len)
		return 0;
	bpf_probe_read_user(&cs_len_be, 2, data + off);
	cs_len = bpf_ntohs(cs_len_be);
	off += 2 + cs_len;

	if ((long)off + 1 > len)
		return 0;
	bpf_probe_read_user(&comp_len, 1, data + off);
	off += 1 + comp_len;

	if ((long)off + 2 > len)
		return 0;
	bpf_probe_read_user(&ext_len_be, 2, data + off);
	ext_len = bpf_ntohs(ext_len_be);
	off += 2;
	ext_end = off + ext_len;
	if ((long)ext_end > len)
		return 0;

	for (int i = 0; i < 32 && (long)off + 4 <= ext_end; i++) {
		__be16 ext_type_be;
		__be16 ext_data_len_be;
		u16 ext_type;
		u16 ext_data_len;

		bpf_probe_read_user(&ext_type_be, 2, data + off);
		bpf_probe_read_user(&ext_data_len_be, 2, data + off + 2);
		ext_type = bpf_ntohs(ext_type_be);
		ext_data_len = bpf_ntohs(ext_data_len_be);

		if (ext_type == 0x0000) { // server_name (SNI)
			__be16 name_len_be;
			u16 name_len;

			if ((long)off + 4 + 5 > ext_end)
				return 0;
			// name_len 位于 server_name_list_len(2) + name_type(1) 之后
			bpf_probe_read_user(&name_len_be, 2, data + off + 4 + 3);
			name_len = bpf_ntohs(name_len_be);
			if (name_len == 0 || name_len >= ADR_NAME_LEN ||
			    (long)off + 4 + 5 + name_len > ext_end)
				return 0;

			__u32 size = sizeof(struct adr_event_header) + sizeof(struct adr_sni_payload);
			struct adr_event_header *hdr = bpf_ringbuf_reserve(&events, size, 0);
			if (!hdr)
				return 0;

			hdr->ts_ns = bpf_ktime_get_ns();
			hdr->type = ADR_EVENT_SNI;
			hdr->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
			hdr->ppid = 0;
			hdr->uid = 0;
			hdr->gid = 0;
			hdr->reserved = 0;
			__builtin_memset(&hdr->taint, 0, sizeof(hdr->taint));

			struct adr_sni_payload *p = (struct adr_sni_payload *)((void *)hdr + sizeof(*hdr));
			bpf_probe_read_user(p->server_name, name_len, data + off + 4 + 5);
			p->server_name[name_len] = '\0';

			bpf_ringbuf_submit(hdr, 0);
			return 1;
		}

		off += 4 + ext_data_len;
	}

	return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t size)
{
	const struct iovec *iov = NULL;
	size_t iov_off = 0;
	const char *base = NULL;
	size_t iov_len = 0;

	if (bpf_core_read(&iov, sizeof(iov), &msg->msg_iter.__iov) < 0)
		return 0;
	if (bpf_core_read(&iov_off, sizeof(iov_off), &msg->msg_iter.iov_offset) < 0)
		return 0;
	if (bpf_probe_read_user(&base, sizeof(base), &iov[0].iov_base) < 0)
		return 0;
	if (bpf_probe_read_user(&iov_len, sizeof(iov_len), &iov[0].iov_len) < 0)
		return 0;
	if (!base || iov_off >= iov_len)
		return 0;

	return handle_tls_sni(base + iov_off, (long)(iov_len - iov_off));
}
