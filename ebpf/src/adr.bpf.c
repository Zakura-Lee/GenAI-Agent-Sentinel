// SPDX-License-Identifier: GPL-2.0
// ADR eBPF 程序集：execve 观测 + pipe 读写关联 + DNS/SNI 识别 + taint 继承，共享 events ring buffer。
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
#define EPERM   1
#define NSEC_PER_TICK 10000000ULL // USER_HZ=100 时每 tick 的纳秒数

// get_start_ticks 返回 task 的启动时间（boottime 时钟 tick 数），与 /proc/<pid>/stat 的 starttime 对齐。
static __always_inline __u64 get_start_ticks(struct task_struct *task)
{
	return BPF_CORE_READ(task, start_boottime) / NSEC_PER_TICK;
}

// events 为共享的 BPF ring buffer，所有事件经此上报用户态。
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// taints 记录 (tgid, start_boottime) → 污点信息；用户态写 agent 根进程标记，task_alloc 继承、exit 清理。
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct adr_taint_key);
	__type(value, struct adr_taint);
} taints SEC(".maps");

// fill_common 填充事件公共头的通用字段（ts_ns/type/pid/reserved/taint）。
// ppid/uid/gid 由调用方自行填充。
static __always_inline void fill_common(struct adr_event_header *hdr, __u32 type)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct adr_taint_key key;
	struct adr_taint *t;

	key.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	key.pad = 0;
	key.start_boottime = get_start_ticks(task);

	hdr->ts_ns = bpf_ktime_get_ns();
	hdr->type = type;
	hdr->pid = key.tgid;
	hdr->reserved = 0;

	t = bpf_map_lookup_elem(&taints, &key);
	if (t)
		hdr->taint = *t;
	else
		__builtin_memset(&hdr->taint, 0, sizeof(hdr->taint));
}

// read_slots 将用户态 char** 数组逐个读入固定大小槽位（verifier 友好的固定偏移）。
static __always_inline void read_slots(char (*dst)[SLOT_SIZE], int max_slots, const char **vec)
{
#pragma unroll
	for (int i = 0; i < max_slots; i++) {
		const char *p = NULL;
		if (bpf_probe_read_user(&p, sizeof(p), &vec[i]) == 0 && p)
			bpf_probe_read_user_str(dst[i], SLOT_SIZE, p);
	}
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

	fill_common(hdr, ADR_EVENT_PIPE);
	hdr->ppid = 0;
	hdr->uid = 0;
	hdr->gid = 0;

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

	fill_common(hdr, ADR_EVENT_EXEC);
	hdr->ppid = (__u32)BPF_CORE_READ(task, real_parent, tgid);
	hdr->uid = (__u32)(uid_gid & 0xffffffff);
	hdr->gid = (__u32)(uid_gid >> 32);

	payload = (struct adr_exec_payload *)((void *)hdr + sizeof(*hdr));
	__builtin_memset(payload, 0, sizeof(*payload));
	bpf_get_current_comm(payload->comm, sizeof(payload->comm));
	read_slots(payload->argv, ARGV_SLOTS, (const char **)ctx->args[1]);
	read_slots(payload->envp, ENVP_SLOTS, (const char **)ctx->args[2]);

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

	fill_common(hdr, ADR_EVENT_DNS);
	hdr->ppid = 0;
	hdr->uid = 0;
	hdr->gid = 0;

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
			bpf_probe_read_user(&name_len_be, 2, data + off + 4 + 3);
			name_len = bpf_ntohs(name_len_be);
			if (name_len == 0 || name_len >= ADR_NAME_LEN ||
			    (long)off + 4 + 5 + name_len > ext_end)
				return 0;

			__u32 size = sizeof(struct adr_event_header) + sizeof(struct adr_sni_payload);
			struct adr_event_header *hdr = bpf_ringbuf_reserve(&events, size, 0);
			if (!hdr)
				return 0;

			fill_common(hdr, ADR_EVENT_SNI);
			hdr->ppid = 0;
			hdr->uid = 0;
			hdr->gid = 0;

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

// task_alloc 在进程出生时将父进程（current）的 taint 继承给新进程（depth + 1）。
SEC("lsm/task_alloc")
int BPF_PROG(task_alloc_entry, struct task_struct *task, unsigned long clone_flags)
{
	struct task_struct *parent = (struct task_struct *)bpf_get_current_task();
	struct adr_taint_key pkey;
	struct adr_taint_key ckey;
	struct adr_taint *t;

	pkey.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	pkey.pad = 0;
	pkey.start_boottime = get_start_ticks(parent);

	t = bpf_map_lookup_elem(&taints, &pkey);
	if (!t)
		return 0;

	ckey.tgid = (__u32)BPF_CORE_READ(task, tgid);
	ckey.pad = 0;
	ckey.start_boottime = get_start_ticks(task);

	struct adr_taint child = *t;
	child.depth++;
	bpf_map_update_elem(&taints, &ckey, &child, BPF_ANY);
	return 0;
}

// trace_exit 清理进程退出后的 taint，避免 pid 复用串号。
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_exit *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct adr_taint_key key;

	key.tgid = (__u32)ctx->pid;
	key.pad = 0;
	key.start_boottime = get_start_ticks(task);

	bpf_map_delete_elem(&taints, &key);
	return 0;
}

// is_sentinel_name 判断文件名是否为哨兵文件（用于 taint 拦截验证）。
static __always_inline int is_sentinel_name(const char *name)
{
	const char magic[] = "adr-sentinel";
#pragma unroll
	for (int i = 0; i < (int)sizeof(magic) - 1; i++) {
		if (name[i] != magic[i])
			return 0;
	}
	return 1;
}

// taint_deny_open 检查当前进程 taint，拒绝 tainted 进程打开哨兵文件。
SEC("lsm/file_open")
int BPF_PROG(taint_deny_open, struct file *file)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct adr_taint_key key;
	struct adr_taint *t;
	char name[32] = {};
	const unsigned char *n = NULL;

	key.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	key.pad = 0;
	key.start_boottime = get_start_ticks(task);

	t = bpf_map_lookup_elem(&taints, &key);
	if (!t || t->session_id == 0)
		return 0;

	if (bpf_core_read(&n, sizeof(n), &file->f_path.dentry->d_name.name) < 0)
		return 0;
	bpf_probe_read_kernel_str(name, sizeof(name), n);

	if (is_sentinel_name(name))
		return -EPERM;
	return 0;
}
