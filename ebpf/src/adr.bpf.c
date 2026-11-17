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
#define PIPE_MIN_LEN 4            // 过滤过短的 pipe 数据（终端控制字符等无观测价值）

// get_start_ticks 返回 task 所在线程组的启动时间（group_leader 的 boottime tick 数），
// 与 /proc/<pid>/stat 的 starttime 对齐，并让同进程的所有线程归并到同一 key。
static __always_inline __u64 get_start_ticks(struct task_struct *task)
{
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	return BPF_CORE_READ(leader, start_boottime) / NSEC_PER_TICK;
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

// is_tainted_current 判断当前进程是否已被标记为 taint（agent 进程）。
static __always_inline int is_tainted_current(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct adr_taint_key key;

	key.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	key.pad = 0;
	key.start_boottime = get_start_ticks(task);

	return bpf_map_lookup_elem(&taints, &key) != NULL;
}

// has_suffix 判断长度 n 的字符串是否以 suffix 结尾（slen 为常量实参，便于展开）。
static __always_inline int has_suffix(const char *s, int n, const char *suffix, int slen)
{
	if (n < slen)
		return 0;

#pragma unroll
	for (int i = 0; i < slen; i++) {
		if (s[n - slen + i] != suffix[i])
			return 0;
	}
	return 1;
}

// is_model_ext 判断路径是否以常见模型文件扩展名结尾（n 为不含 NUL 的长度）。
static __always_inline int is_model_ext(const char *path, int n)
{
	if (n <= 0)
		return 0;
	if (has_suffix(path, n, ".gguf", 5))
		return 1;
	if (has_suffix(path, n, ".safetensors", 12))
		return 1;
	if (has_suffix(path, n, ".onnx", 5))
		return 1;
	if (has_suffix(path, n, ".sft", 4))
		return 1;
	if (has_suffix(path, n, ".pth", 4))
		return 1;
	if (has_suffix(path, n, ".pt", 3))
		return 1;
	if (has_suffix(path, n, ".h5", 3))
		return 1;
	return 0;
}

// report_file 上报 FILE 事件（op: 0=open, 1=mmap）。
static __always_inline void report_file(__u32 op, __u32 dirfd, __u32 flags, __u32 fd, __u32 len, const char *path)
{
	__u32 size = sizeof(struct adr_event_header) + sizeof(struct adr_file_payload);
	struct adr_event_header *hdr = bpf_ringbuf_reserve(&events, size, 0);
	struct adr_file_payload *p;

	if (!hdr)
		return;

	fill_common(hdr, ADR_EVENT_FILE);
	hdr->ppid = 0;
	hdr->uid = 0;
	hdr->gid = 0;

	p = (struct adr_file_payload *)((void *)hdr + sizeof(*hdr));
	__builtin_memset(p, 0, sizeof(*p));
	p->op = op;
	p->dirfd = dirfd;
	p->flags = flags;
	p->fd = fd;
	p->len = len;
	if (path)
		bpf_probe_read_kernel(p->path, sizeof(p->path), path);

	bpf_ringbuf_submit(hdr, 0);
}

// report_net 上报 NET 事件（op: 0=connect, 1=bind, 2=listen）。
static __always_inline void report_net(__u32 op, __u32 family, __u32 port, __u32 fd, const __u8 *addr)
{
	__u32 size = sizeof(struct adr_event_header) + sizeof(struct adr_net_payload);
	struct adr_event_header *hdr = bpf_ringbuf_reserve(&events, size, 0);
	struct adr_net_payload *p;

	if (!hdr)
		return;

	fill_common(hdr, ADR_EVENT_NET);
	hdr->ppid = 0;
	hdr->uid = 0;
	hdr->gid = 0;

	p = (struct adr_net_payload *)((void *)hdr + sizeof(*hdr));
	__builtin_memset(p, 0, sizeof(*p));
	p->op = op;
	p->family = family;
	p->port = port;
	p->fd = fd;
	if (addr)
		__builtin_memcpy(p->addr, addr, sizeof(p->addr));

	bpf_ringbuf_submit(hdr, 0);
}

// read_slots 将用户态 char** 数组逐个读入固定大小槽位（verifier 友好的固定偏移）。
// 遇到 NULL（数组结束）即停止，避免越界读到相邻数组（如 argv 之后紧邻的 envp）。
static __always_inline void read_slots(char (*dst)[SLOT_SIZE], int max_slots, const char **vec)
{
	int stop = 0;

#pragma unroll
	for (int i = 0; i < max_slots; i++) {
		const char *p = NULL;
		if (!stop) {
			if (bpf_probe_read_user(&p, sizeof(p), &vec[i]) != 0 || !p)
				stop = 1;
			else
				bpf_probe_read_user_str(dst[i], SLOT_SIZE, p);
		}
	}
}

// handle_pipe_io 判定 file 是否为 pipe，若是则上报 PIPE 事件。dir: 0=读，1=写。
static __always_inline int handle_pipe_io(struct file *file, const char *buf, size_t len, __u32 dir)
{
	umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
	if ((mode & S_IFMT) != S_IFIFO)
		return 0;

	// 过滤过短的 pipe 数据（终端控制字符等无观测价值）
	if (len < PIPE_MIN_LEN)
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

// get_first_iov 读取 msghdr 的第一个 iovec，兼容 ITER_UBUF（内嵌 iovec）与 ITER_IOVEC（内核态 iovec 数组）。
// 返回 0 成功，-1 失败。
static __always_inline int get_first_iov(struct msghdr *msg, const char **base, size_t *len, size_t *off)
{
	u8 iter_type = 0;
	if (bpf_core_read(&iter_type, sizeof(iter_type), &msg->msg_iter.iter_type) < 0)
		return -1;
	if (bpf_core_read(off, sizeof(*off), &msg->msg_iter.iov_offset) < 0)
		return -1;

	// ITER_UBUF：单个用户 buffer，iovec 内嵌在 iov_iter 中（与 __iov 共用 offset）
	if (iter_type == ITER_UBUF) {
		if (bpf_core_read(base, sizeof(*base), &msg->msg_iter.__ubuf_iovec.iov_base) < 0)
			return -1;
		if (bpf_core_read(len, sizeof(*len), &msg->msg_iter.__ubuf_iovec.iov_len) < 0)
			return -1;
		return 0;
	}

	// 其他类型（ITER_IOVEC 等）：iovec 数组在内核态
	const struct iovec *iov = NULL;
	if (bpf_core_read(&iov, sizeof(iov), &msg->msg_iter.__iov) < 0)
		return -1;
	if (bpf_probe_read_kernel(base, sizeof(*base), &iov[0].iov_base) < 0)
		return -1;
	if (bpf_probe_read_kernel(len, sizeof(*len), &iov[0].iov_len) < 0)
		return -1;
	return 0;
}

// handle_dns 读取 DNS query 的原始 qname（label 格式），固定大小读，变长解析留给用户态。
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
	__builtin_memset(p, 0, sizeof(*p));

	// 读原始 qname（跳过 12 字节 DNS header），用 _str 读到 qname 末尾的 0（label 长度 0）
	// 不能用 bpf_probe_read_user 固定读 ADR_NAME_LEN：DNS 包通常远小于 256 字节，越界会导致整段读取失败
	if (remain > 12)
		bpf_probe_read_user_str(p->qname, ADR_NAME_LEN, dns + 12);

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

	const char *base = NULL;
	size_t iov_len = 0;
	size_t iov_off = 0;
	if (get_first_iov(msg, &base, &iov_len, &iov_off) < 0)
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
	const char *base = NULL;
	size_t iov_len = 0;
	size_t iov_off = 0;
	if (get_first_iov(msg, &base, &iov_len, &iov_off) < 0)
		return 0;
	if (!base || iov_off >= iov_len)
		return 0;

	// 忽略 handle_tls_sni 的返回值（fentry 程序必须返回 0）
	handle_tls_sni(base + iov_off, (long)(iov_len - iov_off));
	return 0;
}

// wake_up_new_task 在进程就绪后继承父进程 taint（此时 tgid/start_boottime 已设置）。
// 线程（tgid != pid）共享进程 tgid 与 group_leader key，无需重复继承。
SEC("fentry/wake_up_new_task")
int BPF_PROG(wake_up_new_task_entry, struct task_struct *task)
{
	struct task_struct *parent = (struct task_struct *)bpf_get_current_task();
	struct adr_taint_key pkey;
	struct adr_taint_key ckey;
	struct adr_taint *t;
	__u32 tgid = (__u32)BPF_CORE_READ(task, tgid);
	__u32 pid = (__u32)BPF_CORE_READ(task, pid);

	if (tgid != pid)
		return 0;

	pkey.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	pkey.pad = 0;
	pkey.start_boottime = get_start_ticks(parent);

	t = bpf_map_lookup_elem(&taints, &pkey);
	if (!t)
		return 0;

	ckey.tgid = tgid;
	ckey.pad = 0;
	ckey.start_boottime = get_start_ticks(task);

	struct adr_taint child = *t;
	child.depth++;
	bpf_map_update_elem(&taints, &ckey, &child, BPF_ANY);
	return 0;
}

// trace_exit 上报 EXIT 事件并清理进程退出后的 taint，避免 pid 复用串号。
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_exit *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct adr_taint_key key;
	struct adr_event_header *hdr;
	struct adr_exit_payload *p;
	__u32 size = sizeof(*hdr) + sizeof(*p);

	// 先上报 EXIT（此时 taint 尚未清理，fill_common 能带上退出前的污点）
	hdr = bpf_ringbuf_reserve(&events, size, 0);
	if (hdr) {
		fill_common(hdr, ADR_EVENT_EXIT);
		hdr->ppid = 0;
		hdr->uid = 0;
		hdr->gid = 0;

		p = (struct adr_exit_payload *)((void *)hdr + sizeof(*hdr));
		p->exit_code = (__u32)BPF_CORE_READ(task, exit_code);
		p->pad = 0;
		// duration 用 monotonic 时钟（start_time 与 bpf_ktime_get_ns 同源）
		__u64 start_ns = BPF_CORE_READ(task, start_time);
		__u64 now_ns = bpf_ktime_get_ns();
		p->duration_ns = now_ns > start_ns ? now_ns - start_ns : 0;

		bpf_ringbuf_submit(hdr, 0);
	}

	// 再清理 taint
	key.tgid = (__u32)ctx->pid;
	key.pad = 0;
	key.start_boottime = get_start_ticks(task);
	bpf_map_delete_elem(&taints, &key);
	return 0;
}

// trace_fork 上报 FORK 事件（头中 pid 为父进程，payload 为子进程 tgid）。
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct adr_event_header *hdr;
	struct adr_fork_payload *p;
	__u32 size = sizeof(*hdr) + sizeof(*p);

	hdr = bpf_ringbuf_reserve(&events, size, 0);
	if (!hdr)
		return 0;

	fill_common(hdr, ADR_EVENT_FORK);
	hdr->ppid = 0;
	hdr->uid = 0;
	hdr->gid = 0;

	p = (struct adr_fork_payload *)((void *)hdr + sizeof(*hdr));
	p->child_pid = (__u32)ctx->child_pid;
	p->pad = 0;
	p->clone_flags = 0; // sched_process_fork tracepoint 不提供 clone_flags

	bpf_ringbuf_submit(hdr, 0);
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

// trace_openat 观测文件打开：tainted 进程全量上报，其他进程只报模型扩展名。
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];
	__u32 dirfd = (__u32)ctx->args[0];
	__u32 flags = (__u32)ctx->args[2];
	char path[ADR_NAME_LEN];
	long n;

	__builtin_memset(path, 0, sizeof(path));
	n = bpf_probe_read_user_str(path, sizeof(path), filename);
	if (n <= 0)
		return 0;

	if (!is_tainted_current() && !is_model_ext(path, (int)(n - 1)))
		return 0;

	report_file(0, dirfd, flags, 0, 0, path);
	return 0;
}

// trace_mmap 观测可执行内存映射（PROT_EXEC）：只上报 tainted 进程。
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
	__u64 prot = ctx->args[2];
	__u64 len = ctx->args[1];
	__u64 fd = ctx->args[4];

	if (!(prot & 0x4)) /* PROT_EXEC */
		return 0;
	if (!is_tainted_current())
		return 0;

	report_file(1, 0, (__u32)prot, (__u32)fd, (__u32)len, NULL);
	return 0;
}

// read_sockaddr 读取用户态 sockaddr，填充 family/port/addr；返回 0 成功，-1 失败。
static __always_inline int read_sockaddr(const void *sockaddr, __u32 *family, __u32 *port, __u8 *addr)
{
	__u16 f = 0;

	if (bpf_probe_read_user(&f, sizeof(f), sockaddr) < 0)
		return -1;
	*family = f;

	if (f == 2) { /* AF_INET */
		struct sockaddr_in sin = {};

		if (bpf_probe_read_user(&sin, sizeof(sin), sockaddr) < 0)
			return -1;
		*port = bpf_ntohs(sin.sin_port);
		__builtin_memcpy(addr, &sin.sin_addr, 4);
		return 0;
	}
	if (f == 10) { /* AF_INET6 */
		struct sockaddr_in6 sin6 = {};

		if (bpf_probe_read_user(&sin6, sizeof(sin6), sockaddr) < 0)
			return -1;
		*port = bpf_ntohs(sin6.sin6_port);
		__builtin_memcpy(addr, &sin6.sin6_addr, 16);
		return 0;
	}
	return -1;
}

// trace_connect 观测外联：只上报 tainted 进程。
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	const void *sockaddr = (const void *)ctx->args[1];
	__u32 fd = (__u32)ctx->args[0];
	__u32 family = 0;
	__u32 port = 0;
	__u8 addr[16] = {};

	if (!is_tainted_current())
		return 0;
	if (read_sockaddr(sockaddr, &family, &port, addr) < 0)
		return 0;

	report_net(0, family, port, fd, addr);
	return 0;
}

// trace_bind 观测监听端口绑定（全量）。
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
	const void *sockaddr = (const void *)ctx->args[1];
	__u32 fd = (__u32)ctx->args[0];
	__u32 family = 0;
	__u32 port = 0;
	__u8 addr[16] = {};

	if (read_sockaddr(sockaddr, &family, &port, addr) < 0)
		return 0;

	report_net(1, family, port, fd, addr);
	return 0;
}

// trace_listen 观测监听开始（全量，确认 bind 后真的 listen）。
SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx)
{
	__u32 fd = (__u32)ctx->args[0];

	report_net(2, 0, 0, fd, NULL);
	return 0;
}
