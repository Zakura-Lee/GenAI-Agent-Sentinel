// taint_test.c - taint 继承验证工具：MarkTaint 注入 + 线程/fork 子/孙 + 读哨兵文件。
// 验证：孙子读哨兵被拒 / 孤儿仍 tainted / 线程归并（dump 条目数）。
// 用法: sudo ./taint_test [obj-path]    （默认 ebpf/build/adr.bpf.o）
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define NTHREADS 4
#define PIN_TAINTS "/sys/fs/bpf/adr/taints"

// adr_taint 对应 eBPF 侧 struct adr_taint（32 字节）
struct adr_taint {
	uint64_t session_id;
	uint64_t tool_id;
	uint32_t agent_type;
	uint32_t depth;
	uint32_t reserved;
	uint32_t pad;
};

// adr_taint_key 对应 eBPF 侧 struct adr_taint_key（16 字节，start_boottime 为 tick 数）
struct adr_taint_key {
	uint32_t tgid;
	uint32_t pad;
	uint64_t start_boottime;
};

// teardown_pins 只删除已知的 pin 名字，绝不做 rm -rf。
static void teardown_pins(void)
{
	unlink(PIN_TAINTS);
}

// get_start_ticks 读 /proc/self/stat 的 starttime（boottime tick 数）。
// 用 fgets + 定位最后一个 ')' 后逐字段解析，避免 fscanf 对 comm 空格/负数字段的解析问题。
static uint64_t get_start_ticks(void)
{
	FILE *f = fopen("/proc/self/stat", "r");
	char buf[1024];
	char *p;
	unsigned long long starttime = 0;
	int field;

	if (!f)
		return 0;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return 0;
	}
	fclose(f);

	p = strrchr(buf, ')');
	if (!p)
		return 0;
	p++;

	// ')' 后第 20 个字段是 starttime
	for (field = 1; field <= 20; field++) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (field == 20) {
			starttime = strtoull(p, NULL, 10);
			break;
		}
		while (*p && *p != ' ' && *p != '\t')
			p++;
	}
	return starttime;
}

static void try_open(const char *who)
{
	int fd = open("/tmp/adr-sentinel", O_RDONLY);
	if (fd < 0)
		printf("[%s] 读 /tmp/adr-sentinel: 被拒 (%s)\n", who, strerror(errno));
	else {
		printf("[%s] 读 /tmp/adr-sentinel: 成功（预期外！）\n", who);
		close(fd);
	}
}

static void *thread_read_sentinel(void *arg)
{
	char name[32];
	snprintf(name, sizeof(name), "线程%s", (char *)arg);
	try_open(name);
	return NULL;
}

// dump_taints 遍历 taints map，打印所有条目并返回条数。
static int dump_taints(struct bpf_map *map)
{
	struct adr_taint_key key, next;
	struct adr_taint val;
	int count = 0;

	if (!map)
		return 0;
	if (bpf_map__get_next_key(map, NULL, &next, sizeof(next)) != 0)
		return 0;
	do {
		key = next;
		if (bpf_map__lookup_elem(map, &key, sizeof(key), &val, sizeof(val), 0) == 0) {
			printf("  taints[tgid=%u start=%llu] session=0x%llx depth=%u\n",
			       key.tgid, (unsigned long long)key.start_boottime,
			       (unsigned long long)val.session_id, val.depth);
			count++;
		}
	} while (bpf_map__get_next_key(map, &key, &next, sizeof(next)) == 0);
	return count;
}

int main(int argc, char **argv)
{
	const char *obj_path = "ebpf/build/adr.bpf.o";
	if (argc > 1)
		obj_path = argv[1];

	teardown_pins();

	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s failed: %s\n", obj_path, strerror(errno));
		return 1;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "load failed\n");
		return 1;
	}

	// attach LSM（taint_deny_open、trace_exit）+ fentry（wake_up_new_task、pipe/dns/sni 观测）
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);
		if (strcmp(name, "taint_deny_open") == 0) {
			if (!bpf_program__attach_lsm(prog)) {
				fprintf(stderr, "attach %s failed: %s\n", name, strerror(errno));
				return 1;
			}
		} else if (strcmp(name, "trace_exit") == 0) {
			if (!bpf_program__attach_tracepoint(prog, "sched", "sched_process_exit")) {
				fprintf(stderr, "attach trace_exit failed: %s\n", strerror(errno));
				return 1;
			}
		} else if (strcmp(name, "wake_up_new_task_entry") == 0 ||
			   strcmp(name, "trace_execve") == 0 ||
			   strcmp(name, "vfs_write_entry") == 0 ||
			   strcmp(name, "vfs_read_exit") == 0 ||
			   strcmp(name, "udp_sendmsg_entry") == 0 ||
			   strcmp(name, "tcp_sendmsg_entry") == 0) {
			continue; // 观测类程序，验证 taint 不需要 attach
		}
	}

	// pin taints map，供外部 bpftool 查证；失败不阻塞验证
	struct bpf_map *taints = bpf_object__find_map_by_name(obj, "taints");
	if (taints) {
		mkdir("/sys/fs/bpf/adr", 0755);
		if (bpf_map__pin(taints, PIN_TAINTS) != 0)
			fprintf(stderr, "pin taints 失败（不影响验证）\n");
	}

	int fd = open("/tmp/adr-sentinel", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) {
		if (write(fd, "secret\n", 7) < 0)
			fprintf(stderr, "写入哨兵文件失败（不影响验证）\n");
		close(fd);
	}

	// MarkTaint 注入自己（key = tgid + start_boottime ticks）
	struct adr_taint_key key = {0};
	key.tgid = (uint32_t)getpid();
	key.start_boottime = get_start_ticks();
	struct adr_taint t = { .session_id = 0x1234, .agent_type = 1, .depth = 1 };
	if (taints && bpf_map__update_elem(taints, &key, sizeof(key), &t, sizeof(t), BPF_ANY) == 0)
		printf("MarkTaint 注入: tgid=%u start_ticks=%llu session_id=0x1234 depth=1\n",
		       key.tgid, (unsigned long long)key.start_boottime);
	else
		printf("MarkTaint 注入失败\n");

	// 线程用例：线程共享进程 taint，读哨兵应被拒，且不新增 taints 条目
	pthread_t threads[NTHREADS];
	char names[NTHREADS][8];
	for (int i = 0; i < NTHREADS; i++) {
		snprintf(names[i], sizeof(names[i]), "%d", i + 1);
		if (pthread_create(&threads[i], NULL, thread_read_sentinel, names[i]) != 0)
			fprintf(stderr, "pthread_create 失败\n");
	}
	for (int i = 0; i < NTHREADS; i++)
		pthread_join(threads[i], NULL);

	// fork 子 → 孙
	pid_t child = fork();
	if (child == 0) {
		pid_t gc = fork();
		if (gc == 0) {
			try_open("孙子进程");
			_exit(0);
		}
		waitpid(gc, NULL, 0);
		sleep(2); // 让父进程先退出，子成孤儿
		try_open("孤儿子进程");
		_exit(0);
	}

	// dump taints map（线程归并后条目数应为 主+子+孙，线程不新增）
	printf("dump taints map:\n");
	int n = dump_taints(taints);
	printf("dump 条目数: %d\n", n);

	printf("主进程退出（exit tracepoint 应清理 taints[%u]）\n", key.tgid);
	teardown_pins();
	return 0;
}
