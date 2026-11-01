// taint_test.c - taint 继承验证工具：MarkTaint 注入 + fork 子/孙 + 读哨兵文件。
// 验证：孙子读哨兵被拒 / 孤儿仍 tainted；无关进程与 map 清空由外部验证。
// 用法: sudo ./taint_test [obj-path]    （默认 ebpf/build/adr.bpf.o）
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// adr_taint 对应 eBPF 侧 struct adr_taint（32 字节）
struct adr_taint {
	uint64_t session_id;
	uint64_t tool_id;
	uint32_t agent_type;
	uint32_t depth;
	uint32_t reserved;
	uint32_t pad;
};

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

int main(int argc, char **argv)
{
	const char *obj_path = "ebpf/build/adr.bpf.o";
	if (argc > 1)
		obj_path = argv[1];

	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s failed: %s\n", obj_path, strerror(errno));
		return 1;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "load failed\n");
		return 1;
	}

	// attach LSM（task_alloc + taint_deny_open）+ trace_exit
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);
		if (strcmp(name, "task_alloc_entry") == 0 ||
		    strcmp(name, "taint_deny_open") == 0) {
			if (!bpf_program__attach_lsm(prog)) {
				fprintf(stderr, "attach %s failed: %s\n", name, strerror(errno));
				return 1;
			}
		} else if (strcmp(name, "trace_exit") == 0) {
			if (!bpf_program__attach_tracepoint(prog, "sched", "sched_process_exit")) {
				fprintf(stderr, "attach trace_exit failed: %s\n", strerror(errno));
				return 1;
			}
		}
	}

	// pin taints map，供外部 bpftool 查证 map 清空
	struct bpf_map *taints = bpf_object__find_map_by_name(obj, "taints");
	if (taints) {
		mkdir("/sys/fs/bpf/adr", 0755);
		bpf_map__pin(taints, "/sys/fs/bpf/adr/taints");
	}

	int fd = open("/tmp/adr-sentinel", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) {
		if (write(fd, "secret\n", 7) < 0)
			fprintf(stderr, "写入哨兵文件失败（不影响验证）\n");
		close(fd);
	}

	// MarkTaint 注入自己
	uint32_t pid = (uint32_t)getpid();
	struct adr_taint t = { .session_id = 0x1234, .agent_type = 1, .depth = 1 };
	if (taints && bpf_map__update_elem(taints, &pid, sizeof(pid), &t, sizeof(t), BPF_ANY) == 0)
		printf("MarkTaint 注入: pid=%u session_id=0x1234 depth=1\n", pid);
	else
		printf("MarkTaint 注入失败\n");

	// fork 子 → 孙
	pid_t child = fork();
	if (child == 0) {
		pid_t gc = fork();
		if (gc == 0) {
			try_open("孙子进程"); // 验证1：孙子读哨兵应被拒
			_exit(0);
		}
		waitpid(gc, NULL, 0);
		sleep(2);               // 让父进程先退出，子成孤儿
		try_open("孤儿子进程"); // 验证4：孤儿仍 tainted，读哨兵应被拒
		_exit(0);
	}

	// 主进程：读 map 验证 taint 条目，然后立即退出（子成孤儿）
	struct adr_taint got;
	if (taints && bpf_map__lookup_elem(taints, &pid, sizeof(pid), &got, sizeof(got), 0) == 0)
		printf("map 验证: pid=%u session_id=0x%llx depth=%u（主进程退出前）\n",
		       pid, (unsigned long long)got.session_id, got.depth);

	printf("主进程退出（exit tracepoint 应清理 taints[%u]）\n", pid);
	return 0;
}
