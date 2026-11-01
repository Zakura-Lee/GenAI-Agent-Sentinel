// lsm_load.c - LSM 程序加载器（libbpf），load + attach_lsm + pin，验证 lsm=bpf 环境。
// 显式指定 attach 目标（bpf_lsm_ 前缀 + hook 名），避免按 section 名解析到错误的 BTF id。
// 用法: sudo ./lsm_load <obj-file> [pin-dir]
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <obj-file> [pin-dir]\n", argv[0]);
		return 1;
	}

	struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "open %s failed: %s\n", argv[1], strerror(errno));
		return 1;
	}

	int err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);
		const char *sec = bpf_program__section_name(prog);
		const char *hook = sec ? strchr(sec, '/') : NULL;

		// LSM hook 在内核 BTF 里的函数名带 bpf_lsm_ 前缀（如 bpf_lsm_file_open）。
		// 显式指定 attach 目标，避免按 section 名解析到错误的 BTF id。
		if (hook) {
			char target[128];
			snprintf(target, sizeof(target), "bpf_lsm_%s", hook + 1);
			err = bpf_program__set_attach_target(prog, 0, target);
			if (err) {
				fprintf(stderr, "set attach target %s failed: %s\n", target, strerror(-err));
				bpf_object__close(obj);
				return 1;
			}
		}

		struct bpf_link *link = bpf_program__attach_lsm(prog);
		if (!link) {
			fprintf(stderr, "attach %s failed: %s\n", name, strerror(errno));
			bpf_object__close(obj);
			return 1;
		}
		printf("attached: %s\n", name);

		if (argc > 2) {
			char path[512];
			snprintf(path, sizeof(path), "%s/%s", argv[2], name);
			err = bpf_link__pin(link, path);
			if (err) {
				fprintf(stderr, "pin %s failed: %s\n", path, strerror(-err));
				return 1;
			}
			printf("pinned:   %s\n", path);
			// pin 已经是持有者，进程退出也不 detach
			bpf_link__disconnect(link);
		}
	}
	return 0;
}
