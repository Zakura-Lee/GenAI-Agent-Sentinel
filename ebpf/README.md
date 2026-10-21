# eBPF 内核态检测

- `src/*.bpf.c`：eBPF 程序（编译为 BPF 字节码 `.bpf.o`）
- `vmlinux.h`：由 `make vmlinux` 通过 `bpftool btf dump` 生成（CO-RE 所需，不入库）
- 用户态加载器（C）与 `libbpf` 骨架代码后续放在本目录

构建：`make -C ebpf`
