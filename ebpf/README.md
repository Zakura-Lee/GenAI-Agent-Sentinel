# eBPF 内核态检测

- `src/adr.bpf.c`：eBPF 程序集（execve 观测 + pipe 读写关联），编译为 `build/adr.bpf.o`
- `adr_event.h`：事件 ABI（公共头 + payload），对应 `docs/ebpf-protocol.md`
- `vmlinux.h`：由 `make vmlinux` 通过 `bpftool btf dump` 生成（CO-RE 所需，不入库）
- 用户态加载器为 Go（`internal/egress`，cilium/ebpf），不在本目录

构建：`make -C ebpf`
