# eBPF 内核态检测

- **版本**：v0.1.0
- **日期**：2026-11-01
- **角色**：Zakura-Lee

## 程序集

- `src/adr.bpf.c`：eBPF 程序集（execve 观测 + pipe 读写关联 + DNS/SNI 识别 + task_alloc 继承 + exit 清理），编译为 `build/adr.bpf.o`
- `adr_event.h`：事件 ABI（公共头 + payload），对应 `docs/ebpf-protocol.md`
- `vmlinux.h`：由 `make vmlinux` 通过 `bpftool btf dump` 生成（CO-RE 所需，不入库）
- 用户态加载器为 Go（`internal/egress`，cilium/ebpf），不在本目录

构建：`make -C ebpf`

## LSM 冒烟测试

- `lsm_smoke.bpf.c`：`lsm/file_open` 对文件名 `adr-deny-test` 返回 `-EPERM`（按 dentry name 匹配，不用 d_path）
- `lsm_load.c`：libbpf loader，`load + attach_lsm + pin`

验证（需 `lsm=bpf` 环境）：

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c lsm_smoke.bpf.c -o /tmp/lsm_smoke.bpf.o
gcc -O2 -g lsm_load.c -o /tmp/lsm_load -lbpf -lelf -lz
sudo mkdir -p /sys/fs/bpf/adr
sudo /tmp/lsm_load /tmp/lsm_smoke.bpf.o /sys/fs/bpf/adr
echo test > /tmp/adr-deny-test   # 期望：不允许的操作
sudo rm -rf /sys/fs/bpf/adr       # 清理（删 pin 即恢复）
```

关键结论（踩坑记录）：

1. `bpftool prog load` 只做 `BPF_PROG_LOAD`（装进内核），**不创建 link**；必须再 `attach_lsm` 才参与裁决。
2. LSM link 绑定 fd，加载器进程退出即 detach；必须 `bpf_link__pin` 才能在进程退出后存活。
3. LSM hook 在内核 BTF 里是 **static** linkage（如 `bpf_lsm_file_open`），`bpf_program__set_attach_target` 按函数名查找会 `-ESRCH`；用 `bpf_program__attach_lsm` 内部解析即可。
