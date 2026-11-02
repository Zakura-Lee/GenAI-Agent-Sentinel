# eBPF 内核态检测

- **版本**：v0.1.1
- **日期**：2026-11-02
- **角色**：Zakura-Lee

## 程序集（`src/adr.bpf.c`）

| 程序 | 类型 | 作用 |
|---|---|---|
| `trace_execve` | tracepoint | execve 观测（comm / argv / envp，固定槽位） |
| `vfs_write_entry` / `vfs_read_exit` | fentry / fexit | pipe 读写关联（按 inode 配对，MCP stdio） |
| `udp_sendmsg_entry` | fentry | DNS 识别（固定大小读原始 qname，用户态解析） |
| `tcp_sendmsg_entry` | fentry | SNI 识别（TLS ClientHello） |
| `wake_up_new_task_entry` | fentry | taint 继承（key 用 `group_leader->start_boottime` 归并线程组） |
| `trace_exit` | tracepoint | 清理 taint（防 pid 复用串号） |
| `taint_deny_open` | LSM | tainted 进程打开哨兵文件返回 `-EPERM` |

- `adr_event.h`：事件 ABI（公共头 + payload），对应 `docs/ebpf-protocol.md`
- `vmlinux.h`：由 `make vmlinux` 通过 `bpftool btf dump` 生成（CO-RE 所需，不入库）
- 用户态加载器为 Go（`internal/egress`，cilium/ebpf），不在本目录

构建：`make -C ebpf`

## taint 继承验证（`taint_test.c`）

验证四条：孙子进程读哨兵被拒 / 无关进程不受影响 / 会话结束 map 清空 / 孤儿仍 tainted。

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c src/adr.bpf.c -o build/adr.bpf.o
gcc -O2 -g taint_test.c -o /tmp/taint_test -lbpf -lelf -lz -lpthread
sudo /tmp/taint_test build/adr.bpf.o
```

## LSM 冒烟测试（`lsm_smoke.bpf.c` + `lsm_load.c`）

验证 `lsm=bpf` 环境可 attach 且返回值生效（需 `lsm=bpf` 启动参数）：

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c lsm_smoke.bpf.c -o /tmp/lsm_smoke.bpf.o
gcc -O2 -g lsm_load.c -o /tmp/lsm_load -lbpf -lelf -lz
sudo mkdir -p /sys/fs/bpf/adr
sudo /tmp/lsm_load /tmp/lsm_smoke.bpf.o /sys/fs/bpf/adr
echo test > /tmp/adr-deny-test   # 期望：不允许的操作
sudo rm -rf /sys/fs/bpf/adr       # 清理（删 pin 即恢复）
```

## 关键结论（踩坑记录，详见 `Problem.md`）

1. `bpftool prog load` 只做 `BPF_PROG_LOAD`（装进内核），**不创建 link**；必须再 `attach_lsm` 才参与裁决。
2. LSM link 绑定 fd，加载器进程退出即 detach；必须 `bpf_link__pin` 才能在进程退出后存活。
3. LSM hook 在内核 BTF 里是 **static** linkage（如 `bpf_lsm_file_open`），`bpf_program__set_attach_target` 按函数名查找会 `-ESRCH`；用 `bpf_program__attach_lsm` 内部解析即可。
4. 变长数据在 BPF 侧一律「固定槽位 + 常量偏移」，变长语义留给用户态；`ringbuf reserve` 后先 `memset`。
5. taint 继承用 `fentry/wake_up_new_task`（`task_alloc` 时 tgid 尚未分配）；fentry 程序必须返回 0。
