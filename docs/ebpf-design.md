# eBPF 层设计

- **版本**：v0.1.0
- **日期**：2026-11-01
- **角色**：Zakura-Lee
- **状态**：设计草案（待确认后实施）

## 1. 设计目标

ADR 平台的 eBPF 层承担两项能力，缺一不可：

1. **信息获取（观测）**：捕获 GenAI Agent 的进程、文件、网络、信号、内存等行为事件，为规则引擎与 AI 审计提供事实依据。
2. **API 拦截（强制执行）**：在策略命中时于内核态阻断危险行为（读敏感文件、外联未知端点、执行可疑二进制、注入他进程等）。

## 2. 参考项目分析

| 项目 | 定位 | 借鉴点 | 局限 |
|---|---|---|---|
| [AgentSight](https://github.com/eunomia-bpf/agentsight)（eunomia-bpf） | 纯 eBPF 系统级观测 | 完整的观测 hook 矩阵：进程/文件/网络/信号/内存/stdio 载荷/TLS 明文 | **零拦截**，只有观测 |
| [AgentReins-Linux](https://github.com/yardfribley-bit/AgentReins-Linux) | Agent 策略与执行框架 | 拦截能力来自 vendor 的 KubeArmor（LSM BPF + kprobe） | 自身无 eBPF 实现，内核策略下发「保持关闭」 |

结论：**观测面学 AgentSight，拦截面学 KubeArmor 的 LSM BPF 路线**，二者合为 ADR 的 eBPF 层。

## 3. 设计原则

1. **观测与拦截分离**：观测用 `tracepoint` / `kprobe` / `uprobe`（只读、低风险）；拦截用 **LSM BPF**（内核授权，返回非零即拒绝）。
2. **CO-RE 优先**：全部经 `vmlinux.h` + BTF 编译，跨内核版本可移植。
3. **事件统一上报**：所有观测事件经 `BPF_MAP_TYPE_RINGBUF` 上报用户态，与阶段 1 一致。
4. **拦截可审计、可回滚**：拦截动作必须记录到事件流，策略由用户态下发（后续阶段 2/8 对接）。

## 4. 信息获取（观测）hook 矩阵

### 4.1 进程类

| 事件 | 程序类型 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|---|
| EXEC | tracepoint | `syscalls/sys_enter_execve` | pid/ppid/uid/gid/comm/argv | agent 启动与工具调用（阶段 1 已有） |
| EXEC_RET | tracepoint | `syscalls/sys_exit_execve` | pid/ret | exec 成败 |
| EXIT | tracepoint | `sched/sched_process_exit` | pid/comm/exit_code/duration | agent 进程生命周期 |
| FORK | tracepoint | `sched/sched_process_fork` | child_pid/parent_pid | agent 派生子进程（血缘追踪） |

### 4.2 文件类

| 事件 | 程序类型 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|---|
| FILE_OPEN | tracepoint | `syscalls/sys_enter_openat` | pid/fd/filename/flags | agent 读敏感文件 |
| FILE_OPEN_RESOLVED | fexit | `security_file_open` | pid/绝对路径/dev/ino/mode | 解析真实路径（符号链接/相对路径） |
| FILE_DELETE | tracepoint | `syscalls/sys_enter_unlinkat` | pid/path | agent 删文件 |
| FILE_RENAME | tracepoint | `syscalls/sys_enter_renameat` | pid/old/new | agent 改名/移动 |
| DIR_CREATE | tracepoint | `syscalls/sys_enter_mkdirat` | pid/path | agent 建目录 |
| FILE_TRUNCATE | tracepoint | `syscalls/sys_enter_ftruncate` | pid/fd/length | agent 截断文件 |
| CHDIR | tracepoint | `syscalls/sys_enter_chdir` | pid/path | agent 切目录 |

### 4.3 读写类

| 事件 | 程序类型 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|---|
| READ | tracepoint | `syscalls/sys_enter_read` | pid/fd/bytes | agent 读（stdin/文件） |
| WRITE | tracepoint | `syscalls/sys_enter_write` | pid/fd/bytes | agent 写（stdout/文件） |
| STDIO_PAYLOAD | tracepoint | `sys_enter/exit read/write` | fd/payload/latency | 捕获 stdio/pipe 载荷 |

### 4.4 网络类

| 事件 | 程序类型 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|---|
| NET_CONNECT | tracepoint | `syscalls/sys_enter_connect` | pid/ip/port | agent 外联（API 端点/可疑 C2） |
| NET_BIND | fexit | `inet_bind` | pid/ip/port/proto | agent 监听端口 |
| NET_LISTEN | kprobe+kretprobe | `inet_listen` | pid/port | agent 监听 |
| NET_ACCEPT | fexit | `inet_csk_accept` | pid/peer_ip/peer_port | agent 接受连接 |
| NET_SEND | tracepoint | `syscalls/sys_enter_sendto` | pid/ip/port/bytes | agent 外发数据量 |
| NET_RECV | tracepoint | `syscalls/sys_enter_recvfrom` | pid/ip/port/bytes | agent 接收数据 |

### 4.5 信号 / 进程操作类

| 事件 | 程序类型 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|---|
| SIGNAL_SEND | tracepoint | `syscalls/sys_enter_kill` | pid/target_pid/sig | agent 发信号 |
| SESSION_CREATE | tracepoint | `syscalls/sys_enter_setsid` | pid | agent 脱离会话 |
| PGRP_CHANGE | tracepoint | `syscalls/sys_enter_setpgid` | pid/pgid | agent 改进程组 |
| PTRACE | tracepoint | `syscalls/sys_enter_ptrace` | pid/target_pid/request | agent 注入/调试他进程 |

### 4.6 系统 / 隐蔽行为类

| 事件 | 程序类型 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|---|
| BPF_LOAD | tracepoint | `syscalls/sys_enter_bpf` | pid/comm/cmd | agent 加载 BPF（隐蔽行为） |
| MOUNT | tracepoint | `syscalls/sys_enter_mount` | pid/source/target/fstype | agent 挂载（逃逸） |
| COW_FAULT | kprobe | `do_wp_page` | pid/addr | 内存篡改/逃逸 |

### 4.7 TLS 明文观测（可选，较重）

| 事件 | 程序类型 | 挂载点（SEC） | 捕获字段 | 说明 |
|---|---|---|---|---|
| TLS_READ/WRITE | uprobe/uretprobe | `SSL_read`/`SSL_write`/`rustls_write` | pid/明文长度/明文 | 覆盖 OpenSSL/GnuTLS/NSS/BoringSSL/Rustls，观测 agent 明文通信 |

## 5. API 拦截（强制执行）hook 矩阵

拦截统一走 **LSM BPF**（返回非零值即拒绝操作），与观测事件一一对应：

| 类别 | LSM 挂载点（SEC） | 拦截动作 | 对应观测事件 |
|---|---|---|---|
| 文件 | `lsm/file_open` | 拒绝读敏感路径（`.ssh/id_*`、`.env`、凭据、`~/.aws`） | FILE_OPEN |
| 文件 | `lsm/file_permission` | 拒绝写关键文件/目录 | WRITE / FILE_TRUNCATE |
| 文件 | `lsm/inode_unlink` | 拒绝删除 | FILE_DELETE |
| 文件 | `lsm/inode_rename` | 拒绝改名/移动 | FILE_RENAME |
| 文件 | `lsm/inode_mkdir` | 拒绝建目录 | DIR_CREATE |
| 文件 | `lsm/path_truncate` | 拒绝截断 | FILE_TRUNCATE |
| 网络 | `lsm/socket_connect` | 拒绝连接未知/敏感端点 | NET_CONNECT |
| 网络 | `lsm/socket_bind` | 拒绝绑定端口 | NET_BIND |
| 网络 | `lsm/socket_sendmsg` | 拒绝外发敏感数据 | NET_SEND |
| 网络 | `lsm/socket_recvmsg` | 拒绝接收 | NET_RECV |
| 进程 | `lsm/bprm_check_security` | 拒绝执行可疑二进制（exec 前阻断） | EXEC |
| 进程 | `lsm/ptrace_access_check` | 拒绝进程注入 | PTRACE |
| 进程 | `lsm/task_kill` | 拒绝杀进程 | SIGNAL_SEND |
| 系统 | `lsm/bpf` | 拒绝加载未签名 BPF 程序 | BPF_LOAD |
| 系统 | `lsm/sb_mount` | 拒绝挂载 | MOUNT |

## 6. 拦截机制选型与可行性

| 方案 | 结论 | 说明 |
|---|---|---|
| **LSM BPF**（推荐） | ✅ 采用 | 内核授权、覆盖文件/网络/进程/系统全类别；需内核 `CONFIG_BPF_LSM=y` 且启动参数含 `lsm=bpf` |
| kprobe override return（`bpf_override_return`） | ❌ 不采用 | 需 `CONFIG_BPF_KPROBE_OVERRIDE`，多数发行版默认关闭，且被 `lockdown` 限制，不安全 |
| seccomp filter | 🔶 辅助 | 用户态配合，作为兜底（阶段 8 再评估） |

**本机现状**：内核 `7.0.0-38-generic` 的 LSM 链为 `lockdown,capability,landlock,yama,apparmor,ima,evm`，**未含 `bpf`**。部署拦截功能需在目标机将 `lsm=bpf` 加入内核启动参数并重启。

## 7. 与现有实现的衔接

- 阶段 1 已实现 `sys_enter_execve` 观测（EXEC 事件 + ring buffer），为本矩阵「4.1 进程类」的第一行。
- 后续按优先级增量扩展：先补进程类与文件类观测，再补网络类观测，最后接 LSM 拦截（需 `lsm=bpf` 环境）。

## 8. 分阶段实施建议

| 阶段 | 内容 |
|---|---|
| A | 补齐进程类（EXIT/FORK）+ 文件类观测（FILE_OPEN/FILE_DELETE/RENAME） |
| B | 补齐网络类观测（NET_CONNECT/BIND/ACCEPT）与信号类 |
| C | LSM BPF 拦截框架 + 敏感文件/外联拦截（需 `lsm=bpf`） |
| D | TLS 明文观测、stdio 载荷、隐蔽行为（BPF_LOAD/MOUNT/COW） |
