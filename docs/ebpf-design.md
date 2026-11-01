# eBPF 层设计

- **版本**：v0.2.1
- **日期**：2026-11-01
- **角色**：Zakura-Lee
- **状态**：设计草案（v2，已吸收评审意见）

## 1. 设计目标

ADR 平台的 eBPF 层承担三类能力：

1. **行为观测（信息获取）**：捕获 GenAI Agent 的进程、文件、网络、信号、内存等行为事件，为规则引擎与 AI 审计提供事实依据。
2. **API 拦截（强制执行）**：在策略命中时于内核态阻断危险行为。
3. **网络重定向（SOAR 落点）**：对 Agent 外联做 sinkhole 重定向与设备隔离，而不是简单 `EPERM`。

> 设计重点不是「钩子数量」，而是两件事：**Agent 语义**（污点继承、argv/env、MCP 管道、LLM 出口域名）和**绕过面清单**（io_uring、memfd、splice、SCM_RIGHTS、mmap、sendmsg）。钩子数量再多，缺了这两样也只是通用主机 EDR 清单。

## 2. 参考项目分析

| 项目 | 定位 | 借鉴点 | 局限 |
|---|---|---|---|
| [AgentSight](https://github.com/eunomia-bpf/agentsight)（eunomia-bpf） | 纯 eBPF 系统级观测 | 观测 hook 全集：进程/文件/网络/信号/stdio/TLS | 零拦截、无 Agent 语义 |
| [AgentReins-Linux](https://github.com/yardfribley-bit/AgentReins-Linux) | Agent 策略与执行框架 | 拦截走 vendor 的 KubeArmor（LSM BPF + kprobe） | 自身无 eBPF 实现，内核策略下发关闭 |

结论：**观测学 AgentSight，拦截学 KubeArmor 的 LSM BPF 路线**，并在此基础上补 Agent 语义与绕过面。

## 3. 设计原则

1. **三类能力分离**：观测用 `tracepoint`/`kprobe`/`uprobe`（只读）；拦截用 **LSM BPF**；网络重定向用 **cgroup BPF**。
2. **Agent 语义优先**：`task_alloc` 污点继承是产品核心，事件必须携带 `session_id`/`taint` 而非裸 syscall 元组。
3. **CO-RE 必须**：全部经 `vmlinux.h` + BTF 编译；BTF-less 内核提供仅观测降级路径。
4. **拦截以 inode+devid 为主键**：路径在 LSM 里拿不到完整值，且 fd 可继承/可经 `SCM_RIGHTS` 传递，路径白名单必然有漏。
5. **对 LLM Agent 静默降级，不硬拒绝**：直接 `EPERM` 等于告诉模型「换个法子」，默认重定向 sinkhole + 累计触发冻结。
6. **观测与强制是两套 attach**：`security_file_open` 的 fexit 观测程序 ≠ LSM 强制程序，架构上不要画成一条线。

## 4. 行为观测（tracepoint/kprobe/uprobe）hook 矩阵

### 4.1 P0 — Agent 语义与绕过面核心

| 事件 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|
| EXEC | `sys_enter_execve` / `sys_exit_execve` | pid/ppid/uid/gid/comm/**argv/envp**/ret | agent 启动与工具调用；argv/envp 必抓 |
| CLONE | `sys_enter_clone` / `sys_enter_clone3` | pid/**clone_flags** | 命名空间创建（`CLONE_NEWNET` 等容器逃逸） |
| FILELESS_EXEC | `sys_enter_memfd_create` + `sys_enter_execveat` | pid/fd/flags | fileless 执行，磁盘无文件 |
| SOCKET_CREATE | `sys_enter_socket` | pid/**family/type/proto** | 拦 raw/AF_PACKET/AF_NETLINK |
| NET_SEND | `sys_enter_sendmsg` / `sys_enter_sendto` / `sys_enter_writev` | pid/fd/bytes | 库层主流发送路径 |
| NET_RECV | `sys_enter_recvmsg` / `sys_enter_recvfrom` / `sys_enter_readv` | pid/fd/bytes | 库层主流接收路径 |
| DNS | UDP 53 载荷解析（sendmsg/recvmsg） | pid/**域名** | LLM 出口域名识别 |
| SNI | TLS ClientHello 解析 | pid/**SNI** | 识别 `api.openai.com` / `api.deepseek.com` |

### 4.2 P1 — 绕过面与提权链

| 事件 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|
| OPENAT2 | `sys_enter_openat2` | pid/path/flags | 新运行时在用（5.6+） |
| IO_URING | `sys_enter_io_uring_setup` / `sys_enter_io_uring_enter` | pid/fd | 完全绕过 read/write 观测 |
| ZEROCOPY | `sys_enter_sendfile` / `splice` / `copy_file_range` | pid/bytes | 零拷贝外传，read/write 静默漏掉 |
| CRED | `commit_creds`（kprobe）或 `setuid`/`setgid`/`capset` | pid/old/new | 提权链，fork/exit 看不到 cred 变化 |
| MODULE_LOAD | `sys_enter_init_module` / `sys_enter_finit_module` | pid/module | rootkit 第一入口 |
| NS_OPS | `sys_enter_unshare` / `sys_enter_setns` | pid/flags/fd | 命名空间操作，与 clone 互补 |
| PIPE2 | `sys_enter_pipe2` | pid/pipefd | MCP stdio 传输走管道，关联 fd |
| DUP | `sys_enter_dup2` / `sys_enter_dup3` | pid/oldfd/newfd | fd 语义关联，否则 read/write 不知道属于哪条流 |

### 4.3 P2 — 侦察与隐蔽行为

| 事件 | 挂载点（SEC） | 捕获字段 | 检测意义 |
|---|---|---|---|
| GETDENTS | `sys_enter_getdents64` / `sys_enter_readlink` | pid/path | 扫 `~/.ssh`、试探 `.env` 的侦察 |
| KERNEL_PRIMITIVES | `perf_event_open` / `userfaultfd` / `kexec_load` | pid/参数 | 侧信道 / 漏洞原语 / bootkit |
| EXEC_POST | `sched_process_exec` | pid/comm | 补 exec 后的 comm，成本极低 |

### 4.4 文件 / 网络 / 信号 / 系统（继承 v0.1.0）

| 事件 | 挂载点（SEC） | 捕获字段 | 备注 |
|---|---|---|---|
| FILE_OPEN | `sys_enter_openat` | pid/fd/filename/flags | 读敏感文件 |
| FILE_OPEN_RESOLVED | fexit `security_file_open` | pid/路径/dev/ino/mode | **观测程序**，非 LSM 强制；依赖 BTF；抓不到失败的 open |
| FILE_DELETE | `sys_enter_unlinkat` | pid/path | 删文件 |
| FILE_RENAME | `sys_enter_renameat` | pid/old/new | 改名/移动 |
| DIR_CREATE | `sys_enter_mkdirat` | pid/path | 建目录 |
| FILE_TRUNCATE | `sys_enter_ftruncate` | pid/fd/length | 截断文件 |
| CHDIR | `sys_enter_chdir` | pid/path | 切目录 |
| NET_CONNECT | `sys_enter_connect` | pid/ip/port | 外联 |
| NET_BIND | fexit `inet_bind` | pid/ip/port/proto | 监听端口 |
| NET_LISTEN | kprobe `inet_listen` | pid/port | 监听 |
| NET_ACCEPT | fexit `inet_csk_accept` | pid/peer_ip/peer_port | 接受连接 |
| SIGNAL_SEND | `sys_enter_kill` | pid/target_pid/sig | 发信号 |
| SESSION_CREATE | `sys_enter_setsid` | pid | 脱离会话 |
| PGRP_CHANGE | `sys_enter_setpgid` | pid/pgid | 改进程组 |
| PTRACE | `sys_enter_ptrace` | pid/target_pid/request | 注入/调试他进程 |
| BPF_LOAD | `sys_enter_bpf` | pid/cmd | 加载 BPF（隐蔽） |
| MOUNT | `sys_enter_mount` | pid/source/target/fstype | 挂载（逃逸） |
| EXIT | `sched_process_exit` | pid/comm/exit_code/duration | 进程生命周期 |
| FORK | `sched_process_fork` | child_pid/parent_pid | 血缘追踪 |
| READ/WRITE | `sys_enter_read` / `sys_enter_write` | pid/fd/bytes | **载荷采样**，见 4.6 |

### 4.5 已删除

- **`do_wp_page`（COW_FAULT）**：缺页热路径每秒几十万次，安全价值（Dirty COW 时代）已极低。自改写/进程镂空改由 `file_mprotect` 的 W^X 判定覆盖。

### 4.6 载荷采集策略

- read/write 载荷**不全量**，仅当「被污点标记的进程 + fd 类型属于 pipe/tty/socket + 采样」三者同时满足时取载荷。
- 明确 writev/sendmsg/mmap/io_uring/splice 是绕过口，载荷采集不是内容全覆盖。

## 5. API 拦截（LSM BPF）hook 矩阵

> 拦截统一走 LSM BPF（返回非零值即拒绝）。路径类拦截一律以 **inode+devid 为第二主键**，不把路径当唯一依据。

### 5.1 P0 — Agent 语义与绕过面核心

| LSM 挂载点（SEC） | 拦截动作 | 对应观测 |
|---|---|---|
| `task_alloc` | **进程出生时打污点并继承**（属于哪个 Agent 会话/哪次工具调用） | —（产品核心能力） |
| `inode_create` | 拒绝创建文件（投递 payload） | 新增 |
| `file_receive` | 校验 `SCM_RIGHTS` 收 fd | 路径策略标准绕过 |
| `mmap_file` | 拦「下载即执行」，exec mmap 唯一强制点 | FILE_OPEN |
| `socket_create` | 拦 raw / AF_PACKET / AF_NETLINK | SOCKET_CREATE |
| `file_open` | 拒读敏感路径（`.ssh`、`.env`、凭据） | FILE_OPEN |
| `bprm_check_security` | 拒绝执行可疑二进制（exec 前阻断） | EXEC |

### 5.2 P1 — 提权与逃逸

| LSM 挂载点（SEC） | 拦截动作 | 对应观测 |
|---|---|---|
| `file_mprotect` | W^X（替代已删的 do_wp_page） | — |
| `bprm_creds_for_exec` / `task_fix_setuid` | setuid/setcap 提权链 | CRED |
| `sb_umount` / `sb_pivotroot` | 容器逃逸与「卸载以隐藏」 | MOUNT |
| `inode_unlink` / `inode_rename` | 拒绝删除/改名（注意拿的是父 dentry，非完整路径） | FILE_DELETE / FILE_RENAME |
| `socket_connect` | 拒绝连接未知/敏感端点 | NET_CONNECT |
| `ptrace_access_check` | 拒绝进程注入 | PTRACE |
| `task_kill` | 拒绝杀进程 | SIGNAL_SEND |

### 5.3 P2 — 持久化与隐蔽

| LSM 挂载点（SEC） | 拦截动作 | 对应观测 |
|---|---|---|
| `file_ioctl` | 拦 `TIOCSTI` 注入、`FS_IOC_SETFLAGS` 锁死文件 | — |
| `socket_setsockopt` | 拦 `SO_ATTACH_BPF` 挂 BPF 隐藏流量 | — |
| `socket_accept` | 入站管控（Agent 自己监听 = 新攻击面） | NET_ACCEPT |
| `inode_link` / `inode_symlink` / `inode_setattr` | 持久化与权限篡改 | — |
| `kernel_read_file` / `kernel_load_data` | 模块/固件加载路径 | MODULE_LOAD |
| `bpf` | 拒绝加载未签名 BPF | BPF_LOAD |
| `sb_mount` | 拒绝挂载 | MOUNT |
| `inode_mkdir` / `path_truncate` | 拒绝建目录/截断 | DIR_CREATE / FILE_TRUNCATE |

### 5.4 降级 / 不承诺

| LSM 挂载点（SEC） | 结论 |
|---|---|
| `file_permission` | 每读写都过的热路径，**降级**：不挂或只做极轻 map 命中判断 |
| `socket_sendmsg` / `socket_recvmsg` | 内容级阻断可被 splice / MSG_ZEROCOPY / kTLS 绕过，**只做元数据审计，不承诺 DLP** |

## 6. 网络重定向（cgroup BPF）— 第三类别

对 LLM Agent 硬拒绝（`EPERM`）会促使模型变形重试，默认应「静默降级 + 重定向」：

| 挂载点（SEC） | 动作 | 用途 |
|---|---|---|
| `cgroup/connect4` + `cgroup/connect6` | 外联重定向到 sinkhole | LLM 出口管控、隐蔽拦截 |
| `cgroup/skb_ingress` + `cgroup/skb_egress` | 入站/出站重定向 | SOAR「隔离设备」落点 |

> 没有这一类别，SOAR 的「隔离设备」「重定向 sinkhole」就没有内核落点。

## 7. TLS 明文观测（三层方案，非单一 uprobe）

`SSL_read/SSL_write` uprobe 只对 CPython（链 libssl）有效，对 Node.js（BoringSSL 静态内联）、Go（自研 `crypto/tls`，符号表里没有 `SSL_read`）、Rust（rustls inline/mangle）基本无效——而 Agent 恰恰主要是这三种。因此：

| 层 | 方案 | 说明 |
|---|---|---|
| 1（主） | 本地透明代理 / MITM | 用户导入 CA，拿 prompt / tool-call / MCP JSON-RPC 的完整语义 |
| 2（辅） | kTLS + 明文 HTTP | 能白拿就不解密 |
| 3（兜底） | uprobe 仅 OpenSSL/GnuTLS；Go 按 `.gopclntab` 符号名做版本适配表；Rust 按 crate mangled 名 | 明确「每升一个大版本要重新适配」 |

> 要的是「Agent 让模型读了哪份文件、把什么发给了谁」——这是**语义层**，syscall 字节流给不了。

## 8. 工程可行性

1. **必须 CO-RE**，否则跨内核需带头文件编译；BTF-less 内核要有仅观测降级路径。
2. **BPF LSM 不是到处都有**：需 `CONFIG_BPF_LSM` + `lsm=` 引导参数（RHEL8 系 4.18 根本没有）。必须提供「降级为仅观测」模式并在 UI 明示，避免客户以为「强制执行」生效实则没生效。
3. **事件 schema 比钩子数量重要**：`pid/ppid/cgroup_id/container_id/session_id/taint/argv/env/cwd/policy_id/decision/rule_version` 这些字段决定「大模型事后审计」能不能用；只给裸 syscall 元组，再强的模型也只能猜。
4. **背压与丢事件策略**：ringbuf 满时明确「丢弃还是阻塞」，丢弃必须把丢失计数送 SIEM，否则审计结论是错的。
5. **本机现状**：内核 LSM 链 `lockdown,capability,landlock,yama,apparmor,ima,evm` 未含 `bpf`；部署拦截需 `lsm=bpf` 引导参数并重启。

## 9. 事件 schema（约定）

统一事件字段（观测与拦截共用，供规则引擎与 AI 审计消费）：

```
ts, event_type, pid, ppid, cgroup_id, container_id, session_id, taint,
comm, argv, env, cwd, policy_id, decision, rule_version, detail(jsonb)
```

## 10. 与现有实现的衔接

- 阶段 1 已实现 `sys_enter_execve` 观测（EXEC 事件 + ring buffer），对应本矩阵 4.1 第一行。
- 已补 `envp` 捕获：事件结构含 argv+envp（Go 侧 `Envp[512]`），agent 打印 `pid/ppid/uid/gid/comm/argv/envp`。
- 后续按 11 节优先级增量扩展；下一步 `task_alloc` 污点继承，判定走**用户态显式注入**（agent 端上报进程标记，Linux 注入方式待适配）。

## 11. 分阶段实施（四件最优先）

| 优先级 | 事项 | 说明 |
|---|---|---|
| **1** | `task_alloc` 污点继承 | Agent 会话/工具调用污点，产品核心 |
| **2** | `execve` 抓 argv/env | 否则等于只记「有人 exec」 |
| **3** | MCP pipe 关联 | `pipe2` + `dup2/3` 关联 fd，识别 MCP stdio 流 |
| **4** | LLM 出口 SNI/DNS 识别 | `connect` 只有 IP，拿不到 `api.deepseek.com` |

四件做完，再谈 28 还是 40 个钩子。
