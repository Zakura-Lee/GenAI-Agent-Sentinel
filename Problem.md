# 开发问题记录（Problem.md）

- **版本**：v0.1.6
- **日期**：2026-11-17
- **角色**：Zakura-Lee

> 记录 ADR 开发期间遇到的问题与解决方法，供后续开发避坑。

## 一、环境类

### 1. Go 工具链不可用（snap-confine 权限）
- **现象**：`go version` 报 `snap-confine is packaged without necessary permissions`
- **原因**：Go 来自 snap，沙箱缺 `cap_dac_override`
- **解决**：从 go.dev/dl 下载独立工具链到 `~/.local/go`，`~/.bashrc` 加 `export PATH="$HOME/.local/go/bin:$PATH"`

### 2. proxy.golang.org 连接被拒
- **现象**：`go get` 报 `dial tcp 142.250.69.177:443: connection refused`
- **解决**：`go env -w GOPROXY=https://goproxy.cn,direct`

### 3. 沙箱内无法加载 eBPF（no_new_privs）
- **现象**：`sudo` 报 `The "no new privileges" flag is set`；`CapEff=0`；`unprivileged_bpf_disabled=2`
- **原因**：Reasonix 沙箱隔离边界（no_new_privs + 无 capability + 禁非特权 BPF）
- **解决**：沙箱内只做编译 + 单测，加载验证在宿主机 sudo 执行

## 二、eBPF 编译类

### 4. BPF_CORE_READ 对值成员报错
- **现象**：`member reference type 'struct sock_common' is not a pointer`
- **原因**：BPF_CORE_READ 宏要求中间成员是指针，`__sk_common`/`msg_iter` 是值成员
- **解决**：改用 `bpf_core_read(&dst, sizeof, &src->field.path)` 直接读完整路径

### 5. EPERM 未定义
- **现象**：`use of undeclared identifier 'EPERM'`
- **解决**：`#define EPERM 1`

### 6. vmlinux.h 的 missing-declarations warning
- **现象**：5 条 `declaration does not declare anything`
- **原因**：内核对前向声明的写法，clang BPF target 的习惯性唠叨
- **解决**：无害，忽略（或加 `-Wno-missing-declarations`）

## 三、LSM 加载类（核心踩坑）

### 7. load ≠ attach
- **现象**：`bpftool prog load` 后 cat 哨兵文件仍能读
- **原因**：`BPF_PROG_LOAD` 只把程序装进内核，不创建 link
- **解决**：必须 `bpf_program__attach_lsm` 才参与裁决

### 8. link 绑定 fd，进程退出即 detach
- **原因**：LSM link 绑定在 fd 上，加载器进程退出 → fd 关 → link 销毁 → 程序 detach
- **解决**：`bpf_link__pin` 让 pin 持有 link，进程退出不 detach

### 9. btf_id 解析到错误目标（CONST 类型）
- **现象**：`bpftool prog show` 显示 `btf_id 102`，查得 `[102] CONST '(anon)'`
- **原因**：BTF 里没有 `FUNC 'file_open'`，真正 hook 是 `bpf_lsm_file_open`（static）；按 section 名 `file_open` 解析撞到 CONST 类型
- **解决**：用 `bpf_program__attach_lsm`（内部自动加 `bpf_lsm_` 前缀并处理 static）

### 10. set_attach_target 报 Invalid argument
- **现象**：`set attach target bpf_lsm_file_open failed: Invalid argument`
- **原因**：`set_attach_target` 在 `bpf_object__load` 之后调用（attach_btf_id 在 load 时已固定）
- **解决**：移到 load 之前

### 11. set_attach_target 报 No such process
- **现象**：`set attach target ... failed: No such process`（-ESRCH）
- **原因**：LSM hook 是 static linkage，`set_attach_target` 的通用查找路径不认 static 函数
- **解决**：去掉 `set_attach_target`，用纯 `attach_lsm`（内部解析）

### 12. verifier 拒绝 read_strvec 越界访问
- **现象**：加载报 `invalid access to memory, mem_size=848 off=847 size=511/510`
- **原因**：`dst + off` 与 `size - off` 是两个独立寄存器，verifier 只做值域推理、不做关系推理，各取最坏值判定越界；`off += n-1`（n 是 helper 返回值）让 off 恒为运行期变量，循环带回边未展开（`llvm-objdump -d | grep 'goto -'` 可查回边）
- **解决**：改用「固定槽位 + 常量偏移」（argv[6][64]/envp[6][64]），每次偏移是编译期常量，结构上不可能溢出

### 13. ringbuf 内存未初始化导致信息泄露
- **现象**：reserve 后未清零的槽位残留上一个进程的参数
- **原因**：`bpf_ringbuf_reserve` 返回的内存不保证清零，ringbuf 复用旧事件内存
- **解决**：reserve 后立即 `__builtin_memset` payload 再填字段

### 14. pid 复用导致 taint 串号
- **现象**：进程退出后 pid 被回收，新进程继承旧进程的 taint
- **解决**：taint 表键由 pid 改为 `(tgid, start_boottime tick)`；内核读 `task->start_boottime / NSEC_PER_TICK`，用户态读 `/proc/<pid>/stat` 的 starttime（第 22 字段），两边对齐

### 15. DNS qname 动态拼接同样触发 verifier 越界
- **现象**：`udp_sendmsg_entry` 加载报 `invalid access to memory, off=320 size=255`
- **原因**：qname 逐 label 拼接时 `p->qname + dst` 与 `lbl` 动态关联，同问题 12
- **解决**：eBPF 侧固定大小读原始 qname（label 格式），变长解析移到 Go 的 `parseDNSQname`

### 16. fentry 程序返回值必须为 0
- **现象**：`tcp_sendmsg_entry` 加载报 `R0 has smin=1 smax=1 should have been in [0, 0]`
- **原因**：`return handle_tls_sni(...)` 让 fentry 程序返回了 1，fentry 不允许修改被 hook 函数的返回值
- **解决**：忽略子函数返回值，fentry 程序统一 `return 0`

### 17. task_alloc 时机导致 taint 写错 key
- **现象**：MarkTaint 注入 depth=1，map 读到 depth=2；子进程/孙子未被 tainted
- **原因**：`security_task_alloc` 在 `copy_process` 的 `alloc_pid` 之前，`task->tgid`/`start_boottime` 仍是父进程值，子 key = 父 key，`depth++` 写回父进程
- **解决**：改用 `fentry/wake_up_new_task`（tgid 已设置），key 用 `group_leader->start_boottime` 归并线程组；线程（`tgid != pid`）不重复继承

### 18. taint_test 误将继承程序放进「跳过 attach」分支
- **现象**：线程归并被拒正常（4 线程全拒、dump 仅 1 条），但进程 fork 后孙子未被 tainted（dump 无子/孙条目）
- **原因**：`taint_test.c` 的 attach 循环把 `wake_up_new_task_entry` 与其他观测程序一起 `continue` 跳过，继承程序从未挂载
- **解决**：`wake_up_new_task_entry` 单独 `bpf_program__attach`；仅观测类程序跳过

### 19. LSM 程序用 AttachTracing 挂载报错
- **现象**：朋友拉取仓库后 `sudo adr agent` 报 `挂载程序: invalid program type LSM, expected Tracing`
- **原因**：`taint_deny_open` 是 LSM 程序（`SEC("lsm/file_open")`），`loader.go` 里用 `link.AttachTracing` 挂载；该 API 只接受 Tracing 类型（fentry/fexit）
- **解决**：按程序类型分三种 attach——tracepoint / `AttachTracing`（fentry/fexit）/ `AttachLSM`（LSM）

### 20. argv 槽位越界读到 envp
- **现象**：execve 事件的 argv 里混入环境变量，如 `argv=which ps VSCODE_CWD=/home/fff`
- **原因**：`read_slots` 遇到 NULL（argv 数组结束）后继续读 `vec[i+1..]`，越界读到紧邻的 `envp` 数组
- **解决**：`read_slots` 遇 NULL 置 `stop`，后续槽位不再读取

### 21. C/Go 事件结构布局不一致
- **现象**：argv/envp 解析错位
- **原因**：C 侧槽位从 `[8][32]/[16][32]` 改为 `[6][64]/[6][64]` 时，Go 侧 `ExecPayload` 未同步；总大小都是 784 但内部布局不同（argv 384/256、envp 384/512）
- **解决**：Go 侧 `ExecPayload` 同步为 `Argv [6][64]byte` / `Envp [6][64]byte`，`execPayloadSize` 改为 `16 + 6*64 + 6*64`

### 22. 用户态显式注入未实现（taint 链路悬空）
- **现象**：`MarkTaint`/`GetTaint` 定义了但全仓无调用点，agent 运行时 taints map 永远为空
- **原因**：阶段 1 聚焦 eBPF 观测与 taint 继承/拦截，用户态注入（agent 上报进程标记）未实现
- **解决**：新增 `ReadStartTicks`（读 `/proc/<pid>/stat`）；agent 启动扫描 `/proc` 按 comm 白名单 `MarkTaint`；支持 `ADR_AGENT_WHITELIST` 扩展

### 23. DNS qname 为空
- **现象**：agent 输出 `dns pid=3298 qname=`（qname 全空）
- **原因**：`handle_dns` 用 `bpf_probe_read_user` 固定读 `ADR_NAME_LEN`（256 字节），DNS 包通常远小于 256 字节，从 offset 12 越界导致整段读取失败，qname 保持 memset 的 0
- **解决**：改用 `bpf_probe_read_user_str`，读到 qname 末尾的 0（label 长度 0）停止，不越界
