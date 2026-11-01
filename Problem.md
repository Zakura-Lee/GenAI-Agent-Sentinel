# 开发问题记录（Problem.md）

- **版本**：v0.1.0
- **日期**：2026-11-01
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
