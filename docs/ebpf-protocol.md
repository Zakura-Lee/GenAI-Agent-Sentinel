# eBPF 层协议 v0

- **版本**：v0.1.0
- **日期**：2026-11-01
- **角色**：Zakura-Lee
- **状态**：草案（MCP pipe 与 taint 继承共同引用）

## 1. 目标与范围

本协议定义 ADR eBPF 层「用户态 ↔ 内核态」的 ABI：map 布局、事件结构、上报语义、时序约束与版本管理。步骤 2（MCP pipe 关联）与步骤 4（taint 继承）均以本协议为准，禁止各自发明一套结构。

## 2. Map ABI

| map 名 | 类型 | key | value | 方向 | 用途 |
|---|---|---|---|---|---|
| `events` | `BPF_MAP_TYPE_RINGBUF`（1 MiB） | — | 事件记录（头 + payload） | 内核 → 用户态 | 所有观测事件上报 |
| `taints` | `BPF_MAP_TYPE_HASH`（1024 条） | `u32` pid(tgid) | `struct adr_taint` | 双向 | 用户态写 agent 根进程标记；内核 fork/exec 继承并查询 |

## 3. 事件结构

### 3.1 事件类型枚举

| 值 | 名称 | 说明 |
|---|---|---|
| 1 | `EXEC` | execve 观测（含 argv/envp） |
| 2 | `EXIT` | 进程退出 |
| 3 | `FORK` | fork/clone（含父子 pid、clone flags） |
| 4 | `PIPE` | 管道读写（MCP stdio 关联） |
| 5 | `DNS` | UDP 53 域名解析 |
| 6 | `SNI` | TLS ClientHello SNI |

### 3.2 事件公共头（64 字节，8 对齐）

```c
struct adr_event_header {
    __u64 ts_ns;             // 时间戳 bpf_ktime_get_ns()
    __u32 type;              // adr_event_type
    __u32 pid;               // 进程 id（tgid）
    __u32 ppid;              // 父进程 id
    __u32 uid;
    __u32 gid;
    __u32 reserved;          // 保留，置 0
    struct adr_taint taint;  // 污点信息（32 字节）
};
```

### 3.3 污点结构（32 字节，8 对齐）

```c
struct adr_taint {
    __u64 session_id;   // agent 会话 id，0 表示未污染
    __u64 tool_id;      // 工具调用 id，0 表示会话根
    __u32 agent_type;   // agent 类型枚举（1=claude,2=codex,3=cursor,...）
    __u32 depth;        // 继承深度（根进程为 1）
    __u32 reserved;     // 保留，置 0
    __u32 pad;          // 对齐
};
```

### 3.4 各事件 payload（紧随头之后）

| 事件 | payload 布局 |
|---|---|
| `EXEC` | `comm[16]` + `argv[256]` + `envp[512]` |
| `EXIT` | `exit_code u32` + `duration_ns u64` |
| `FORK` | `child_pid u32` + `clone_flags u64`（头中 pid 为父进程） |
| `PIPE` | `fd u32` + `dir u8`(0=读,1=写) + `len u16` + `data[128]`（截断载荷） |
| `DNS` | `qname[256]` |
| `SNI` | `server_name[256]` |

> 字节布局两侧（C/Go）必须一致，由 `internal/egress` 单测锁定。现有扁平 `ExecveEvent` 将在步骤 2 迁移到「公共头 + payload」结构。

## 4. 上报语义

- **内核 → 用户态**：所有事件写入 `events` ring buffer，用户态经 `ringbuf.Reader` 顺序读取；事件头 `ts_ns` 由内核采集，用户态不做时序推断。
- **用户态 → 内核**：agent 端采集模块对 `taints` map 执行 `bpf_map_update`，写入「根进程 pid → taint」，作为污点继承起点；`session_id=0` 的写入视为删除。
- **继承语义**：`FORK` 事件携带父进程 taint，用户态（v0）或内核（LSM 版）据此建立子进程 taint，`EXEC` 事件复用同一 taint。

## 5. 时序坑

1. **fork/exec 窗口**：fork 后、exec 前，`argv`/`comm` 尚未就绪，`EXEC` 事件的 argv 只在 sys_enter_execve 时可用；taint 继承必须以 fork 时刻为准，不能等 exec。
2. **pid 复用**：进程退出后 pid 会被复用，`taints` map 必须在 `EXIT` 时删除对应条目，否则新进程串号；`EXIT` 事件与 taint 清理必须原子。
3. **事件乱序**：ring buffer 多 CPU 合并，`ts_ns` 不单调；用户态消费须按事件内容关联，不得依赖到达顺序。
4. **命名空间**：容器内 pid 与宿主机 pid 不同，`pid` 字段统一用**宿主视角 tgid**，容器映射在用户态用 `cgroup_id` 辅助。

## 6. ABI 版本

- 协议版本号 = `adr_event_header` 的 `reserved` 字段低 16 位（v0 为 0）。
- 变更规则：头结构字段增删 → major 升版并拒绝旧对象；仅新增事件类型/payload → minor 升版，旧用户态忽略未知 type。
- 每次升级同步更新本文档元信息（版本/日期/角色）。
