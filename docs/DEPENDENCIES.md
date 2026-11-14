# 环境依赖清单

- **版本**：v0.1.0
- **日期**：2026-11-14
- **角色**：Zakura-Lee

> 本项目为 **Go + C/eBPF + 前端（React/TS/Vite）**，**无 Python 组件**，因此不使用 `requirements.txt`。
> 依赖安装脚本见 [`setup.sh`](../setup.sh)，问题记录见 [`Problem.md`](../Problem.md)。

## 1. 系统依赖（Ubuntu 24.04）

| 依赖 | 版本/来源 | 用途 |
|---|---|---|
| build-essential / gcc / g++ / make / cmake / pkg-config | apt | C 编译链 |
| clang / llvm / lld | clang 18+ | eBPF 编译（`-target bpf`） |
| libbpf-dev | 1.3+ | libbpf 头文件与库 |
| **linux-tools-common** | apt | **bpftool**（生成 `vmlinux.h`） |
| libelf-dev / zlib1g-dev / libssl-dev / libcap-dev | apt | libbpf 依赖 |
| git | apt | 版本控制 |
| PostgreSQL 16 + pgvector | apt | 日志 / 知识库存储 |
| Redis 7 | apt | 事件队列 |

安装：`sudo ./setup.sh`

## 2. Go

| 依赖 | 版本 |
|---|---|
| Go | **1.27**（`go.mod` 声明） |
| 模块依赖 | 见 [`go.mod`](../go.mod)：cilium/ebpf、pgx/v5、go-redis/v9、go-openai、grpc、protobuf |

> 注意：snap 版 Go 在部分沙箱环境中不可用（`snap-confine` 权限问题），可改用独立工具链（见 `Problem.md` 问题 1）。

## 3. 前端（后续阶段）

| 依赖 | 版本 |
|---|---|
| Node.js | 24 |
| npm | 11 |
| React + TypeScript + Vite | 见 [`frontend/README.md`](../frontend/README.md)（工程尚未初始化） |

## 4. 运行时要求（eBPF 加载 / LSM 拦截）

| 要求 | 说明 |
|---|---|
| 内核 BTF | `/sys/kernel/btf/vmlinux` 存在（CO-RE 必需） |
| root 或 `CAP_BPF + CAP_PERFMON` | 加载 eBPF 程序 |
| **`lsm=bpf` 内核启动参数** | **LSM 拦截（`taint_deny_open`）必需**；`cat /sys/kernel/security/lsm` 应包含 `bpf` |
| 内核版本 | ≥ 5.15（sleepable LSM / `bpf_d_path`）；本机实测 7.0 |

> 无 `lsm=bpf` 时 LSM 程序无法 attach，当前 loader 会报错退出（后续可加「仅观测降级」）。

## 5. 快速检查

```bash
go version                                  # go1.27+
clang --version                             # 18+
bpftool version                             # v7+
ls /sys/kernel/btf/vmlinux                  # 存在
cat /sys/kernel/security/lsm | grep -o bpf  # LSM 拦截需要
psql --version                              # 16
redis-server --version                      # 7
```
