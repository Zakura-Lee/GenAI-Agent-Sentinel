# ADR — GenAI Agent Detection & Response

针对 GenAI Agent 的检测与响应系统。在内核态用 eBPF 捕获 Agent 行为，规则引擎实时判定，大模型做事后审计，前端可视化，数据库存储日志与知识库。

## 架构

```
┌─────────────┐   eBPF 事件   ┌──────────────┐   告警/审计   ┌─────────────┐
│  eBPF 内核态 │ ────────────► │ 规则 agent    │ ────────────► │ LLM 事后审计 │
│  (C + libbpf)│               │  (Go)        │               │  (Go/Python)│
└─────────────┘               └──────┬───────┘               └──────┬──────┘
                                     │                              │
                                     ▼                              ▼
                              ┌─────────────┐              ┌──────────────┐
                              │  PostgreSQL  │◄────────────►│  Redis 队列   │
                              │  + pgvector  │              └──────────────┘
                              └─────────────┘
                                     ▲
                                     │
                              ┌─────────────┐
                              │   前端控制台 │
                              └─────────────┘
```

## 目录结构

| 目录 | 说明 | 技术 |
|---|---|---|
| `ebpf/` | 内核态检测程序 | C + eBPF (libbpf / CO-RE) |
| `cmd/agent/` | 规则 agent | Go |
| `cmd/audit/` | LLM 事后审计 | Go |
| `internal/` | 共享内部包 | Go |
| `frontend/` | 可视化前端 | Node (待定) |
| `db/` | 数据库 schema 与迁移 | PostgreSQL + pgvector |
| `deploy/` | 部署配置 | — |

## 快速开始

```bash
# 1) 初始化开发环境（已装过可跳过）
sudo ./setup.sh

# 2) 配置环境变量
cp .env.example .env      # 填入 ANTHROPIC_API_KEY 等

# 3) 构建 eBPF 程序（生成 vmlinux.h + 编译 .bpf.o）
make build-ebpf

# 4) 构建 Go 服务
make build

# 5) 初始化数据库
sudo -u postgres createdb adr
sudo -u postgres psql -d adr -f db/schema.sql
```

> 仓库：https://github.com/Zakura-Lee/GenAI-Agent-Sentinel（Go 模块路径 `github.com/Zakura-Lee/GenAI-Agent-Sentinel`）。
