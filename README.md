# ADR — GenAI Agent Detection & Response

ADR 是一个面向安全运营工程师的 **GenAI Agent 检测与响应运营平台**，融合 EDR / SIEM / SOAR 三类能力：

- **EDR（GenAI Agent 专用）**：内核态用 eBPF 捕获 Agent 行为，规则引擎实时判定，支持多设备接入。
- **SIEM**：多设备日志汇聚、存储、检索与**实时监测**，安全运营工程师在平台直接查看日志。
- **SOAR**：告警转工单、工单生命周期管理、剧本化响应编排与（AI 授权的）自主响应。
- **AI 赋能审计**：大模型事后审计 + AI 自主研判 + 规则库自更新 + 简单工单自主响应（默认 DeepSeek，兼容 OpenAI/Claude 等供应商）。

最终交付为**单个可执行文件**，下载即可部署（服务端与设备端以子命令区分）。实现路线、环境依赖与待确认决策见 [`docs/PLAN.md`](docs/PLAN.md)。

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

## 产品能力

| 能力 | 说明 | 对应阶段 |
|---|---|---|
| EDR | eBPF 采集 + 本地规则判定 + 多设备接入 | 阶段 1–2、4 |
| SIEM | 日志汇聚 / 检索 / 实时监测 | 阶段 5 |
| SOAR | 工单 + 响应编排 + 自主响应 | 阶段 6、8 |
| AI 审计 | 事后审计 / 自主研判 / 规则自更新 | 阶段 7–8 |
| 交付 | 单可执行文件（`adr server` / `adr agent`） | 阶段 3、9 |

## 路线图

完整分阶段实现计划与验收标准见 [`docs/PLAN.md`](docs/PLAN.md)。
