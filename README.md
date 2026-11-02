# ADR — GenAI Agent Detection & Response

- **版本**：v0.1.1
- **日期**：2026-11-02
- **角色**：Zakura-Lee

ADR 是一个面向安全运营工程师的 **GenAI Agent 检测与响应运营平台**，融合 EDR / SIEM / SOAR 三类能力：

- **EDR（GenAI Agent 专用）**：内核态用 eBPF 捕获 Agent 行为，规则引擎实时判定，支持多设备接入。
- **SIEM**：多设备日志汇聚、存储、检索与**实时监测**，安全运营工程师在平台直接查看日志。
- **SOAR**：告警转工单、工单生命周期管理、剧本化响应编排与（AI 授权的）自主响应。
- **AI 赋能审计**：大模型事后审计 + AI 自主研判 + 规则库自更新 + 简单工单自主响应（默认 DeepSeek，兼容 OpenAI/Claude 等供应商）。

最终交付为**单个可执行文件**，下载即可部署（服务端与设备端以子命令区分）。实现路线、环境依赖与待确认决策见 [`docs/PLAN.md`](docs/PLAN.md)。

## 架构

```
┌─ 设备侧 (adr agent) ───────────────────────────┐      ┌─ 平台侧 (adr server，后续阶段) ─────────┐
│ eBPF 观测: execve / pipe / DNS / SNI            │ gRPC │ 事件入库 (PostgreSQL)                    │
│ taint 继承: wake_up_new_task (group_leader 归并) │ ───► │ SIEM 检索 / 实时推送 (WebSocket)         │
│ LSM 拦截:   taint_deny_open (file_open)         │      │ SOAR 工单 → AI 审计/研判 → 自主响应      │
└─────────────────────────────────────────────────┘      └──────────────────────────────────────────┘
```

## 当前进度

- ✅ **阶段 0**（环境与工程基础）：独立 Go 工具链、单入口 `cmd/adr`、核心依赖。
- ✅ **eBPF 层**（阶段 1 扩展）：execve 观测（argv/envp 固定槽位）、MCP pipe 关联、DNS/SNI 识别、taint 继承、LSM 拦截。
- ✅ **taint 验证**：孙子进程被拦截、线程归并、孤儿仍 tainted、无关进程不受影响。
- ⏳ **下一阶段**：本地规则引擎（`internal/rule`）。

## 目录结构

| 目录 | 说明 | 技术 |
|---|---|---|
| `ebpf/` | 内核态检测程序（`src/adr.bpf.c` 程序集） | C + eBPF (libbpf / CO-RE) |
| `cmd/adr/` | 单入口（`server` / `agent` / `audit` 子命令） | Go |
| `internal/egress/` | eBPF 加载器与事件解析（cilium/ebpf） | Go |
| `internal/rule/` | 规则引擎（下一阶段） | Go |
| `internal/` 其余 | transport / store / soar / audit / web 骨架 | Go |
| `frontend/` | 可视化前端 | React + TypeScript + Vite |
| `db/` | 数据库 schema 与迁移 | PostgreSQL + pgvector |
| `deploy/` | 部署配置 | — |
| `docs/` | 实现计划、eBPF 设计/协议 | Markdown |

## 快速开始

```bash
# 1) 初始化开发环境（已装过可跳过）
sudo ./setup.sh

# 2) 配置环境变量
cp .env.example .env      # 填入 DEEPSEEK_API_KEY / DATABASE_URL 等

# 3) 构建 eBPF 程序（生成 vmlinux.h + 编译 adr.bpf.o）
make build-ebpf

# 4) 构建 Go
make build

# 5) 运行 agent（加载 eBPF，需 root 或 CAP_BPF；LSM 拦截另需内核 lsm=bpf）
sudo go run ./cmd/adr agent
```

> 仓库：https://github.com/Zakura-Lee/GenAI-Agent-Sentinel（Go 模块路径 `github.com/Zakura-Lee/GenAI-Agent-Sentinel`）。

## 产品能力

| 能力 | 说明 | 对应阶段 |
|---|---|---|
| EDR | eBPF 采集 + taint 拦截 + 规则判定 + 多设备接入 | 阶段 1–2、4 |
| SIEM | 日志汇聚 / 检索 / 实时监测 | 阶段 5 |
| SOAR | 工单 + 响应编排 + 自主响应 | 阶段 6、8 |
| AI 审计 | 事后审计 / 自主研判 / 规则自更新 | 阶段 7–8 |
| 交付 | 单可执行文件（`adr server` / `adr agent`） | 阶段 3、9 |

## 文档索引

| 文档 | 内容 |
|---|---|
| [`docs/PLAN.md`](docs/PLAN.md) | 分阶段实现计划与验收标准 |
| [`docs/ebpf-design.md`](docs/ebpf-design.md) | eBPF 层设计：观测 / LSM 拦截 / cgroup 重定向 hook 矩阵 |
| [`docs/ebpf-protocol.md`](docs/ebpf-protocol.md) | eBPF 事件 ABI（map、事件头、payload、时序坑） |
| [`Problem.md`](Problem.md) | 开发期间问题与解决方法记录 |
