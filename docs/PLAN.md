# ADR 实现计划

> 本文档定义 ADR 平台的目标、环境依赖、架构与分阶段实现路线。
> 状态：规划中（待确认「待确认决策」后冻结）。

## 1. 目标与定位

ADR 不是一个单纯的 GenAI Agent EDR，而是一个**完整的 ADR 运营平台**，融合三类能力：

| 能力 | 说明 |
|---|---|
| **EDR（GenAI Agent 专用）** | 内核态 eBPF 采集 Agent 行为，实时规则判定，支持多设备接入 |
| **SIEM** | 多设备日志汇聚、存储、检索与实时监测，安全运营工程师在平台直接查看日志 |
| **SOAR** | 告警转工单、工单生命周期管理、剧本化响应编排与（AI 授权的）自主响应 |
| **AI 事后审计增强** | 大模型事后审计 + AI 自主研判 + 规则库自更新 + 简单工单自主响应 |

最终交付形态：**单个可执行文件**，用户下载即可运行（服务端与设备端通过子命令区分）。

## 2. 需求清单

以下为已确认的核心诉求，后续功能以它们为准：

1. **单文件打包**：平台最终打包成一个可执行文件，方便用户部署使用。
2. **多设备集成**：本地验证通过后接入多设备，后台/前端界面可**实时监测所有设备**。
3. **完整运营平台**：在 EDR 之外补齐 SIEM 与 SOAR，安全运营工程师可在平台查看日志与工单。
4. **AI 赋能审计**：事后审计包含
   - AI 自主研判（对告警/工单给出研判结论）；
   - 规则库自更新（依据研判结果与专家反馈更新规则）；
   - 简单工单自主响应（低风险、可回滚的响应动作）。
5. **交付节奏**：每完成一个功能更新，立即 `git push` 到 GitHub 仓库。

## 3. 环境依赖

### 3.1 开发 / 构建环境（本机实测）

| 依赖 | 版本 | 状态 |
|---|---|---|
| Go | 1.27（`go.mod` 声明） | ⚠️ 见下方「待解决」 |
| Node.js | v24.22.0 | ✅ |
| npm | 11.19.1 | ✅ |
| clang | 18.1.3 | ✅ |
| bpftool | v7.7.0 | ✅ |
| libbpf-dev | 头文件位于 `/usr/include/bpf` | ✅ |
| kernel BTF | `/sys/kernel/btf/vmlinux` 存在 | ✅（可生成 `vmlinux.h`） |
| PostgreSQL | 16.15 | ✅ |
| pgvector | 由 `setup.sh` 安装 | 需在目标 DB 中 `CREATE EXTENSION vector` |
| Redis | 7.0.15 | ✅ |
| Docker | — | 不需要（`setup.sh` 即不含 Docker） |

**待解决**：本机 `go` 来自 snap（`/snap/bin/go` → snap-confine），在沙箱中因缺少
`cap_dac_override` 能力而无法运行。计划第一步将从 <https://go.dev/dl/> 安装独立 Go
工具链到用户目录（或 `/usr/local/go`），绕过 snap，恢复 `go build` / `go test`。

### 3.2 运行环境（部署到用户侧）

- **agent（设备端）**：Linux，内核支持 eBPF CO-RE（存在 BTF）；加载 eBPF 需 `root`
  或 `CAP_BPF + CAP_SYS_ADMIN + CAP_PERFMON`。
- **server（平台端）**：Linux，依赖 PostgreSQL 16 + pgvector、Redis 7；LLM 审计需配置所选
  供应商的 API Key（默认 `DEEPSEEK_API_KEY`，兼容 OpenAI/Anthropic 等）。

## 4. 架构设计

### 4.1 单二进制形态（关键决策）

单一可执行文件 `adr`，用**子命令**区分角色：

```
adr server   # 平台后端：SIEM/SOAR/审计 + 内嵌前端静态资源 + WebSocket 推送
adr agent    # 设备端：eBPF 采集 + 规则判定 + 上报到 server
```

- 前端 `dist/` 通过 `go:embed` 打入二进制。
- eBPF `.bpf.o` 通过 `go:embed` 打入二进制，`adr agent` 在运行时加载，无需外部文件。
- 同一份二进制既能部署平台也能部署探针，满足「一个可执行文件」的诉求。

### 4.2 数据流

```
┌─ 设备 ────────────────────────────┐        ┌─ 平台 server ────────────────────────┐
│ eBPF(内核) → 规则引擎(本地判定)      │ gRPC   │ 事件入库(PostgreSQL)                  │
│            → 告警/事件 → agent      │ ─────► │ SIEM 检索 / 实时推送(WebSocket)      │
└────────────────────────────────────┘        │ SOAR 工单 → AI 审计/研判 → 自主响应   │
                                              │ 规则库自更新 → 下发到各 agent           │
                                              └──────────────────────────────────────┘
```

- **agent → server**：gRPC 双向流（心跳/事件上报 + 规则/指令下发）。
- **前端 → server**：REST（查询/工单操作）+ WebSocket（实时监测所有设备）。

## 5. 技术选型

| 层 | 选型 |
|---|---|
| 后端 | Go（单二进制，`go:embed`） |
| eBPF | C + libbpf CO-RE（`.bpf.o` 由 clang 编译后嵌入） |
| agent↔server | gRPC（Go，protobuf） |
| 前端↔server | REST + WebSocket |
| 前端 | React + TypeScript + Vite（与 `frontend/README.md` 建议一致） |
| 存储 | PostgreSQL 16 + pgvector（日志 + 知识库 + 规则库） |
| 队列/缓存 | Redis 7 |
| LLM | DeepSeek（OpenAI 兼容 API）为主，抽象 Provider 接口，可扩展 Claude/OpenAI 等供应商 |

## 6. 分阶段里程碑

每阶段一个可交付增量，完成后立即 `git push`。验收标准见各阶段 `[c*]`。

### 阶段 0：环境与工程基础
- 安装独立 Go 工具链，恢复 `go build ./...`、`go test ./...`。
- 补齐 monorepo 目录结构与 Makefile 目标（`build` / `test` / `run-server` / `run-agent`）。
- 引入 Go 依赖管理（gRPC、pgx、go-redis、Anthropic SDK、cilium/ebpf 或 libbpf）。
- 验收 [c0]：`make build` 与 `make test` 在干净环境可跑通。

### 阶段 1：eBPF 事件采集（EDR 内核态）
- 扩展 `trace_execve.bpf.c`：捕获 `execve` 关键字段（pid/ppid/comm/argv）并经 ring buffer 上报用户态。
- 编写用户态加载器（Go，加载 `.bpf.o`、挂载 tracepoint、读取事件）。
- 验收 [c1]：`adr agent` 能在目标内核上加载 eBPF 并打印捕获到的 execve 事件。

### 阶段 2：本地规则引擎（agent 内实时判定）
- 实现规则模型（事件类型 + 条件匹配）与判定引擎。
- agent 对 eBPF 事件实时判定，产出本地告警（verdict）。
- 验收 [c2]：构造可疑 execve 可触发告警；规则可增删改。

### 阶段 3：单文件打包 + 本地端到端验证
- `go:embed` 嵌入 `.bpf.o`；`adr server` 内嵌前端占位页。
- 单设备本地闭环：agent 采集 → 判定 → 本地展示/落库。
- 验收 [c3]：单个 `adr` 二进制在无外部资源下启动 server 与 agent。

### 阶段 4：多设备集成（agent → server）
- gRPC 服务端：设备注册/心跳/事件上报；agent 侧接入 gRPC 客户端。
- server 汇聚事件写入 PostgreSQL。
- 验收 [c4]：两台以上 agent 上报事件，server 统一入库并可区分设备。

### 阶段 5：SIEM 平台（日志 + 实时监测）
- 日志检索（按设备/类型/时间/关键字），pgvector 语义检索预留。
- 前端仪表盘：设备列表 + 实时事件流（WebSocket 推送）。
- 验收 [c5]：前端可实时看到所有设备的事件，支持检索与过滤。

### 阶段 6：SOAR 平台（工单 + 响应编排）
- 告警→工单转换、工单状态流转、处置记录。
- 剧本/动作编排骨架；低风险响应动作（如进程 kill、网络封禁）预留接口。
- 验收 [c6]：告警可生成工单并在平台完成流转；响应动作可记录执行结果。

### 阶段 7：AI 事后审计 + 自主研判
- 接入 LLM 审计接口（默认 DeepSeek，OpenAI 兼容协议，Provider 可切换）：对工单/事件做事后审计，输出研判结论（正常/恶意/待定 + 理由）。
- 研判结论回写工单与日志。
- 验收 [c7]：给定事件，审计服务产出可读研判结论并落库展示。

### 阶段 8：规则库自更新 + 简单工单自主响应
- 规则库版本化存储；依据 AI 研判与专家反馈生成/调整规则并下发 agent。
- 「简单工单」白名单 + 低风险动作，AI 授权后自主执行并全程留痕、可回滚。
- 验收 [c8]：规则可自更新并热生效；简单工单可被 AI 自主处置并记录审计链。

### 阶段 9：整合 + 文档 + 发布
- 三能力（EDR/SIEM/SOAR）+ AI 审计整合联调。
- 补充部署文档、打包脚本（跨平台构建）、发布说明。
- 验收 [c9]：单二进制完成「采集 → 判定 → 汇聚 → 监测 → 工单 → AI 研判/响应」全链路演示。

## 7. 目录结构规划

```
cmd/            # 入口（未来改为 cmd/adr 单入口，含 server/agent 子命令）
internal/       # 共享内部包
  egress/       #   eBPF 加载器
  rule/         #   规则引擎
  transport/    #   gRPC 服务端/客户端
  store/        #   PostgreSQL/Redis 访问
  soar/         #   工单与编排
  audit/        #   LLM 审计与研判
  web/          #   前端静态资源 embed + REST/WebSocket
api/            # protobuf 定义（agent↔server）
ebpf/           # eBPF 源文件与 Makefile
frontend/       # React + TS + Vite
db/migrations/  # 数据库迁移
docs/           # 设计/计划文档
deploy/         # 部署配置（systemd 等）
```

## 8. Git 协作流程

- 当前分支 `reasonix/delivery-20261101-*`，`origin` 已配置为
  `https://github.com/Zakura-Lee/GenAI-Agent-Sentinel.git`。
- **每个功能更新完成即 `commit` + `push` 到当前分支**（严格遵守）。
- 遵守 `CLAUDE.md` 的 Conventional Commits 与分支规范；`main` 受保护，最终经 PR 合并。

## 9. 技术决策（已确认）

1. **单二进制形态**：一个 `adr` 可执行文件 + server/agent 子命令（最贴合「单文件」诉求）。
2. **前端框架**：React + TypeScript + Vite。
3. **agent↔server 协议**：gRPC。
4. **LLM 供应商**：主用 DeepSeek（OpenAI 兼容 API），抽象 Provider 接口，可扩展 Claude/OpenAI
   等其他供应商。

确认后即可按阶段 0 开始实现。
