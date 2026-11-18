# AI Agent/Harness 识别与模型厂商/版本推断

- **版本**：v0.3.1
- **日期**：2026-11-17
- **角色**：Zakura-Lee

端点侧识别：主机上正在运行哪些 **AI Agent/Harness**（Claude Code、Cursor、Codex、Cline、Aider…），以及它们使用的**模型厂商**与**模型版本**。

> 与「推理服务发现」（ollama/vllm 端口 + 模型文件扫描）不同：本模块关注的是 **Agent 客户端**，而不是本地模型服务。

## 1. 识别矩阵

| 线索 | 采集方式 | 能识别什么 |
|---|---|---|
| **进程名**（comm） | eBPF `execve` / `/proc/<pid>/comm` | Agent 产品（claude / cursor / codex…） |
| **命令行**（cmdline） | `/proc/<pid>/cmdline` | Agent 产品 + `--model` 显式指定 |
| **配置文件** | `~/.claude/settings.json`、`.cursorrules`、`.aider.conf.yml`… | **模型版本 + 厂商** |
| **环境变量** | `/proc/<pid>/environ`（白名单） | API key 变量名 → 厂商；`*_MODEL` → 版本 |
| **API 域名** | eBPF **SNI/DNS**（运行时） | 厂商（`api.anthropic.com` → Anthropic） |

## 2. 已知 Agent/Harness 白名单

| Harness | 进程/命令行特征 | 配置文件 | 环境变量特征 |
|---|---|---|---|
| `claude-code` | `claude` | `~/.claude/settings.json`、`.claude/settings.json` | `ANTHROPIC_API_KEY`、`ANTHROPIC_MODEL`、`CLAUDE_MODEL` |
| `cursor` | `cursor` | `~/.cursor/`、`.cursorrules`、`.cursor/rules` | `CURSOR_API_KEY` |
| `codex` | `codex` | `~/.codex/`、`.codex/` | `OPENAI_API_KEY`、`OPENAI_MODEL` |
| `cline` | `cline` | `.clinerules`、`~/.cline/`、`.cline/` | `ANTHROPIC_API_KEY`、`OPENAI_API_KEY` |
| `aider` | `aider` | `.aider.conf.yml`、`~/.aider.conf.yml` | `ANTHROPIC_API_KEY`、`OPENAI_API_KEY`、`DEEPSEEK_API_KEY` |
| `continue` | `continue` | `~/.continue/config.json`、`.continue/` | `ANTHROPIC_API_KEY`、`OPENAI_API_KEY` |
| `windsurf` | `windsurf` | `~/.codeium/windsurf/` | `CODEIUM_API_KEY` |
| `zed` | `zed` | `~/.config/zed/settings.json`、`.zed/settings.json` | `ANTHROPIC_API_KEY`、`OPENAI_API_KEY` |
| `reasonix-studio` | `reasonix-studio`、`reasonix studio` | `~/.reasonix/config.toml`、`~/.config/Reasonix Studio/` | `REASONIX_API_KEY` |

匹配规则：comm 或 cmdline **小写包含**任一特征即命中；配置文件按 `~` 与进程 cwd 展开后检查存在性。

## 3. 厂商 / 模型版本推断

模型版本优先级：

1. **配置文件** `model` / `model_name` / `default_model` 字段（JSON 或简单 YAML）
2. **环境变量** `*_MODEL`（`ANTHROPIC_MODEL`、`OPENAI_MODEL`、`DEEPSEEK_MODEL`…）
3. **命令行** `--model` / `-m` / `--model=xxx`

厂商优先级（`InferProvider`）：

1. **配置文件** `provider` / `api_provider` 字段
2. **模型名前缀**：`claude`→anthropic、`gpt`/`o1`/`o3`→openai、`deepseek`→deepseek、`gemini`→google、`qwen`→alibaba、`glm`→zhipu、`llama`→meta…
3. **API key 环境变量名**：`ANTHROPIC_API_KEY`→anthropic、`OPENAI_API_KEY`→openai、`DEEPSEEK_API_KEY`→deepseek…
4. **运行时 API 域名**（eBPF SNI/DNS）：`api.anthropic.com`、`api.openai.com`、`api.deepseek.com`、`generativelanguage.googleapis.com`…
5. **Harness 兜底**：`claude-code`→anthropic、`codex`→openai、`windsurf`→codeium

## 4. 数据结构（AgentSession）

```json
[
  {
    "pid": 12345,
    "comm": "claude",
    "cmdline": ["claude", "--model", "claude-sonnet-4"],
    "cwd": "/home/user/project",
    "uid": 1000,
    "start_ticks": 1234567,
    "harness": "claude-code",
    "config_files": ["/home/user/.claude/settings.json"],
    "env_keys": ["ANTHROPIC_API_KEY"],
    "provider": "anthropic",
    "model": "claude-sonnet-4",
    "source": "proc-scan"
  }
]
```

相关结构：`AgentSession`（agent 会话）、`ProcInfo`（/proc 富化结果）。

## 5. 安全约束

- **API key 只记名字，不记值**：`EnvKeys` 只保存命中的变量名（`ANTHROPIC_API_KEY`），值绝不落盘
- **模型名与端点可采集**：`ANTHROPIC_MODEL`、`*_BASE_URL` 属于非敏感配置
- **配置文件只读不写**：仅 `os.Stat` 判断存在性、`os.ReadFile` 读取 model/provider 字段

## 6. 包结构（`internal/fingerprint`）

| 文件 | 职责 |
|---|---|
| `schema.go` | `AgentSession` 结构 |
| `proc.go` | `/proc/<pid>` 富化：stat/cmdline/exe/cwd/status/cgroup/ns/environ/fd/maps |
| `agent.go` | Agent/Harness 白名单识别（comm/cmdline/config/env） |
| `config.go` | 配置文件 model/provider 解析（JSON + 简单 YAML） |
| `provider.go` | 厂商推断（域名/模型前缀/环境变量/Harness）与模型提取（cmdline/env） |
| `collector.go` | 编排：扫描 `/proc` → 识别 → 推断 → JSON 输出 |

## 7. CLI

```bash
adr fingerprint                        # 默认 30 秒间隔，输出 JSON
ADR_FP_INTERVAL=10s adr fingerprint    # 自定义间隔，Ctrl+C 退出
```

## 8. 与 eBPF 层的衔接

- **进程层**：`execve` 事件（`internal/egress`）实时给出 comm/argv/envp，可与 `/proc` 扫描互相补充
- **网络层**：`SNI`/`DNS` 事件给出 Agent 实际访问的 API 域名，作为厂商推断的第 4 优先级
- **文件层**：`openat` 事件可观测 Agent 读取的配置文件（阶段 A 已实现）

离线扫描（`adr fingerprint`）不依赖 eBPF 运行；`APIHosts` 字段留待与运行中的 agent 事件流关联后填充。

## 9. 已知限制

- 只覆盖**已知 Agent 白名单**（8 个），未知产品需要追加 `agentSignatures`
- 模型版本依赖配置文件/环境变量/cmdline；若 Agent 在运行时动态选模型（如 Cursor 的 UI 选择），离线扫描可能拿不到
- **不做 TLS 解密**（不引入 MITM）：请求体里的精确 `model` 字段不可见，只能靠上述间接线索
- 配置文件格式只支持 JSON 与「简单 YAML 行解析」，复杂嵌套 YAML 可能漏读
- 容器内 Agent 需要 `/proc` 可见（宿主机扫描容器进程需额外 namespace 处理）

## 10. 后续方向

- 扩充 Agent 白名单与配置文件格式（TOML、复杂 YAML）
- 与 eBPF SNI/DNS 事件流联动，填充 `APIHosts`
- 资产清单落库（CycloneDX ML-BOM 风格）并对接 SIEM/SOAR
