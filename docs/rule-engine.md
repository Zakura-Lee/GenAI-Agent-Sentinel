# 本地规则引擎设计

- **版本**：v0.1.0
- **日期**：2026-11-17
- **角色**：Zakura-Lee

agent 内实时规则判定层：对 eBPF 事件做条件匹配，产出告警（verdict），并按规则识别 Agent 进程注入 taint。

## 1. 目标与范围

- **输入**：`internal/egress` 解析出的事件（EXEC / EXIT / FORK / PIPE / DNS / SNI）
- **输出**：命中列表（规则 + verdict + severity），agent 据此打印告警、注入 taint
- **规则来源**：YAML 文件，支持 fsnotify 热更新
- **不在本层**：网络重定向、LSM 强制拦截（后者由 eBPF 层 `taint_deny_open` 承担）

## 2. 规则模型

```yaml
rules:
  - id: suspicious-download-exec
    name: 可疑下载后执行
    event_type: exec          # exec / exit / fork / pipe / dns / sni
    conditions:               # AND 语义
      - field: argv
        op: contains
        value: curl
      - field: argv
        op: contains
        value: "| sh"
    verdict: alert            # allow / alert / block
    severity: high            # low / medium / high / critical
    agent_type: 1             # 可选：命中即把进程标记为 Agent（接管 taint 注入）
```

### 2.1 可匹配字段

| 事件 | 字段 |
|---|---|
| `exec` | `comm`、`argv`（空格拼接）、`envp`（空格拼接，agent 打印时脱敏） |
| `exit` | `exit_code`、`pid` |
| `fork` | `child_pid`、`pid` |
| `pipe` | `ino`、`data` |
| `dns` | `qname`（点分隔域名） |
| `sni` | `server_name` |

所有事件还带 `pid` / `ppid` / `uid` / `gid`。

### 2.2 操作符

| op | 语义 |
|---|---|
| `eq` | 完全相等 |
| `contains` | 包含子串 |
| `prefix` | 前缀匹配 |
| `suffix` | 后缀匹配 |

### 2.3 verdict 与 severity

- `verdict`：`allow`（放行）/ `alert`（告警）/ `block`（建议阻断，后续接 SOAR）
- `severity`：`low` / `medium` / `high` / `critical`

## 3. 判定流程

```text
eBPF 事件 → egress.parseEvent → rule.Engine.Evaluate
  ├─ 按 event_type 过滤规则
  ├─ extractFields 提取字段 map
  ├─ matchConditions（AND）逐条匹配
  └─ 返回 []Match{规则, verdict, severity}
```

- `Engine` 用 `sync.RWMutex` 保护规则集，`Replace` 原子替换（热更新）
- 规则校验：`id` 唯一、`event_type` 非空、`verdict` 合法、条件 `field/op` 非空

## 4. 热更新

- `rule.NewWatcher(path)` 加载规则并注册 fsnotify 监听
- 监听 `Write` / `Create` / `Rename`，变化后重新解析并 `Replace`
- 解析失败保留旧规则并打印错误（不影响正在运行的判定）

## 5. agent 集成

```text
runAgent
  ├─ egress.Load（加载 eBPF）
  ├─ rule.NewWatcher（ADR_RULES，默认 rules/default.yaml）+ go watcher.Run()
  ├─ markAgentByRules（扫描 /proc，用规则识别现有 Agent 并 MarkTaint）
  └─ 事件循环：Evaluate → 打印告警；agent_type 规则命中 → markTaintForEvent
```

- **agent 识别由规则引擎接管**：规则里 `agent_type: 1` 即表示「命中即标记为 Agent」，替代早期硬编码 comm 白名单
- 启动扫描构造仅含 `comm` 的虚拟 EXEC 事件，复用同一套规则

## 6. 默认规则集

`rules/default.yaml` 包含：

| 规则 | 事件 | 判定 | 说明 |
|---|---|---|---|
| `agent-claude` / `agent-codex` / `agent-cursor` | `exec` | allow + agent_type | Agent 识别 → taint 注入 |
| `suspicious-download-exec` | `exec` | alert/high | `curl` + `\| sh` 下载后执行 |
| `sensitive-file-access` | `exec` | alert/high | 访问 `.ssh/id_rsa` |
| `llm-egress-deepseek` | `sni` | allow/low | LLM 出口识别 |

## 7. 验收（[c2]）

- 构造可疑 execve（`curl ... | sh`）可触发 `告警 rule=suspicious-download-exec ...`
- 修改 `rules/default.yaml` 后无需重启，agent 输出 `规则已热更新: N 条`
- 单元测试：`go test ./internal/rule/ -v`（解析、匹配、agent 识别、热更新、event_type 过滤）

## 8. 已知限制

- `envp` 在规则层可匹配全量拼接串；agent 打印时已对敏感变量脱敏，但规则匹配仍可命中明文（规则作者需注意）
- 规则条件暂不支持正则与数值比较（如 `pid > 1000`）
- 规则命中 `block` 目前只打印，真正的强制拦截仍由 eBPF LSM 层承担
- 启动扫描只覆盖 agent 启动时已存在的进程；新启动进程依赖事件驱动的 `agent_type` 规则
