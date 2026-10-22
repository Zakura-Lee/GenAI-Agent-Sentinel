# CLAUDE.md

本文件为 Claude Code 提供项目上下文，供多人协作时保持一致。

## 项目概述

ADR（GenAI Agent Detection & Response）：检测与响应 GenAI Agent 的行为。内核态用 eBPF 捕获行为事件，Go 规则引擎实时判定，大模型（Claude API）做事后审计，前端可视化，PostgreSQL（+pgvector）存储日志与知识库。

## 技术栈

- **内核态检测**：C + eBPF，使用 `libbpf` + CO-RE（`vmlinux.h` 由 bpftool 生成）
- **规则 agent / 审计**：Go 1.27
- **LLM 审计**：Claude API（Anthropic Go SDK）
- **前端**：Node 24 / Vite（框架待定）
- **数据库**：PostgreSQL 16 + pgvector 0.6；Redis 7 作事件队列

## 目录约定

- `ebpf/src/*.bpf.c` — eBPF 程序源文件
- `cmd/` — 各可执行服务入口（`agent`、`audit`）
- `internal/` — 不对外导出的共享包
- `db/migrations/` — 数据库迁移（当前用 `db/schema.sql` 起步）
- `frontend/` — 前端工程

## 常用命令

```bash
make build          # 构建 eBPF + Go
make build-ebpf     # 生成 vmlinux.h 并编译 .bpf.o
make run-agent      # 运行规则 agent
make run-audit      # 运行审计服务
make test           # 运行 Go 测试
```

## 约定与注意

- eBPF 程序需 `SEC("license") = "GPL"`，否则无法加载。
- `vmlinux.h`、`ebpf/build/` 由构建生成，已加入 `.gitignore`，勿提交。
- 密钥（`ANTHROPIC_API_KEY` 等）只放 `.env`，严禁提交到仓库。

## 编码风格

### 通用

- 缩进：Go 用 tab（以 `gofmt` 为准）；C/eBPF 用 tab，宽度 8；前端用 2 空格。
- 行尾不留空白字符，文件末尾保留一个换行符。
- 注释与提交信息统一使用中文（对外可读的标识符、日志、API 文档按需用英文）。

### Go

- 提交前必须通过 `gofmt`、`go vet`，并运行 `golangci-lint run`。
- 命名：导出标识符用驼峰、首字母大写；未导出的首字母小写；缩写词全大写（如 `ID`、`URL`、`HTTP`）。
- 错误处理：返回 `error` 而非 panic；向上传递时用 `fmt.Errorf("...: %w", err)` 保留上下文。
- 每个导出包、导出函数/类型写文档注释，以名称开头。
- 禁止忽略错误（`_ = err`）与裸 `panic`（仅用于不可恢复的初始化失败）。

### C / eBPF

- 遵循 Linux 内核编码风格（kernel coding style），函数与变量用 `snake_case`。
- 内核结构体访问用 CO-RE 辅助宏（`bpf_core_read*`），禁止直接解引用内核内存。
- 每个程序必须包含 `SEC("license") = "GPL"`。

### 前端

- TypeScript 优先；统一用 ESLint + Prettier 格式化。
- 2 空格缩进、单引号、语句末尾加分号。

## Git 约定

- `main` 为受保护分支，禁止直接 push；所有改动经 PR 合并。
- 分支命名：`feat/<描述>`、`fix/<描述>`、`refactor/<描述>`、`docs/<描述>`、`chore/<描述>`（描述用短横线连接，如 `feat/audit-batch-rule`）。
- 一个 PR 只解决一个主题，避免夹带无关改动。
- 合并方式统一 squash，保持 `main` 线性历史；不对共享分支 force-push。
- 合并前：本地跑 `make test` 与 `make build`；PR 用 `/code-review` 自检。

## Git Commit 规范

采用约定式提交（Conventional Commits），格式：

```
<type>(<scope>): <subject>
```

- **subject**：祈使句、小写开头、不超过 72 字符、结尾不加句号。
- **type**（必填）：`feat` / `fix` / `docs` / `refactor` / `perf` / `test` / `build` / `ci` / `chore` / `style`。
- **scope**（可选）：影响范围，如 `ebpf`、`agent`、`audit`、`frontend`、`db`。
- **body**（可选）：说明「为什么改」与影响面，与 subject 间空一行。
- **破坏性变更**：type 后加 `!`（如 `feat!:`），或 body 末尾加 `BREAKING CHANGE:` 说明。

示例：

```text
feat(ebpf): 捕获 execve 行为事件并上报
fix(audit): 修复规则引擎在空事件下的 panic
feat(agent)!: 调整事件上报协议，需同步升级 collector
```
