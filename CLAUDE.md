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
- 提交信息用约定式提交（`feat:` / `fix:` / `docs:` / `refactor:` / `chore:`）。
- 多人协作：合并前跑 `make test` 与 `make build`；PR 用 `/code-review` 自检。
