# 前端

ADR 运营平台可视化控制台：设备实时监测、日志检索、工单处置与 AI 研判展示。

技术栈：**React + TypeScript + Vite**（与 `docs/PLAN.md` 选型一致）。

初始化：

```bash
npm create vite@latest . -- --template react-ts
```

构建产物 `dist/` 将由后端通过 `go:embed` 嵌入单可执行文件。
