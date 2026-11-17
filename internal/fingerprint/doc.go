// Package fingerprint 提供端点侧 AI Agent/Harness 识别：判断主机上跑着哪些 AI Agent
// （Claude Code、Cursor、Codex、Cline、Aider 等），并结合配置文件、环境变量与命令行
// 推断其使用的模型厂商与版本。
//
// 运行时厂商确认可结合 eBPF 的 SNI/DNS 事件（如 api.anthropic.com → Anthropic），
// 由 internal/egress 提供。
package fingerprint
