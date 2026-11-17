// Package fingerprint 提供端点侧 AI 资产发现：进程 enrichment、模型文件指纹、推理端口探测与 GPU 占用。
//
// 采集分五层（进程/文件/网络/运行时/行为），本包负责用户态富化，
// eBPF 行为层（openat/mmap/connect/bind/listen）由 internal/egress 提供。
package fingerprint
