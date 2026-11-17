# 指纹检测（端点 AI 资产发现）设计

- **版本**：v0.2.0
- **日期**：2026-11-17
- **角色**：Zakura-Lee

端点侧 AI 资产发现：识别主机上运行的推理框架、加载的模型文件、暴露的推理端口，为规则引擎与 AI 审计提供资产清单。

## 1. 定位

「指纹」指**端点侧 AI 资产发现**（不是模型水印/所有权指纹）：

- 判断这台机器上跑没跑大模型、哪个框架、加载了哪个模型文件
- 五层模型：进程 / 文件 / 网络 / 运行时 / 行为
- 与 ADR 现有 eBPF 采集、taint、规则引擎复用同一条事件管线

## 2. 五层模型与实现状态

| 层 | 判断依据 | 当前实现 |
|---|---|---|
| 进程层 | comm / argv / envp | ✅ eBPF `trace_execve`（已有） |
| 文件层 | 模型文件魔数 + 元数据 | ✅ eBPF `trace_openat`（阶段 A）+ 用户态扫描（阶段 B） |
| 网络层 | 监听端口 + HTTP 探测 | ✅ eBPF `bind`/`listen`/`connect`（阶段 A）+ 用户态 `ss`/HTTP（阶段 B） |
| 运行时层 | DSO / GPU | ✅ eBPF `mmap`（阶段 A）+ 用户态 `/proc/maps`/GPU（阶段 B） |
| 行为层 | execve / openat / mmap | ✅ 阶段 A |

## 3. 阶段 A：eBPF 采集 hook（已完成）

### 3.1 hook 矩阵

| hook | 事件 | 过滤策略 | 记录字段 |
|---|---|---|---|
| `trace_openat` | FILE | tainted 全量 + 非 tainted 仅模型扩展名（`.gguf`/`.safetensors`/`.onnx`/`.sft`/`.pth`/`.pt`/`.h5`） | path / dirfd / flags |
| `trace_mmap` | FILE | `PROT_EXEC` + tainted | fd / prot / len |
| `trace_connect` | NET | 仅 tainted | family / port / addr / fd |
| `trace_bind` | NET | 全量（量极小） | family / port / fd |
| `trace_listen` | NET | 全量 | fd |

### 3.2 过滤设计（事件量控制）

`openat` 是全系统最高频钩子，必须过滤：

- **tainted 进程**：全量上报（AI 进程的文件访问）
- **非 tainted 进程**：只报模型扩展名（避免淹没 ring buffer）

其余 hook：

- `mmap`：只报 `PROT_EXEC`（可执行映射 = DSO/二进制）+ tainted
- `connect`：只报 tainted（AI 进程的外联）
- `bind` / `listen`：全量（事件量极小）

### 3.3 协议扩展

FILE 事件（`ADR_EVENT_FILE=7`）：

```c
struct adr_file_payload {
	__u32 op;                 // 0=open, 1=mmap
	__u32 dirfd;              // AT_FDCWD=-100
	__u32 flags;              // openat flags / mmap prot
	__u32 fd;                 // mmap 的 fd
	__u32 len;                // mmap 长度
	char  path[256];
};
```

NET 事件（`ADR_EVENT_NET=8`）：

```c
struct adr_net_payload {
	__u32 op;       // 0=connect, 1=bind, 2=listen
	__u32 family;   // AF_INET / AF_INET6
	__u32 port;     // 主机字节序
	__u32 fd;
	__u8  addr[16]; // IPv4 用前 4 字节
};
```

### 3.4 实现要点

- `is_model_ext` 用**直接比较末尾字节**，不用 `#pragma unroll` 循环（循环展开在 eBPF 侧不完整，见 Problem.md 问题 24）
- `read_sockaddr` 兼容 `AF_INET` / `AF_INET6`
- `report_file` / `report_net` 统一上报
- `is_tainted_current` 复用 `(tgid, start_boottime)` 键，与现有 taint 机制一致

### 3.5 验证结果（宿主机实测）

| hook | 验证输出 |
|---|---|
| openat | `file op=open path=/tmp/test.gguf dirfd=4294967196 flags=0x0` |
| mmap | `file op=mmap flags=0x7 fd=4294967295 len=4096` |
| connect | `net op=connect port=443 addr=104.20.23.154`（IPv4）+ `addr=2606:4700:10::6814:179a`（IPv6） |
| bind | `net op=bind port=8000` |
| listen | `net op=listen` |

## 4. 阶段 B：用户态富化（已实现）

包结构（`internal/fingerprint`）：

| 文件 | 职责 |
|---|---|
| `schema.go` | CycloneDX ML-BOM 对齐的 `Asset` / `ModelFile` / `PortInfo` / `GPUInfo` |
| `proc.go` | `/proc/<pid>` enrichment：stat/cmdline/exe/cwd/status/cgroup/ns/environ（白名单）/fd/maps |
| `file.go` | 模型文件指纹：魔数（GGUF/HDF5/PyTorch ZIP/pickle/safetensors/ONNX）+ GGUF/safetensors 元数据 + 采样哈希 |
| `port.go` | 监听端口（`/proc/net/tcp`/`tcp6`）+ HTTP 探测（`/api/tags`、`/v1/models`、`/health`） |
| `gpu.go` | GPU 占用（`nvidia-smi --query-compute-apps`） |
| `collector.go` | 编排：`/proc` 扫描 + AI 进程识别 + 文件/端口/GPU 关联 + JSON 输出 |

CLI：

```bash
adr fingerprint                        # 默认 30 秒间隔，输出 JSON
ADR_FP_INTERVAL=10s adr fingerprint    # 自定义间隔，Ctrl+C 退出
```

关键实现：

- **environ 白名单**：只采集 `HF_HOME`/`OLLAMA_MODELS`/`CUDA_VISIBLE_DEVICES`/`TRANSFORMERS_CACHE` 等 AI 相关变量，避免泄露密钥
- **采样哈希**：头 1MB + 尾 1MB + size，大模型不全文读取
- **AI 进程识别**：comm/cmdline 匹配 ollama/llama-server/vllm/sglang/tgi/triton 等推理栈
- **GPU 关联**：按 pid 关联 `nvidia-smi` 的显存占用
- **端口探测**：`/proc/net/tcp` 的 `st=0A` 即 LISTEN，再对 127.0.0.1 发 HTTP 探测

## 5. Schema

- **CycloneDX ML-BOM** 字段（模型名/版本/格式/哈希/许可证）
- 关联键：`pid + start_boottime`（复用 taint key）

## 6. 已知限制

- `openat` 的 `path` 可能是相对路径（`dirfd` 非 `AT_FDCWD`），完整路径由阶段 B 的 `/proc/<pid>/cwd` + `/proc/<pid>/fd/<dirfd>` 补全
- `mmap` 的 `path` 为空，由阶段 B 的 `/proc/<pid>/maps` 补全
- `mmap` 的 `fd` 常为 `-1`（匿名映射），路径信息依赖阶段 B
- `connect` 只报 tainted 进程，需要先标记 agent 进程（`ADR_AGENT_WHITELIST`）
- 模型扩展名匹配基于文件名后缀，会漏掉非常规扩展名（阶段 B 的文件扫描补）

## 7. 开源项目借鉴

| 项目 | 借鉴内容 |
|---|---|
| Tetragon（Go + cilium/ebpf） | eBPF hook 设计、运行时 enrichment 字段 |
| modelscan | 模型格式清单（魔数） |
| gguf-py / safetensors | GGUF/safetensors 头解析规范 |
| CycloneDX ML-BOM | 资产 schema 字段 |
