package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// aiSignature 为推理栈的进程名/命令行特征（小写匹配）。
var aiSignature = []string{
	"ollama", "llama-server", "llama.cpp", "vllm", "sglang",
	"text-generation-inference", "triton", "localai", "koboldcpp",
	"lmstudio", "gpt4all", "xinference", "fastchat",
	"transformers", "torch", "tensorrt", "onnxruntime",
}

// aiDSOKeywords 为 AI 运行时相关的共享库关键词（小写匹配）。
var aiDSOKeywords = []string{
	"libcuda", "libcudart", "libtorch", "libggml",
	"libnccl", "libhip", "librocm", "libopenvino",
}

// Collector 编排 /proc 扫描、文件指纹、端口探测与 GPU 关联。
type Collector struct {
	Interval   time.Duration
	ModelDirs  []string
	ProbePorts bool
}

// NewCollector 创建默认采集器（30 秒间隔、探测端口）。
func NewCollector() *Collector {
	return &Collector{
		Interval:   30 * time.Second,
		ModelDirs:  ModelDirs,
		ProbePorts: true,
	}
}

// Scan 执行一次全量扫描，返回资产清单。
func (c *Collector) Scan() ([]Asset, error) {
	assets := make([]Asset, 0, 16)

	gpuProcs, _ := ListGPUProcesses()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("扫描 /proc: %w", err)
	}
	for _, e := range entries {
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		info, err := ReadProc(uint32(pid64))
		if err != nil || !isAIProcess(info) {
			continue
		}

		asset := Asset{
			Pid:        info.Pid,
			Ppid:       info.Ppid,
			Comm:       info.Comm,
			Exe:        info.Exe,
			Cmdline:    info.Cmdline,
			Cwd:        info.Cwd,
			UID:        info.UID,
			GID:        info.GID,
			StartTicks: info.StartTicks,
			Cgroup:     info.Cgroup,
			NsInodes:   info.NsInodes,
			Env:        info.Environ,
			DSOs:       filterAIDSOS(info.DSOs),
			ModelFiles: modelFilesFromFDs(info.FDs),
			Source:     "proc-scan",
		}
		if g, ok := gpuProcs[info.Pid]; ok {
			asset.GPU = g
		}
		assets = append(assets, asset)
	}

	if len(c.ModelDirs) > 0 {
		if files, err := ScanModelDirs(c.ModelDirs); err == nil {
			for i := range files {
				assets = append(assets, Asset{
					ModelFiles: []ModelFile{files[i]},
					Source:     "file-scan",
				})
			}
		}
	}

	// 监听端口：只列入 HTTP 探测成功的 AI 推理服务，避免 SSH/DNS/Redis 等噪音
	for _, p := range ListenPorts() {
		probed, err := ProbePort(p.Port)
		if err != nil {
			continue
		}
		p.Service = probed.Service
		p.Models = probed.Models
		assets = append(assets, Asset{
			ListenPorts: []PortInfo{p},
			Source:      "port-scan",
		})
	}

	return assets, nil
}

// Run 定时扫描并按 JSON 输出，直到 ctx 取消。
func (c *Collector) Run(ctx context.Context, out io.Writer) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	for {
		assets, err := c.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "指纹扫描失败: %v\n", err)
		} else if err := enc.Encode(assets); err != nil {
			return fmt.Errorf("编码资产清单: %w", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.Interval):
		}
	}
}

// isAIProcess 判断进程是否为推理服务（comm/cmdline 特征匹配）。
func isAIProcess(info *ProcInfo) bool {
	comm := strings.ToLower(info.Comm)
	for _, s := range aiSignature {
		if strings.Contains(comm, s) {
			return true
		}
	}
	for _, arg := range info.Cmdline {
		a := strings.ToLower(arg)
		for _, s := range aiSignature {
			if strings.Contains(a, s) {
				return true
			}
		}
	}
	return false
}

// filterAIDSOS 只保留 AI 运行时相关的共享库。
func filterAIDSOS(dsos []string) []string {
	var out []string
	for _, d := range dsos {
		low := strings.ToLower(d)
		for _, k := range aiDSOKeywords {
			if strings.Contains(low, k) {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// modelFilesFromFDs 从进程打开的 fd 中提取模型文件指纹。
func modelFilesFromFDs(fds []string) []ModelFile {
	seen := map[string]bool{}
	var out []ModelFile
	for _, fd := range fds {
		if !modelExts[strings.ToLower(filepath.Ext(fd))] || seen[fd] {
			continue
		}
		seen[fd] = true
		if mf, err := ScanModelFile(fd); err == nil {
			out = append(out, *mf)
		}
	}
	return out
}
