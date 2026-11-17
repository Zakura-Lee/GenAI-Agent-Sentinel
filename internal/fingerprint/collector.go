package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

// Collector 扫描 /proc 识别 AI Agent/Harness，并推断厂商与模型。
type Collector struct {
	Interval time.Duration
}

// NewCollector 创建默认采集器（30 秒间隔）。
func NewCollector() *Collector {
	return &Collector{Interval: 30 * time.Second}
}

// Scan 执行一次扫描，返回 Agent 会话清单。
func (c *Collector) Scan() ([]AgentSession, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("扫描 /proc: %w", err)
	}

	var sessions []AgentSession
	for _, e := range entries {
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		info, err := ReadProc(uint32(pid64))
		if err != nil {
			continue
		}
		harness, configs, envKeys := IdentifyAgent(info)
		if harness == "" {
			continue
		}

		// 模型推断：配置文件 > 环境变量 > 命令行
		model, configProvider := ModelFromConfig(configs)
		if model == "" {
			model = ModelFromEnv(info.Environ)
		}
		if model == "" {
			model = ModelFromCmdline(info.Cmdline)
		}
		provider := InferProvider(harness, configProvider, model, envKeys, nil)

		sessions = append(sessions, AgentSession{
			Pid:         info.Pid,
			Ppid:        info.Ppid,
			Comm:        info.Comm,
			Exe:         info.Exe,
			Cmdline:     info.Cmdline,
			Cwd:         info.Cwd,
			UID:         info.UID,
			GID:         info.GID,
			StartTicks:  info.StartTicks,
			Cgroup:      info.Cgroup,
			NsInodes:    info.NsInodes,
			Harness:     harness,
			ConfigFiles: configs,
			EnvKeys:     envKeys,
			Provider:    provider,
			Model:       model,
			Source:      "proc-scan",
		})
	}
	return sessions, nil
}

// Run 定时扫描并按 JSON 输出，直到 ctx 取消。
func (c *Collector) Run(ctx context.Context, out io.Writer) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	for {
		sessions, err := c.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Agent 扫描失败: %v\n", err)
		} else if err := enc.Encode(sessions); err != nil {
			return fmt.Errorf("编码 Agent 会话: %w", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.Interval):
		}
	}
}
