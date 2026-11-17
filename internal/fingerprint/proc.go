package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// envAllowlist 为 AI 相关环境变量白名单（只采集这些，避免泄露密钥）。
var envAllowlist = []string{
	"HF_HOME", "OLLAMA_MODELS", "CUDA_VISIBLE_DEVICES", "TRANSFORMERS_CACHE",
	"HF_HUB_CACHE", "VLLM_CACHE_ROOT", "TORCH_HOME",
}

// errnoStatFields 是 /proc/<pid>/stat 在 ')' 之后的最小字段数（starttime 在索引 19）。
const errnoStatFields = 20

// ProcInfo 为 /proc/<pid> 的采集结果。
type ProcInfo struct {
	Pid        uint32            `json:"pid"`
	Ppid       uint32            `json:"ppid"`
	Comm       string            `json:"comm"`
	Exe        string            `json:"exe,omitempty"`
	Cmdline    []string          `json:"cmdline,omitempty"`
	Cwd        string            `json:"cwd,omitempty"`
	UID        uint32            `json:"uid"`
	GID        uint32            `json:"gid"`
	StartTicks uint64            `json:"start_ticks"`
	Cgroup     string            `json:"cgroup,omitempty"`
	NsInodes   map[string]string `json:"ns_inodes,omitempty"`
	Environ    map[string]string `json:"environ,omitempty"`
	FDs        []string          `json:"fds,omitempty"`
	DSOs       []string          `json:"dsos,omitempty"`
}

// ReadProc 采集指定进程的 /proc 信息；进程已退出时返回错误。
func ReadProc(pid uint32) (*ProcInfo, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	info := &ProcInfo{Pid: pid}

	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return nil, fmt.Errorf("读取 %s/stat: %w", base, err)
	}
	if err := parseProcStat(string(stat), info); err != nil {
		return nil, fmt.Errorf("%s/stat: %w", base, err)
	}

	// cmdline（\0 分隔）
	if data, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		for _, arg := range strings.Split(string(data), "\x00") {
			if arg != "" {
				info.Cmdline = append(info.Cmdline, arg)
			}
		}
	}

	info.Exe, _ = os.Readlink(filepath.Join(base, "exe"))
	info.Cwd, _ = os.Readlink(filepath.Join(base, "cwd"))

	if data, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		parseProcStatus(string(data), info)
	}

	if data, err := os.ReadFile(filepath.Join(base, "cgroup")); err == nil {
		if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) > 0 {
			info.Cgroup = lines[0]
		}
	}

	info.NsInodes = readNsInodes(filepath.Join(base, "ns"))
	info.Environ = readAllowlistedEnv(filepath.Join(base, "environ"))
	info.FDs = readFDs(filepath.Join(base, "fd"), 64)
	info.DSOs = readDSOs(filepath.Join(base, "maps"))

	return info, nil
}

// parseProcStat 解析 /proc/<pid>/stat 的 ppid/comm/starttime。
func parseProcStat(stat string, info *ProcInfo) error {
	// comm 可能含空格/括号，定位最后一个 ')' 后按空白切分
	idx := strings.LastIndexByte(stat, ')')
	if idx < 0 {
		return fmt.Errorf("格式异常（缺少 ')'）")
	}
	if l := strings.IndexByte(stat, '('); l >= 0 && l < idx {
		info.Comm = stat[l+1 : idx]
	}

	fields := strings.Fields(stat[idx+1:])
	if len(fields) < errnoStatFields {
		return fmt.Errorf("字段不足: %d", len(fields))
	}
	if v, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
		info.Ppid = uint32(v)
	}
	if v, err := strconv.ParseUint(fields[19], 10, 64); err == nil {
		info.StartTicks = v
	}
	return nil
}

// parseProcStatus 从 /proc/<pid>/status 解析 uid/gid。
func parseProcStatus(status string, info *ProcInfo) {
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			if v, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
				info.UID = uint32(v)
			}
		case "Gid:":
			if v, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
				info.GID = uint32(v)
			}
		}
	}
}

// readNsInodes 读取 namespace inode（symlink 目标）。
func readNsInodes(dir string) map[string]string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil {
			out[e.Name()] = target
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// readAllowlistedEnv 读取 environ 并只保留白名单变量。
func readAllowlistedEnv(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	allow := make(map[string]bool, len(envAllowlist))
	for _, k := range envAllowlist {
		allow[k] = true
	}
	out := map[string]string{}
	for _, kv := range strings.Split(string(data), "\x00") {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		if k := kv[:i]; allow[k] {
			out[k] = kv[i+1:]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// readFDs 读取打开的 fd 目标（最多 max 个）。
func readFDs(dir string, max int) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if len(out) >= max {
			break
		}
		if target, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil {
			out = append(out, target)
		}
	}
	return out
}

// readDSOs 从 /proc/<pid>/maps 提取共享库路径。
func readDSOs(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		i := strings.IndexByte(line, '/')
		if i < 0 {
			continue
		}
		p := line[i:]
		if !strings.Contains(p, ".so") || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
