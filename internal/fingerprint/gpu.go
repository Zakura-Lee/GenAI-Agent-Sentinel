package fingerprint

import (
	"os/exec"
	"strconv"
	"strings"
)

// ListGPUProcesses 查询 GPU 计算进程占用（需要 nvidia-smi）。
func ListGPUProcesses() (map[uint32]*GPUInfo, error) {
	out, err := exec.Command("nvidia-smi",
		"--query-compute-apps=pid,used_memory",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		return nil, err
	}

	res := map[uint32]*GPUInfo{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 32)
		if err != nil {
			continue
		}
		mem, _ := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
		res[uint32(pid)] = &GPUInfo{Device: "nvidia", UsedMemory: mem}
	}
	return res, nil
}
