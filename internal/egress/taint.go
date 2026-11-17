package egress

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadStartTicks 读取进程的 starttime（/proc/<pid>/stat 第 22 字段，boottime tick 数）。
// 与 eBPF 侧 get_start_ticks（group_leader->start_boottime / NSEC_PER_TICK）对齐。
func ReadStartTicks(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("读取 /proc/%d/stat: %w", pid, err)
	}

	// comm 可能含空格，定位最后一个 ')' 后按空白切分
	s := string(data)
	idx := strings.LastIndexByte(s, ')')
	if idx < 0 {
		return 0, fmt.Errorf("/proc/%d/stat 格式异常", pid)
	}
	fields := strings.Fields(s[idx+1:])
	// ')' 后字段：state(0) ppid(1) ... itrealvalue(18) starttime(19)
	if len(fields) < 20 {
		return 0, fmt.Errorf("/proc/%d/stat 字段不足", pid)
	}

	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("解析 starttime: %w", err)
	}
	return ticks, nil
}
