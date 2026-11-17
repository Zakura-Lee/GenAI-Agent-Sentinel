package egress

import (
	"os"
	"testing"
)

// TestReadStartTicks 验证读取自身进程 starttime 非 0。
func TestReadStartTicks(t *testing.T) {
	ticks, err := ReadStartTicks(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("ReadStartTicks 失败: %v", err)
	}
	if ticks == 0 {
		t.Fatal("starttime 为 0，解析可能失败")
	}
}
