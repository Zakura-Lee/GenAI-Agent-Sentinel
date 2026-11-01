package egress

import (
	"testing"
	"unsafe"
)

// TestExecveEventSize 锁定 Go 侧事件结构与 eBPF 侧 struct execve_event 的字节布局一致。
func TestExecveEventSize(t *testing.T) {
	const want uintptr = 4*4 + 16 + 256 + 512
	if got := unsafe.Sizeof(ExecveEvent{}); got != want {
		t.Fatalf("ExecveEvent 大小 = %d，期望 %d（需与 eBPF 侧 struct execve_event 对齐）", got, want)
	}
	if ExecveEventSize != want {
		t.Fatalf("ExecveEventSize = %d，期望 %d", ExecveEventSize, want)
	}
}
