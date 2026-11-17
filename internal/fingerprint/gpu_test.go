package fingerprint

import (
	"os/exec"
	"testing"
)

// TestListGPUProcesses 验证 GPU 查询（nvidia-smi 不可用时跳过）。
func TestListGPUProcesses(t *testing.T) {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		t.Skip("nvidia-smi 不可用，跳过")
	}
	if _, err := ListGPUProcesses(); err != nil {
		t.Fatalf("ListGPUProcesses 失败: %v", err)
	}
}
