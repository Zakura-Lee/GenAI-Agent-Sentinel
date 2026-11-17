package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsAIProcess 验证推理进程识别（comm / cmdline 特征）。
func TestIsAIProcess(t *testing.T) {
	cases := []struct {
		name string
		info *ProcInfo
		want bool
	}{
		{"ollama-comm", &ProcInfo{Comm: "ollama"}, true},
		{"llama-server-comm", &ProcInfo{Comm: "llama-server"}, true},
		{"vllm-cmdline", &ProcInfo{Comm: "python3", Cmdline: []string{"python3", "-m", "vllm.entrypoints.openai.api_server"}}, true},
		{"bash", &ProcInfo{Comm: "bash", Cmdline: []string{"bash", "-c", "ls"}}, false},
		{"nginx", &ProcInfo{Comm: "nginx", Cmdline: []string{"nginx", "-g", "daemon off;"}}, false},
	}
	for _, c := range cases {
		if got := isAIProcess(c.info); got != c.want {
			t.Errorf("%s: isAIProcess = %v，期望 %v", c.name, got, c.want)
		}
	}
}

// TestFilterAIDSOS 验证只保留 AI 相关共享库。
func TestFilterAIDSOS(t *testing.T) {
	dsos := []string{
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libcuda.so.1",
		"/usr/lib/x86_64-linux-gnu/libtorch_cpu.so",
		"/usr/lib/x86_64-linux-gnu/libz.so.1",
	}
	got := filterAIDSOS(dsos)
	if len(got) != 2 {
		t.Fatalf("AI DSO 数 = %d，期望 2: %v", len(got), got)
	}
}

// TestModelFilesFromFDs 验证从 fd 中提取模型文件。
func TestModelFilesFromFDs(t *testing.T) {
	dir := t.TempDir()
	gguf := filepath.Join(dir, "m.gguf")
	buf := make([]byte, 24)
	copy(buf[0:4], "GGUF")
	if err := os.WriteFile(gguf, buf, 0o600); err != nil {
		t.Fatal(err)
	}

	fds := []string{gguf, "/dev/null", "/usr/lib/libc.so.6", gguf}
	files := modelFilesFromFDs(fds)
	if len(files) != 1 {
		t.Fatalf("模型文件数 = %d，期望 1（去重后）: %v", len(files), files)
	}
	if files[0].Format != "gguf" {
		t.Fatalf("Format = %q，期望 gguf", files[0].Format)
	}
}
