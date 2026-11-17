package fingerprint

import (
	"os"
	"strings"
	"testing"
)

// TestReadProcSelf 验证能读取自身进程的 /proc 信息。
func TestReadProcSelf(t *testing.T) {
	info, err := ReadProc(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("ReadProc 失败: %v", err)
	}
	if info.Pid != uint32(os.Getpid()) {
		t.Fatalf("Pid = %d，期望 %d", info.Pid, os.Getpid())
	}
	if info.Comm == "" {
		t.Fatal("Comm 为空")
	}
	if len(info.Cmdline) == 0 {
		t.Fatal("Cmdline 为空")
	}
	if info.StartTicks == 0 {
		t.Fatal("StartTicks 为 0")
	}
}

// TestParseProcStat 验证 stat 解析（含 comm 带空格/括号的边界）。
func TestParseProcStat(t *testing.T) {
	// 真实格式：pid (comm) state ppid ... starttime 在第 22 字段
	stat := "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 1 0 98765 1000000 100 18446744073709551615"
	info := &ProcInfo{}
	if err := parseProcStat(stat, info); err != nil {
		t.Fatalf("parseProcStat 失败: %v", err)
	}
	if info.Comm != "my (weird) proc" {
		t.Fatalf("Comm = %q", info.Comm)
	}
	if info.Ppid != 1 {
		t.Fatalf("Ppid = %d，期望 1", info.Ppid)
	}
	if info.StartTicks != 98765 {
		t.Fatalf("StartTicks = %d，期望 98765", info.StartTicks)
	}
}

// TestReadAllowlistedEnv 验证 environ 只保留白名单变量。
func TestReadAllowlistedEnv(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/environ"
	data := strings.Join([]string{
		"HF_HOME=/home/u/.cache/huggingface",
		"OLLAMA_MODELS=/home/u/.ollama/models",
		"SECRET_KEY=should-not-leak",
		"PATH=/usr/bin",
	}, "\x00")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	env := readAllowlistedEnv(path)
	if env["HF_HOME"] != "/home/u/.cache/huggingface" {
		t.Fatalf("HF_HOME = %q", env["HF_HOME"])
	}
	if _, ok := env["SECRET_KEY"]; ok {
		t.Fatal("SECRET_KEY 不应被采集")
	}
	if _, ok := env["PATH"]; ok {
		t.Fatal("PATH 不在白名单，不应被采集")
	}
}

// TestReadDSOs 验证从 maps 提取 .so 路径。
func TestReadDSOs(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/maps"
	maps := strings.Join([]string{
		"7f0000000000-7f0000100000 r-xp 00000000 08:01 123 /usr/lib/x86_64-linux-gnu/libc.so.6",
		"7f0000100000-7f0000200000 r-xp 00000000 08:01 124 /usr/lib/x86_64-linux-gnu/libcuda.so.1",
		"7f0000200000-7f0000300000 rw-p 00000000 00:00 0",
		"7f0000300000-7f0000400000 r-xp 00000000 08:01 125 /usr/bin/somebin",
	}, "\n")
	if err := os.WriteFile(path, []byte(maps), 0o600); err != nil {
		t.Fatal(err)
	}

	dsos := readDSOs(path)
	if len(dsos) != 2 {
		t.Fatalf("DSO 数 = %d，期望 2: %v", len(dsos), dsos)
	}
}
