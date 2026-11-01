package egress

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestParseEvent 验证 ring buffer 原始字节能被正确解析为 ExecveEvent。
func TestParseEvent(t *testing.T) {
	raw := make([]byte, ExecveEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], 1234)   // pid
	binary.LittleEndian.PutUint32(raw[4:8], 5678)   // ppid
	binary.LittleEndian.PutUint32(raw[8:12], 1000)  // uid
	binary.LittleEndian.PutUint32(raw[12:16], 1000) // gid
	copy(raw[16:32], "bash")                        // comm
	copy(raw[32:288], "ls -la")                     // argv
	copy(raw[288:], "PATH=/usr/bin")                // envp

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent 失败: %v", err)
	}
	if e.Pid != 1234 || e.Ppid != 5678 || e.Uid != 1000 || e.Gid != 1000 {
		t.Fatalf("字段解析错误: %+v", e)
	}
	if got := string(bytes.TrimRight(e.Comm[:], "\x00")); got != "bash" {
		t.Fatalf("comm = %q，期望 bash", got)
	}
	if got := string(bytes.TrimRight(e.Argv[:], "\x00")); got != "ls -la" {
		t.Fatalf("argv = %q，期望 ls -la", got)
	}
	if got := string(bytes.TrimRight(e.Envp[:], "\x00")); got != "PATH=/usr/bin" {
		t.Fatalf("envp = %q，期望 PATH=/usr/bin", got)
	}
}

// TestParseEventTooShort 验证过短事件返回错误。
func TestParseEventTooShort(t *testing.T) {
	if _, err := parseEvent(make([]byte, ExecveEventSize-1)); err == nil {
		t.Fatal("期望过短事件返回错误")
	}
}
