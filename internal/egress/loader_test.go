package egress

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestParseExecEvent 验证 EXEC 事件（头 + payload）能正确解析。
func TestParseExecEvent(t *testing.T) {
	raw := make([]byte, AdrEventHeaderSize+execPayloadSize)
	binary.LittleEndian.PutUint64(raw[0:8], 123456789) // ts_ns
	binary.LittleEndian.PutUint32(raw[8:12], EventTypeExec)
	binary.LittleEndian.PutUint32(raw[12:16], 100) // pid
	binary.LittleEndian.PutUint32(raw[16:20], 1)   // ppid
	binary.LittleEndian.PutUint32(raw[20:24], 1000)
	binary.LittleEndian.PutUint32(raw[24:28], 1000)
	// payload 起始于 64
	copy(raw[64:80], "bash")
	copy(raw[80:336], "ls -la")
	copy(raw[336:], "PATH=/usr/bin")

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent 失败: %v", err)
	}
	if e.Header.Type != EventTypeExec || e.Header.Pid != 100 || e.Exec == nil {
		t.Fatalf("EXEC 事件解析错误: %+v", e.Header)
	}
	if got := string(bytes.TrimRight(e.Exec.Argv[:], "\x00")); got != "ls -la" {
		t.Fatalf("argv = %q，期望 ls -la", got)
	}
	if got := string(bytes.TrimRight(e.Exec.Envp[:], "\x00")); got != "PATH=/usr/bin" {
		t.Fatalf("envp = %q，期望 PATH=/usr/bin", got)
	}
}

// TestParsePipeEvent 验证 PIPE 事件（头 + payload）能正确解析，含方向与 inode。
func TestParsePipeEvent(t *testing.T) {
	raw := make([]byte, AdrEventHeaderSize+pipePayloadSize)
	binary.LittleEndian.PutUint32(raw[8:12], EventTypePipe)
	binary.LittleEndian.PutUint32(raw[12:16], 200) // pid
	// payload 起始于 64
	binary.LittleEndian.PutUint64(raw[64:72], 0xdeadbeef) // ino
	binary.LittleEndian.PutUint32(raw[72:76], 5)          // len
	binary.LittleEndian.PutUint32(raw[76:80], 1)          // dir=写
	copy(raw[80:85], "hello")

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent 失败: %v", err)
	}
	if e.Header.Type != EventTypePipe || e.Pipe == nil {
		t.Fatalf("PIPE 事件解析错误: %+v", e.Header)
	}
	if e.Pipe.Ino != 0xdeadbeef || e.Pipe.Dir != 1 || e.Pipe.Len != 5 {
		t.Fatalf("PIPE payload 错误: %+v", e.Pipe)
	}
	if got := string(e.Pipe.Data[:e.Pipe.Len]); got != "hello" {
		t.Fatalf("pipe data = %q，期望 hello", got)
	}
}

// TestParseEventTooShort 验证过短事件返回错误。
func TestParseEventTooShort(t *testing.T) {
	if _, err := parseEvent(make([]byte, AdrEventHeaderSize-1)); err == nil {
		t.Fatal("期望过短事件返回错误")
	}
}
