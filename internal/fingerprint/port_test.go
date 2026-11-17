package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseProcNet 验证 /proc/net/tcp 监听端口解析（只取 st=0A）。
func TestParseProcNet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F91 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	ports := parseProcNet(path, "tcp")
	if len(ports) != 2 {
		t.Fatalf("监听端口数 = %d，期望 2: %v", len(ports), ports)
	}
	if ports[0].Port != 8080 {
		t.Errorf("ports[0].Port = %d，期望 8080", ports[0].Port)
	}
	if ports[0].Addr != "127.0.0.1" {
		t.Errorf("ports[0].Addr = %q，期望 127.0.0.1", ports[0].Addr)
	}
	if ports[1].Port != 22 || ports[1].Addr != "0.0.0.0" {
		t.Errorf("ports[1] = %+v，期望 0.0.0.0:22", ports[1])
	}
}

// TestHexToBytes 验证十六进制地址转换（小端 4 字节组）。
func TestHexToBytes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
		{"00000000000000000000000000000000", "::"},
	}
	for _, c := range cases {
		b, err := hexToBytes(c.in)
		if err != nil {
			t.Fatalf("hexToBytes(%q) 失败: %v", c.in, err)
		}
		if got := parseHexAddr(c.in); got != c.want {
			t.Errorf("parseHexAddr(%q) = %q，期望 %q（bytes=%v）", c.in, got, c.want, b)
		}
	}
}
