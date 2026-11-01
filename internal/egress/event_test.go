package egress

import (
	"testing"
	"unsafe"
)

// TestEventLayoutSize 锁定各结构与 C 侧字节布局一致。
func TestEventLayoutSize(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"AdrEventHeader", unsafe.Sizeof(AdrEventHeader{}), 64},
		{"AdrTaint", unsafe.Sizeof(AdrTaint{}), 32},
		{"ExecPayload", unsafe.Sizeof(ExecPayload{}), 16 + 256 + 512},
		{"PipePayload", unsafe.Sizeof(PipePayload{}), 8 + 4 + 4 + 128},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s 大小 = %d，期望 %d（需与 C 侧对齐）", c.name, c.got, c.want)
		}
	}
}
