package egress

import (
	"bytes"
	"strings"
)

// CStr 将定长字节数组转为 C 字符串（截断到首个 '\0'）。
func CStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// JoinSlots 将固定槽位数组拼接为空格分隔的字符串。
func JoinSlots(slots [][64]byte) string {
	parts := make([]string, 0, len(slots))
	for _, s := range slots {
		if str := CStr(s[:]); str != "" {
			parts = append(parts, str)
		}
	}
	return strings.Join(parts, " ")
}

// ParseDNSQname 将 DNS label 格式（[len][bytes]...）解析为点分隔域名。
func ParseDNSQname(raw []byte) string {
	var b strings.Builder
	for i := 0; i < len(raw); {
		l := int(raw[i])
		if l == 0 || i+1+l > len(raw) {
			break
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(raw[i+1 : i+1+l])
		i += 1 + l
	}
	return b.String()
}
