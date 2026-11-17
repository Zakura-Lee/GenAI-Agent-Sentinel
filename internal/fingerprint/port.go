package fingerprint

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// procNetPaths 为监听端口的数据源（tcp/tcp6）。
var procNetPaths = []struct {
	path     string
	protocol string
}{
	{"/proc/net/tcp", "tcp"},
	{"/proc/net/tcp6", "tcp6"},
}

// ListenPorts 读取系统监听端口（来自 /proc/net/tcp 与 tcp6）。
func ListenPorts() []PortInfo {
	var out []PortInfo
	for _, p := range procNetPaths {
		out = append(out, parseProcNet(p.path, p.protocol)...)
	}
	return out
}

// parseProcNet 解析 /proc/net/tcp 格式的监听端口（st=0A 即 LISTEN）。
func parseProcNet(path, protocol string) []PortInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []PortInfo
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.ParseUint(parts[1], 16, 32)
		if err != nil {
			continue
		}
		out = append(out, PortInfo{
			Protocol: protocol,
			Port:     uint32(port),
			Addr:     parseHexAddr(parts[0]),
		})
	}
	return out
}

// parseHexAddr 将 /proc/net 的十六进制地址转成可读 IP。
func parseHexAddr(hexAddr string) string {
	b, err := hexToBytes(hexAddr)
	if err != nil {
		return ""
	}
	if len(b) == 4 || len(b) == 16 {
		return net.IP(b).String()
	}
	return ""
}

// hexToBytes 将十六进制字符串按 4 字节小端组转为字节。
func hexToBytes(s string) ([]byte, error) {
	if len(s)%8 != 0 {
		return nil, fmt.Errorf("长度 %d 非 8 的倍数", len(s))
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 8 {
		v, err := strconv.ParseUint(s[i:i+8], 16, 32)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return out, nil
}

// ProbePort 对本地端口做 HTTP 探测，只认 AI 推理服务的明确特征。
func ProbePort(port uint32) (*PortInfo, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	if models, ok := probeModelJSON(client, base+"/api/tags", "models", "name"); ok {
		return &PortInfo{Port: port, Service: "ollama", Models: models}, nil
	}
	if models, ok := probeModelJSON(client, base+"/v1/models", "data", "id"); ok {
		return &PortInfo{Port: port, Service: "openai-compat", Models: models}, nil
	}
	return nil, fmt.Errorf("端口 %d 未识别为推理服务", port)
}

// probeModelJSON 探测返回 JSON 数组的接口，提取模型名列表。
func probeModelJSON(client *http.Client, url, arrayKey, nameKey string) ([]string, bool) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false
	}
	raw, ok := payload[arrayKey]
	if !ok {
		return nil, false
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false
	}
	var models []string
	for _, item := range items {
		var name string
		if err := json.Unmarshal(item[nameKey], &name); err == nil && name != "" {
			models = append(models, name)
		}
	}
	return models, true
}
