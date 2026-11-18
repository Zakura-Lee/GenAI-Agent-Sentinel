package fingerprint

import (
	"encoding/json"
	"os"
	"strings"
)

// ModelFromConfig 从 Agent 配置文件读取 model/provider 字段（JSON 优先，回退简单 YAML 行解析）。
func ModelFromConfig(paths []string) (model, provider string) {
	for _, p := range paths {
		m, pr := parseConfigFile(p)
		if model == "" {
			model = m
		}
		if provider == "" {
			provider = pr
		}
		if model != "" && provider != "" {
			break
		}
	}
	return model, provider
}

// parseConfigFile 解析单个配置文件。
func parseConfigFile(path string) (model, provider string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}

	var obj map[string]any
	if json.Unmarshal(data, &obj) == nil {
		return extractModelFields(obj)
	}
	return parseYAMLFlat(string(data))
}

// extractModelFields 从 JSON 对象递归提取 model/provider 字段。
func extractModelFields(obj map[string]any) (model, provider string) {
	for k, v := range obj {
		switch strings.ToLower(k) {
		case "model", "model_name", "default_model":
			if s, ok := v.(string); ok && model == "" {
				model = s
			}
		case "provider", "api_provider", "model_provider":
			if s, ok := v.(string); ok && provider == "" {
				provider = s
			}
		}
		if sub, ok := v.(map[string]any); ok {
			m, p := extractModelFields(sub)
			if model == "" {
				model = m
			}
			if provider == "" {
				provider = p
			}
		}
	}
	return model, provider
}

// parseYAMLFlat 简单 YAML 行解析（只识别顶层 `model:` / `provider:`）。
func parseYAMLFlat(text string) (model, provider string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "model", "model_name", "default_model":
			if model == "" {
				model = val
			}
		case "provider", "api_provider":
			if provider == "" {
				provider = val
			}
		}
	}
	return model, provider
}
