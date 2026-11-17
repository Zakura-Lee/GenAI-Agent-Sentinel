package fingerprint

import "strings"

// providerByHost 将 API 域名映射到厂商。
var providerByHost = map[string]string{
	"api.anthropic.com":                 "anthropic",
	"api.openai.com":                    "openai",
	"api.deepseek.com":                  "deepseek",
	"generativelanguage.googleapis.com": "google",
	"api.mistral.ai":                    "mistral",
	"api.groq.com":                      "groq",
	"api.together.xyz":                  "together",
	"openrouter.ai":                     "openrouter",
	"api.cohere.com":                    "cohere",
	"api.perplexity.ai":                 "perplexity",
	"api.x.ai":                          "xai",
	"api.moonshot.cn":                   "moonshot",
	"dashscope.aliyuncs.com":            "alibaba",
	"open.bigmodel.cn":                  "zhipu",
	"api.minimax.chat":                  "minimax",
}

// ProviderFromHost 根据 API 域名推断厂商（后缀匹配，兼容子域名）。
func ProviderFromHost(host string) string {
	h := strings.ToLower(host)
	for domain, provider := range providerByHost {
		if h == domain || strings.HasSuffix(h, "."+domain) {
			return provider
		}
	}
	return ""
}

// providerByEnvKey 将 API key 环境变量名映射到厂商。
var providerByEnvKey = map[string]string{
	"ANTHROPIC_API_KEY":  "anthropic",
	"OPENAI_API_KEY":     "openai",
	"DEEPSEEK_API_KEY":   "deepseek",
	"GOOGLE_API_KEY":     "google",
	"GEMINI_API_KEY":     "google",
	"MISTRAL_API_KEY":    "mistral",
	"GROQ_API_KEY":       "groq",
	"OPENROUTER_API_KEY": "openrouter",
	"TOGETHER_API_KEY":   "together",
	"CODEIUM_API_KEY":    "codeium",
}

// ProviderFromEnv 根据命中的环境变量名推断厂商（按传入顺序取第一个命中）。
func ProviderFromEnv(keys []string) string {
	for _, k := range keys {
		if p, ok := providerByEnvKey[k]; ok {
			return p
		}
	}
	return ""
}

// providerByModelPrefix 根据模型名前缀推断厂商。
var providerByModelPrefix = []struct {
	prefix   string
	provider string
}{
	{"claude", "anthropic"},
	{"gpt", "openai"},
	{"o1", "openai"},
	{"o3", "openai"},
	{"deepseek", "deepseek"},
	{"gemini", "google"},
	{"mistral", "mistral"},
	{"llama", "meta"},
	{"qwen", "alibaba"},
	{"glm", "zhipu"},
	{"moonshot", "moonshot"},
	{"grok", "xai"},
	{"command", "cohere"},
	{"minimax", "minimax"},
}

// ProviderFromModel 根据模型名推断厂商。
func ProviderFromModel(model string) string {
	m := strings.ToLower(model)
	for _, p := range providerByModelPrefix {
		if strings.HasPrefix(m, p.prefix) {
			return p.provider
		}
	}
	return ""
}

// providerByHarness 为已知 Harness 的默认厂商（兜底推断）。
var providerByHarness = map[string]string{
	"claude-code": "anthropic",
	"codex":       "openai",
	"windsurf":    "codeium",
}

// ModelFromCmdline 从命令行提取 `--model` / `-m` 参数值。
func ModelFromCmdline(cmdline []string) string {
	for i, arg := range cmdline {
		switch {
		case (arg == "--model" || arg == "-m") && i+1 < len(cmdline):
			return cmdline[i+1]
		case strings.HasPrefix(arg, "--model="):
			return strings.TrimPrefix(arg, "--model=")
		}
	}
	return ""
}

// ModelFromEnv 从 environ 的 *_MODEL 变量读取模型名。
func ModelFromEnv(environ map[string]string) string {
	for _, k := range []string{
		"ANTHROPIC_MODEL", "CLAUDE_MODEL", "OPENAI_MODEL",
		"DEEPSEEK_MODEL", "GOOGLE_MODEL", "GEMINI_MODEL",
		"CURSOR_MODEL", "CODEIUM_MODEL",
	} {
		if v := environ[k]; v != "" {
			return v
		}
	}
	return ""
}

// InferProvider 综合推断厂商。
// 优先级：配置文件 provider > 模型名前缀 > API key 环境变量 > 运行时 API 域名 > Harness 兜底。
func InferProvider(harness, configProvider, model string, envKeys, apiHosts []string) string {
	if configProvider != "" {
		return strings.ToLower(configProvider)
	}
	if p := ProviderFromModel(model); p != "" {
		return p
	}
	if p := ProviderFromEnv(envKeys); p != "" {
		return p
	}
	for _, h := range apiHosts {
		if p := ProviderFromHost(h); p != "" {
			return p
		}
	}
	return providerByHarness[harness]
}
