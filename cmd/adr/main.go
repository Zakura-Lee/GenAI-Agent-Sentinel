// Command adr 是 ADR 平台单可执行文件入口，通过子命令区分 server 与 agent 角色。
package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/egress"
)

// envSecretKeywords 环境变量名包含这些子串时视为敏感，值会被脱敏。
var envSecretKeywords = []string{
	"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTHORIZATION",
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		fmt.Println("ADR server starting...")
	case "agent":
		if err := runAgent(); err != nil {
			fmt.Fprintln(os.Stderr, "agent 错误:", err)
			os.Exit(1)
		}
	case "audit":
		fmt.Println("ADR audit service starting...")
	default:
		usage()
		os.Exit(1)
	}
}

// usage 打印命令行用法并退出。
func usage() {
	fmt.Fprintln(os.Stderr, "用法: adr <server|agent|audit>")
}

// runAgent 加载 eBPF 程序集并循环打印捕获到的事件。
func runAgent() error {
	objPath := os.Getenv("ADR_BPF_OBJ")
	if objPath == "" {
		objPath = "ebpf/build/adr.bpf.o"
	}

	obj, err := os.ReadFile(objPath)
	if err != nil {
		return fmt.Errorf("读取 eBPF 对象 %s: %w", objPath, err)
	}

	l, err := egress.Load(obj)
	if err != nil {
		return fmt.Errorf("加载 eBPF: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "关闭加载器失败:", err)
		}
	}()

	markAgentProcesses(l)

	fmt.Println("ADR agent 已启动，等待事件...")
	for {
		e, err := l.Read()
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取事件失败:", err)
			continue
		}
		switch e.Header.Type {
		case egress.EventTypeExec:
			printExec(e)
		case egress.EventTypeExit:
			printExit(e)
		case egress.EventTypeFork:
			printFork(e)
		case egress.EventTypePipe:
			printPipe(e)
		case egress.EventTypeDNS:
			printDNS(e)
		case egress.EventTypeSNI:
			printSNI(e)
		case egress.EventTypeFile:
			printFile(e)
		case egress.EventTypeNet:
			printNet(e)
		default:
			fmt.Printf("event type=%d pid=%d\n", e.Header.Type, e.Header.Pid)
		}
	}
}

// defaultAgentWhitelist 默认识别的 GenAI Agent 进程名（comm）。
var defaultAgentWhitelist = []string{"claude", "codex", "cursor", "continue", "copilot", "aider"}

// markAgentProcesses 扫描 /proc，按 comm 白名单为现有 Agent 进程写入 taint。
// 额外白名单可通过 ADR_AGENT_WHITELIST（逗号分隔）注入。
func markAgentProcesses(l *egress.Loader) {
	whitelist := defaultAgentWhitelist
	if extra := os.Getenv("ADR_AGENT_WHITELIST"); extra != "" {
		whitelist = append(append([]string{}, whitelist...), strings.Split(extra, ",")...)
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		fmt.Fprintln(os.Stderr, "扫描 /proc 失败:", err)
		return
	}

	marked := 0
	for _, e := range entries {
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)

		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if !matchesWhitelist(name, whitelist) {
			continue
		}

		ticks, err := egress.ReadStartTicks(pid)
		if err != nil {
			continue
		}

		key := egress.TaintKey{Tgid: pid, StartBoottime: ticks}
		taint := egress.AdrTaint{SessionID: 1, AgentType: 1, Depth: 1}
		if err := l.MarkTaint(key, taint); err != nil {
			fmt.Fprintf(os.Stderr, "标记 pid=%d 失败: %v\n", pid, err)
			continue
		}
		fmt.Printf("已标记 agent 进程: pid=%d comm=%s\n", pid, name)
		marked++
	}
	if marked > 0 {
		fmt.Printf("共标记 %d 个 agent 进程\n", marked)
	}
}

// matchesWhitelist 判断 comm 是否命中白名单（精确匹配）。
func matchesWhitelist(name string, whitelist []string) bool {
	for _, w := range whitelist {
		if name == strings.TrimSpace(w) {
			return true
		}
	}
	return false
}

// printExec 打印 EXEC 事件（envp 中敏感变量值脱敏）。
func printExec(e *egress.Event) {
	p := e.Exec
	fmt.Printf("execve pid=%d ppid=%d uid=%d gid=%d comm=%s argv=%s envp=%s\n",
		e.Header.Pid, e.Header.Ppid, e.Header.Uid, e.Header.Gid,
		cstr(p.Comm[:]), joinSlots(p.Argv[:]), redactEnv(p.Envp[:]))
}

// printPipe 打印 PIPE 事件。
func printPipe(e *egress.Event) {
	p := e.Pipe
	dir := "读"
	if p.Dir == 1 {
		dir = "写"
	}
	fmt.Printf("pipe ino=%d pid=%d dir=%s len=%d data=%q\n",
		p.Ino, e.Header.Pid, dir, p.Len, p.Data[:p.Len])
}

// printDNS 打印 DNS 事件。
func printDNS(e *egress.Event) {
	fmt.Printf("dns pid=%d qname=%s\n", e.Header.Pid, parseDNSQname(e.Dns.Qname[:]))
}

// parseDNSQname 将 DNS label 格式（[len][bytes]...）解析为点分隔域名。
func parseDNSQname(raw []byte) string {
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

// printSNI 打印 SNI 事件。
func printSNI(e *egress.Event) {
	fmt.Printf("sni pid=%d server_name=%s\n", e.Header.Pid, cstr(e.Sni.ServerName[:]))
}

// printExit 打印 EXIT 事件。
func printExit(e *egress.Event) {
	fmt.Printf("exit pid=%d exit_code=%d duration_ms=%d\n",
		e.Header.Pid, e.Exit.ExitCode, e.Exit.DurationNs/1e6)
}

// printFork 打印 FORK 事件。
func printFork(e *egress.Event) {
	fmt.Printf("fork ppid=%d child_pid=%d\n", e.Header.Pid, e.Fork.ChildPid)
}

// printFile 打印 FILE 事件（openat / mmap）。
func printFile(e *egress.Event) {
	p := e.File
	op := "open"
	if p.Op == 1 {
		op = "mmap"
	}
	fmt.Printf("file op=%s pid=%d path=%s dirfd=%d flags=0x%x fd=%d len=%d\n",
		op, e.Header.Pid, cstr(p.Path[:]), p.Dirfd, p.Flags, p.Fd, p.Len)
}

// printNet 打印 NET 事件（connect / bind / listen）。
func printNet(e *egress.Event) {
	p := e.Net
	ops := []string{"connect", "bind", "listen"}
	op := "unknown"
	if int(p.Op) < len(ops) {
		op = ops[p.Op]
	}
	fmt.Printf("net op=%s pid=%d family=%d port=%d fd=%d addr=%s\n",
		op, e.Header.Pid, p.Family, p.Port, p.Fd, formatAddr(p.Family, p.Addr[:]))
}

// formatAddr 将 IPv4/IPv6 地址格式化为字符串。
func formatAddr(family uint32, addr []byte) string {
	if family == 2 && len(addr) >= 4 {
		return net.IP(addr[:4]).String()
	}
	if family == 10 && len(addr) >= 16 {
		return net.IP(addr[:16]).String()
	}
	return ""
}

// cstr 将定长字节数组转为 C 字符串（截断到首个 '\0'）。
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// joinSlots 将固定槽位数组拼接为空格分隔的字符串。
func joinSlots(slots [][64]byte) string {
	parts := make([]string, 0, len(slots))
	for _, s := range slots {
		if str := cstr(s[:]); str != "" {
			parts = append(parts, str)
		}
	}
	return strings.Join(parts, " ")
}

// redactEnv 拼接环境变量槽位，并对敏感变量值脱敏。
func redactEnv(slots [][64]byte) string {
	parts := make([]string, 0, len(slots))
	for _, s := range slots {
		str := cstr(s[:])
		if str == "" {
			continue
		}
		parts = append(parts, redactEnvVar(str))
	}
	return strings.Join(parts, " ")
}

// redactEnvVar 将形如 KEY=VALUE 的敏感环境变量值替换为 ***。
func redactEnvVar(s string) string {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return s
	}
	key := s[:i]
	upper := strings.ToUpper(key)
	for _, kw := range envSecretKeywords {
		if strings.Contains(upper, kw) {
			return key + "=***"
		}
	}
	return s
}
