// Command adr 是 ADR 平台单可执行文件入口，通过子命令区分 server 与 agent 角色。
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/egress"
	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/rule"
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

	rulesPath := os.Getenv("ADR_RULES")
	if rulesPath == "" {
		rulesPath = "rules/default.yaml"
	}
	watcher, err := rule.NewWatcher(rulesPath)
	if err != nil {
		return fmt.Errorf("加载规则 %s: %w", rulesPath, err)
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "关闭规则监听失败:", err)
		}
	}()
	go watcher.Run()
	engine := watcher.Engine()

	markAgentByRules(l, engine)

	fmt.Println("ADR agent 已启动，等待事件...")
	for {
		e, err := l.Read()
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取事件失败:", err)
			continue
		}

		for _, m := range engine.Evaluate(e) {
			fmt.Printf("告警 rule=%s name=%s verdict=%s severity=%s pid=%d\n",
				m.Rule.ID, m.Rule.Name, m.Verdict, m.Severity, e.Header.Pid)
			if m.Rule.AgentType != 0 {
				markTaintForEvent(l, e, m.Rule.AgentType)
			}
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
		default:
			fmt.Printf("event type=%d pid=%d\n", e.Header.Type, e.Header.Pid)
		}
	}
}

// markAgentByRules 扫描 /proc，用规则引擎识别 Agent 进程并写入 taint。
func markAgentByRules(l *egress.Loader, engine *rule.Engine) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		fmt.Fprintln(os.Stderr, "扫描 /proc 失败:", err)
		return
	}

	marked := 0
	for _, ent := range entries {
		pid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)

		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}

		// 构造虚拟 EXEC 事件供规则匹配（仅含 comm，用于 agent 识别）
		ev := &egress.Event{
			Header: egress.AdrEventHeader{Type: egress.EventTypeExec, Pid: pid},
			Exec:   &egress.ExecPayload{},
		}
		copy(ev.Exec.Comm[:], strings.TrimSpace(string(comm)))

		for _, m := range engine.Evaluate(ev) {
			if m.Rule.AgentType == 0 {
				continue
			}
			if markTaintForEvent(l, ev, m.Rule.AgentType) {
				fmt.Printf("已标记 agent 进程: pid=%d comm=%s rule=%s\n",
					pid, egress.CStr(ev.Exec.Comm[:]), m.Rule.ID)
				marked++
			}
			break
		}
	}
	if marked > 0 {
		fmt.Printf("共标记 %d 个 agent 进程\n", marked)
	}
}

// markTaintForEvent 按事件 pid 写入 taint（规则引擎接管 agent 识别）。
func markTaintForEvent(l *egress.Loader, e *egress.Event, agentType uint32) bool {
	ticks, err := egress.ReadStartTicks(e.Header.Pid)
	if err != nil {
		return false
	}
	key := egress.TaintKey{Tgid: e.Header.Pid, StartBoottime: ticks}
	taint := egress.AdrTaint{SessionID: 1, AgentType: agentType, Depth: 1}
	if err := l.MarkTaint(key, taint); err != nil {
		fmt.Fprintf(os.Stderr, "标记 pid=%d 失败: %v\n", e.Header.Pid, err)
		return false
	}
	return true
}

// printExec 打印 EXEC 事件（envp 中敏感变量值脱敏）。
func printExec(e *egress.Event) {
	p := e.Exec
	fmt.Printf("execve pid=%d ppid=%d uid=%d gid=%d comm=%s argv=%s envp=%s\n",
		e.Header.Pid, e.Header.Ppid, e.Header.Uid, e.Header.Gid,
		egress.CStr(p.Comm[:]), egress.JoinSlots(p.Argv[:]), redactEnv(p.Envp[:]))
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
	fmt.Printf("dns pid=%d qname=%s\n", e.Header.Pid, egress.ParseDNSQname(e.Dns.Qname[:]))
}

// printSNI 打印 SNI 事件。
func printSNI(e *egress.Event) {
	fmt.Printf("sni pid=%d server_name=%s\n", e.Header.Pid, egress.CStr(e.Sni.ServerName[:]))
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

// redactEnv 拼接环境变量槽位，并对敏感变量值脱敏。
func redactEnv(slots [][64]byte) string {
	parts := make([]string, 0, len(slots))
	for _, s := range slots {
		str := egress.CStr(s[:])
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
