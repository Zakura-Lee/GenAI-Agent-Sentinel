// Command adr 是 ADR 平台单可执行文件入口，通过子命令区分 server 与 agent 角色。
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/egress"
)

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

// printExec 打印 EXEC 事件。
func printExec(e *egress.Event) {
	p := e.Exec
	fmt.Printf("execve pid=%d ppid=%d uid=%d gid=%d comm=%s argv=%s envp=%s\n",
		e.Header.Pid, e.Header.Ppid, e.Header.Uid, e.Header.Gid,
		cstr(p.Comm[:]), cstr(p.Argv[:]), cstr(p.Envp[:]))
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
	fmt.Printf("dns pid=%d qname=%s\n", e.Header.Pid, cstr(e.Dns.Qname[:]))
}

// printSNI 打印 SNI 事件。
func printSNI(e *egress.Event) {
	fmt.Printf("sni pid=%d server_name=%s\n", e.Header.Pid, cstr(e.Sni.ServerName[:]))
}

// cstr 将定长字节数组转为 C 字符串（截断到首个 '\0'）。
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
