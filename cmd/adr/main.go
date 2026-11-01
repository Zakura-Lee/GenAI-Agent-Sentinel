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

// runAgent 加载 eBPF 程序并循环打印捕获到的 execve 事件。
func runAgent() error {
	objPath := os.Getenv("ADR_BPF_OBJ")
	if objPath == "" {
		objPath = "ebpf/build/trace_execve.bpf.o"
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

	fmt.Println("ADR agent 已启动，等待 execve 事件...")
	for {
		e, err := l.Read()
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取事件失败:", err)
			continue
		}
		fmt.Printf("execve pid=%d ppid=%d uid=%d gid=%d comm=%s argv=%s envp=%s\n",
			e.Pid, e.Ppid, e.Uid, e.Gid,
			cstr(e.Comm[:]), cstr(e.Argv[:]), cstr(e.Envp[:]))
	}
}

// cstr 将定长字节数组转为 C 字符串（截断到首个 '\0'）。
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
