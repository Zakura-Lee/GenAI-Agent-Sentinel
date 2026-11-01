// Command adr 是 ADR 平台单可执行文件入口，通过子命令区分 server 与 agent 角色。
package main

import (
	"fmt"
	"os"
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
		fmt.Println("ADR agent starting...")
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
