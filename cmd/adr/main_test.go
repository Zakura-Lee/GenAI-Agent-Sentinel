package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/egress"
	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/rule"
)

func TestToRuleEventExec(t *testing.T) {
	event := &egress.Event{
		Header: egress.AdrEventHeader{TsNs: 123, Type: egress.EventTypeExec, Pid: 20, Ppid: 10, Uid: 1000, Gid: 1000},
		Exec: &egress.ExecPayload{
			Comm: [16]byte{'c', 'u', 'r', 'l'},
			Argv: [6][64]byte{
				{'c', 'u', 'r', 'l'},
				{'-', 'o'},
			},
			Envp: [6][64]byte{
				{'S', 'E', 'C', 'R', 'E', 'T', '=', 'x'},
			},
		},
	}

	got, err := toRuleEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != rule.EventTypeExec || got.TimestampNS != 123 || got.Exec == nil {
		t.Fatalf("unexpected normalized event: %+v", got)
	}
	if got.Exec.PID != 20 || got.Exec.PPID != 10 || got.Exec.UID != 1000 || got.Exec.GID != 1000 {
		t.Fatalf("unexpected process identity: %+v", got.Exec)
	}
	if got.Exec.Comm != "curl" || len(got.Exec.Argv) != 2 || got.Exec.Argv[1] != "-o" {
		t.Fatalf("unexpected process arguments: %+v", got.Exec)
	}
}

func TestToRuleEventPipeDNSAndSNI(t *testing.T) {
	pipe, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{Type: egress.EventTypePipe, Pid: 30, Ppid: 15},
		Pipe:   &egress.PipePayload{Ino: 99, Len: 5, Dir: 1, Data: [128]byte{'h', 'e', 'l', 'l', 'o'}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pipe.Type != rule.EventTypePipe || pipe.Pipe == nil || pipe.Pipe.Dir != "write" || pipe.Pipe.Data != "hello" {
		t.Fatalf("unexpected PIPE event mapping: %+v", pipe)
	}

	var qname [256]byte
	qname[0] = 7
	copy(qname[1:], "example")
	qname[8] = 3
	copy(qname[9:], "com")
	dns, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{Type: egress.EventTypeDNS, Pid: 31, Ppid: 16},
		Dns:    &egress.DnsPayload{Qname: qname},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dns.Type != rule.EventTypeDNS || dns.DNS == nil || dns.DNS.Qname != "example.com" {
		t.Fatalf("unexpected DNS event mapping: %+v", dns)
	}

	sni, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{Type: egress.EventTypeSNI, Pid: 32, Ppid: 17},
		Sni:    &egress.SniPayload{ServerName: [256]byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sni.Type != rule.EventTypeSNI || sni.SNI == nil || sni.SNI.ServerName != "example.com" {
		t.Fatalf("unexpected SNI event mapping: %+v", sni)
	}
}

func TestToRuleEventForkExitFileAndNet(t *testing.T) {
	fork, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{TsNs: 1, Type: egress.EventTypeFork, Pid: 20, Uid: 1000},
		Fork:   &egress.ForkPayload{ChildPid: 21},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fork.Type != rule.EventTypeFork || fork.Fork == nil || fork.Fork.PID != 20 || fork.Fork.ChildPID != 21 {
		t.Fatalf("unexpected FORK event mapping: %+v", fork)
	}

	exit, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{Type: egress.EventTypeExit, Pid: 21},
		Exit:   &egress.ExitPayload{ExitCode: 1, DurationNs: 1234},
	})
	if err != nil {
		t.Fatal(err)
	}
	if exit.Type != rule.EventTypeExit || exit.Exit == nil || exit.Exit.ExitCode != 1 || exit.Exit.DurationNS != 1234 {
		t.Fatalf("unexpected EXIT event mapping: %+v", exit)
	}

	file, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{Type: egress.EventTypeFile, Pid: 22},
		File:   &egress.FilePayload{Op: 0, Dirfd: 4294967196, Flags: 1, Path: [256]byte{'/', 't', 'm', 'p', '/', 'x'}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if file.Type != rule.EventTypeFile || file.File == nil || file.File.Op != "open" || file.File.Dirfd != -100 || file.File.Path != "/tmp/x" {
		t.Fatalf("unexpected FILE event mapping: %+v", file)
	}

	net, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{Type: egress.EventTypeNet, Pid: 23},
		Net:    &egress.NetPayload{Op: 0, Family: 2, Port: 443, Fd: 8, Addr: [16]byte{203, 0, 113, 8}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if net.Type != rule.EventTypeNet || net.Net == nil || net.Net.Op != "connect" || net.Net.Addr != "203.0.113.8" || net.Net.Port != 443 {
		t.Fatalf("unexpected NET event mapping: %+v", net)
	}
}

func TestToRuleEventRejectsInvalidFileAndNetOperations(t *testing.T) {
	cases := []struct {
		name  string
		event *egress.Event
	}{
		{
			name:  "file",
			event: &egress.Event{Header: egress.AdrEventHeader{Type: egress.EventTypeFile}, File: &egress.FilePayload{Op: 2}},
		},
		{
			name:  "net",
			event: &egress.Event{Header: egress.AdrEventHeader{Type: egress.EventTypeNet}, Net: &egress.NetPayload{Op: 3}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := toRuleEvent(tc.event); err == nil {
				t.Fatal("toRuleEvent succeeded with invalid operation")
			}
		})
	}
}

func TestToRuleEventRejectsInvalidPipePayload(t *testing.T) {
	_, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{Type: egress.EventTypePipe},
		Pipe:   &egress.PipePayload{Len: 129},
	})
	if err == nil {
		t.Fatal("expected invalid PIPE payload error")
	}
}

func TestWriteAlert(t *testing.T) {
	var output bytes.Buffer
	alert := rule.Alert{
		TimestampNS: 123,
		RuleID:      "test-sleep",
		RuleName:    "测试 sleep 进程",
		Severity:    "low",
		Source:      "local",
		PID:         20,
		PPID:        10,
		Comm:        "bash",
	}

	if err := writeAlert(&output, alert); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), formatAlert(alert)+"\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExecAlertPipelineWritesMatchingRule(t *testing.T) {
	engine, err := rule.NewEngine([]rule.Rule{
		{
			ID:         "test-sleep",
			Name:       "test sleep",
			Enabled:    true,
			EventType:  rule.EventTypeExec,
			Severity:   "low",
			Expression: `Argv[0] matches "(^|/)sleep$"`,
			Source:     "local",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var argv [6][64]byte
	copy(argv[0][:], "/usr/bin/sleep")
	copy(argv[1][:], "1")
	event, err := toRuleEvent(&egress.Event{
		Header: egress.AdrEventHeader{TsNs: 123, Type: egress.EventTypeExec, Pid: 20, Ppid: 10},
		Exec:   &egress.ExecPayload{Comm: [16]byte{'b', 'a', 's', 'h'}, Argv: argv},
	})
	if err != nil {
		t.Fatal(err)
	}

	alerts, err := engine.Evaluate(event)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleID != "test-sleep" {
		t.Fatalf("got alerts %+v, want one test-sleep alert", alerts)
	}

	logPath := filepath.Join(t.TempDir(), "alerts.log")
	t.Setenv("ADR_ALERT_LOG", logPath)
	logFile, gotPath, err := openAlertLog()
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != logPath {
		t.Fatalf("got log path %q, want %q", gotPath, logPath)
	}
	defer func() {
		if err := logFile.Close(); err != nil {
			t.Errorf("close alert log: %v", err)
		}
	}()
	if err := writeAlert(logFile, alerts[0]); err != nil {
		t.Fatal(err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if line := string(logData); !strings.Contains(line, "rule_id=test-sleep") || !strings.Contains(line, "pid=20") {
		t.Fatalf("unexpected alert log line: %q", line)
	}
}

func TestToRuleEventIgnoresUnsupportedEvent(t *testing.T) {
	got, err := toRuleEvent(&egress.Event{Header: egress.AdrEventHeader{Type: 99}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "" || got.Exec != nil || got.Pipe != nil || got.DNS != nil || got.SNI != nil ||
		got.Fork != nil || got.Exit != nil || got.File != nil || got.Net != nil {
		t.Fatalf("unexpected event mapping: %+v", got)
	}
}
