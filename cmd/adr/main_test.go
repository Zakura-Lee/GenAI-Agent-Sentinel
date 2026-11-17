package main

import (
	"bytes"
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

func TestToRuleEventIgnoresUnsupportedEvent(t *testing.T) {
	got, err := toRuleEvent(&egress.Event{Header: egress.AdrEventHeader{Type: egress.EventTypeFork}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "" || got.Exec != nil || got.Pipe != nil || got.DNS != nil || got.SNI != nil {
		t.Fatalf("unexpected event mapping: %+v", got)
	}
}
