package rule

import (
	"strings"
	"testing"
)

func testRule(id, expression string, enabled bool) Rule {
	return Rule{
		ID:         id,
		Name:       id,
		Enabled:    enabled,
		EventType:  EventTypeExec,
		Severity:   "medium",
		Expression: expression,
		Source:     "local",
	}
}

func TestEngineEvaluateExec(t *testing.T) {
	engine, err := NewEngine([]Rule{
		testRule("match-comm", `Comm == "curl"`, true),
		testRule("match-argv", `"-o" in Argv`, true),
		testRule("disabled", `Comm == "curl"`, false),
		testRule("no-match", `Comm == "wget"`, true),
	})
	if err != nil {
		t.Fatal(err)
	}

	alerts, err := engine.Evaluate(Event{
		Type:        EventTypeExec,
		TimestampNS: 12345,
		Exec: &ExecEvent{
			PID:  12,
			PPID: 5,
			UID:  1000,
			Comm: "curl",
			Argv: []string{"curl", "-o", "file"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want 2", len(alerts))
	}
	if alerts[0].RuleID != "match-comm" || alerts[0].PID != 12 || alerts[0].PPID != 5 || alerts[0].TimestampNS != 12345 {
		t.Fatalf("unexpected first alert: %+v", alerts[0])
	}
	if alerts[1].RuleID != "match-argv" {
		t.Fatalf("unexpected second alert: %+v", alerts[1])
	}
}

func TestEngineMatchesExecArgvZero(t *testing.T) {
	engine, err := NewEngine([]Rule{
		testRule("match-sleep-path", `Argv[0] matches "(^|/)sleep$"`, true),
	})
	if err != nil {
		t.Fatal(err)
	}

	alerts, err := engine.Evaluate(Event{
		Type: EventTypeExec,
		Exec: &ExecEvent{
			Comm: "bash",
			Argv: []string{"/usr/bin/sleep", "1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleID != "match-sleep-path" {
		t.Fatalf("got alerts %+v, want sleep path match", alerts)
	}
}

func TestEngineEvaluatesPipeDNSAndSNI(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{ID: "pipe-write", Name: "pipe write", Enabled: true, EventType: EventTypePipe, Severity: "low", Expression: `Dir == "write" && Len > 0`, Source: "local"},
		{ID: "dns-example", Name: "DNS example", Enabled: true, EventType: EventTypeDNS, Severity: "medium", Expression: `Qname == "example.com"`, Source: "local"},
		{ID: "sni-example", Name: "SNI example", Enabled: true, EventType: EventTypeSNI, Severity: "high", Expression: `ServerName == "example.com"`, Source: "local"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		event Event
		id    string
	}{
		{
			name: "pipe",
			event: Event{
				Type: EventTypePipe,
				Pipe: &PipeEvent{PID: 20, PPID: 10, Ino: 123, Len: 5, Dir: "write", Data: "hello"},
			},
			id: "pipe-write",
		},
		{
			name: "dns",
			event: Event{
				Type: EventTypeDNS,
				DNS:  &DNSEvent{PID: 21, PPID: 11, Qname: "example.com"},
			},
			id: "dns-example",
		},
		{
			name: "sni",
			event: Event{
				Type: EventTypeSNI,
				SNI:  &SNIEvent{PID: 22, PPID: 12, ServerName: "example.com"},
			},
			id: "sni-example",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alerts, err := engine.Evaluate(tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if len(alerts) != 1 || alerts[0].RuleID != tc.id || alerts[0].EventType != tc.event.Type {
				t.Fatalf("got alerts %+v, want rule %s", alerts, tc.id)
			}
			if alerts[0].Subject == "" {
				t.Fatalf("alert has no event subject: %+v", alerts[0])
			}
		})
	}
}

func TestEngineEvaluatesForkExitFileAndNet(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{ID: "fork-child", Name: "fork child", Enabled: true, EventType: EventTypeFork, Severity: "low", Expression: `ChildPID == 404`, Source: "local"},
		{ID: "exit-failure", Name: "exit failure", Enabled: true, EventType: EventTypeExit, Severity: "medium", Expression: `ExitCode != 0 && DurationNS > 100`, Source: "local"},
		{ID: "file-open", Name: "file open", Enabled: true, EventType: EventTypeFile, Severity: "high", Expression: `Op == "open" && Dirfd == -100 && Path == "/tmp/secret.key"`, Source: "local"},
		{ID: "net-connect", Name: "net connect", Enabled: true, EventType: EventTypeNet, Severity: "critical", Expression: `Op == "connect" && Port == 443 && Addr == "203.0.113.8"`, Source: "local"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		event Event
		id    string
	}{
		{name: "fork", event: Event{Type: EventTypeFork, Fork: &ForkEvent{PID: 20, ChildPID: 404}}, id: "fork-child"},
		{name: "exit", event: Event{Type: EventTypeExit, Exit: &ExitEvent{PID: 21, ExitCode: 1, DurationNS: 200}}, id: "exit-failure"},
		{name: "file", event: Event{Type: EventTypeFile, File: &FileEvent{PID: 22, Op: "open", Dirfd: -100, Path: "/tmp/secret.key"}}, id: "file-open"},
		{name: "net", event: Event{Type: EventTypeNet, Net: &NetEvent{PID: 23, Op: "connect", Port: 443, Addr: "203.0.113.8"}}, id: "net-connect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alerts, err := engine.Evaluate(tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if len(alerts) != 1 || alerts[0].RuleID != tc.id || alerts[0].PID == 0 || alerts[0].Subject == "" {
				t.Fatalf("got alerts %+v, want matching rule %s with process details", alerts, tc.id)
			}
		})
	}
}

func TestNewEngineRejectsInvalidRules(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{name: "unknown field", rule: testRule("bad-field", `Missing == "x"`, true)},
		{name: "invalid expression", rule: testRule("bad-syntax", `Comm ==`, true)},
		{name: "unsupported event", rule: Rule{ID: "bad-event", Name: "bad", Enabled: true, EventType: "UNKNOWN", Severity: "low", Expression: "true", Source: "local"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewEngine([]Rule{tc.rule}); err == nil {
				t.Fatal("NewEngine succeeded, want validation error")
			}
		})
	}
}

func TestEngineRejectsDuplicateIDs(t *testing.T) {
	_, err := NewEngine([]Rule{
		testRule("duplicate", `Comm == "a"`, true),
		testRule("duplicate", `Comm == "b"`, true),
	})
	if err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("got %v, want duplicate ID error", err)
	}
}

func TestEngineRejectsMissingExecData(t *testing.T) {
	engine, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Evaluate(Event{Type: EventTypeExec}); err == nil {
		t.Fatal("Evaluate succeeded, want missing data error")
	}
}

func TestEngineRejectsMissingTypedPayload(t *testing.T) {
	engine, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []string{
		EventTypePipe, EventTypeDNS, EventTypeSNI,
		EventTypeFork, EventTypeExit, EventTypeFile, EventTypeNet,
	} {
		t.Run(eventType, func(t *testing.T) {
			if _, err := engine.Evaluate(Event{Type: eventType}); err == nil {
				t.Fatalf("Evaluate(%s) succeeded without payload", eventType)
			}
		})
	}
}

func TestEngineIgnoresUnsupportedEvent(t *testing.T) {
	engine, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := engine.Evaluate(Event{Type: "UNKNOWN"})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("got %d alerts, want none", len(alerts))
	}
}
