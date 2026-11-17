package rule

import (
	"strconv"
	"strings"
	"sync"

	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/egress"
)

// Engine 为规则判定引擎，支持热更新。
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewEngine 创建引擎。
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Replace 原子替换规则集（热更新）。
func (e *Engine) Replace(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// Rules 返回当前规则集副本。
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule(nil), e.rules...)
}

// Match 为一条命中的规则。
type Match struct {
	Rule     Rule
	Verdict  Verdict
	Severity Severity
}

// Evaluate 对事件评估所有规则，返回命中列表。
func (e *Engine) Evaluate(ev *egress.Event) []Match {
	fields := extractFields(ev)
	name := eventTypeName(ev.Header.Type)

	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []Match
	for _, r := range e.rules {
		if r.EventType != name {
			continue
		}
		if matchConditions(r.Conditions, fields) {
			matches = append(matches, Match{Rule: r, Verdict: r.Verdict, Severity: r.Severity})
		}
	}
	return matches
}

// extractFields 将事件转换为规则可匹配的字段 map。
func extractFields(ev *egress.Event) map[string]string {
	f := map[string]string{
		"pid":  strconv.FormatUint(uint64(ev.Header.Pid), 10),
		"ppid": strconv.FormatUint(uint64(ev.Header.Ppid), 10),
		"uid":  strconv.FormatUint(uint64(ev.Header.Uid), 10),
		"gid":  strconv.FormatUint(uint64(ev.Header.Gid), 10),
	}
	switch ev.Header.Type {
	case egress.EventTypeExec:
		if ev.Exec != nil {
			f["comm"] = egress.CStr(ev.Exec.Comm[:])
			f["argv"] = egress.JoinSlots(ev.Exec.Argv[:])
			f["envp"] = egress.JoinSlots(ev.Exec.Envp[:])
		}
	case egress.EventTypeDNS:
		if ev.Dns != nil {
			f["qname"] = egress.ParseDNSQname(ev.Dns.Qname[:])
		}
	case egress.EventTypeSNI:
		if ev.Sni != nil {
			f["server_name"] = egress.CStr(ev.Sni.ServerName[:])
		}
	case egress.EventTypePipe:
		if ev.Pipe != nil {
			f["ino"] = strconv.FormatUint(ev.Pipe.Ino, 10)
			f["data"] = string(ev.Pipe.Data[:ev.Pipe.Len])
		}
	case egress.EventTypeExit:
		if ev.Exit != nil {
			f["exit_code"] = strconv.FormatUint(uint64(ev.Exit.ExitCode), 10)
		}
	case egress.EventTypeFork:
		if ev.Fork != nil {
			f["child_pid"] = strconv.FormatUint(uint64(ev.Fork.ChildPid), 10)
		}
	}
	return f
}

// eventTypeName 将事件类型转成规则中的名称。
func eventTypeName(t uint32) string {
	switch t {
	case egress.EventTypeExec:
		return "exec"
	case egress.EventTypeExit:
		return "exit"
	case egress.EventTypeFork:
		return "fork"
	case egress.EventTypePipe:
		return "pipe"
	case egress.EventTypeDNS:
		return "dns"
	case egress.EventTypeSNI:
		return "sni"
	default:
		return "unknown"
	}
}

// matchConditions 判断字段是否满足全部条件（AND）。
func matchConditions(conds []Condition, fields map[string]string) bool {
	for _, c := range conds {
		if !matchCondition(c, fields) {
			return false
		}
	}
	return true
}

// matchCondition 判断单个条件。
func matchCondition(c Condition, fields map[string]string) bool {
	v, ok := fields[c.Field]
	if !ok {
		return false
	}
	switch c.Op {
	case "eq":
		return v == c.Value
	case "contains":
		return strings.Contains(v, c.Value)
	case "prefix":
		return strings.HasPrefix(v, c.Value)
	case "suffix":
		return strings.HasSuffix(v, c.Value)
	default:
		return false
	}
}
