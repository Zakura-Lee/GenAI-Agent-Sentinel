package rule

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

const (
	// EventTypeExec 表示进程执行事件。
	EventTypeExec = "EXEC"
	// EventTypePipe 表示管道读写事件。
	EventTypePipe = "PIPE"
	// EventTypeDNS 表示 DNS 查询事件。
	EventTypeDNS = "DNS"
	// EventTypeSNI 表示 TLS SNI 事件。
	EventTypeSNI = "SNI"

	maxRules          = 1000
	maxExpressionSize = 4096
)

var ruleIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// Rule 描述一条本地检测规则。
type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	EventType   string    `json:"event_type"`
	Severity    string    `json:"severity"`
	Expression  string    `json:"expression"`
	Source      string    `json:"source"`
	SourceURL   string    `json:"source_url,omitempty"`
	UpstreamID  string    `json:"upstream_id,omitempty"`
	License     string    `json:"license,omitempty"`
	Author      string    `json:"author,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// ExecEvent 是规则可见的 EXEC 字段，不包含环境变量。
type ExecEvent struct {
	PID  uint32
	PPID uint32
	UID  uint32
	GID  uint32
	Comm string // sys_enter_execve 时当前进程的 comm，通常不是目标程序名。
	Argv []string
}

// PipeEvent 是规则可见的管道事件字段。
type PipeEvent struct {
	PID  uint32
	PPID uint32
	UID  uint32
	GID  uint32
	Ino  uint64
	Len  uint32
	Dir  string
	Data string
}

// DNSEvent 是规则可见的 DNS 查询字段。
type DNSEvent struct {
	PID   uint32
	PPID  uint32
	UID   uint32
	GID   uint32
	Qname string
}

// SNIEvent 是规则可见的 TLS SNI 字段。
type SNIEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	GID        uint32
	ServerName string
}

// Event 是交给规则引擎的标准化事件。
type Event struct {
	Type        string
	TimestampNS uint64
	Exec        *ExecEvent
	Pipe        *PipeEvent
	DNS         *DNSEvent
	SNI         *SNIEvent
}

// Alert 表示命中规则后产生的本地告警。
type Alert struct {
	TimestampNS uint64
	EventType   string
	RuleID      string
	RuleName    string
	Severity    string
	Source      string
	Author      string
	PID         uint32
	PPID        uint32
	Comm        string
	Subject     string
}

type compiledRule struct {
	rule    Rule
	program *vm.Program
}

// Engine 编译并评估一组规则。
type Engine struct {
	rules []compiledRule
}

// Validate 检查规则字段和值是否合法。
func Validate(r Rule) error {
	if !ruleIDPattern.MatchString(r.ID) {
		return errors.New("规则 ID 必须为 1-128 个字母、数字、点、下划线或连字符，且以字母或数字开头")
	}
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("规则名称不能为空")
	}
	switch r.EventType {
	case EventTypeExec, EventTypePipe, EventTypeDNS, EventTypeSNI:
	default:
		return fmt.Errorf("不支持的事件类型 %q", r.EventType)
	}
	switch r.Severity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("不支持的严重级别 %q", r.Severity)
	}
	if strings.TrimSpace(r.Expression) == "" {
		return errors.New("规则表达式不能为空")
	}
	if len(r.Expression) > maxExpressionSize {
		return fmt.Errorf("规则表达式超过 %d 字节", maxExpressionSize)
	}
	if strings.TrimSpace(r.Source) == "" {
		return errors.New("规则来源不能为空")
	}
	return nil
}

// CompileRule 验证并编译一条规则。
func CompileRule(r Rule) (*vm.Program, error) {
	if err := Validate(r); err != nil {
		return nil, err
	}
	env, err := expressionEnvironment(r.EventType)
	if err != nil {
		return nil, err
	}
	program, err := expr.Compile(r.Expression, expr.Env(env), expr.AsBool(), expr.MaxNodes(256))
	if err != nil {
		return nil, fmt.Errorf("编译表达式: %w", err)
	}
	return program, nil
}

func expressionEnvironment(eventType string) (any, error) {
	switch eventType {
	case EventTypeExec:
		return ExecEvent{}, nil
	case EventTypePipe:
		return PipeEvent{}, nil
	case EventTypeDNS:
		return DNSEvent{}, nil
	case EventTypeSNI:
		return SNIEvent{}, nil
	default:
		return nil, fmt.Errorf("不支持的事件类型 %q", eventType)
	}
}

// NewEngine 验证并编译规则集。禁用规则也会校验，但不会编译或执行。
func NewEngine(rules []Rule) (*Engine, error) {
	if len(rules) > maxRules {
		return nil, fmt.Errorf("规则数量超过上限 %d", maxRules)
	}

	engine := &Engine{rules: make([]compiledRule, 0, len(rules))}
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if err := Validate(r); err != nil {
			return nil, fmt.Errorf("规则 %q: %w", r.ID, err)
		}
		if _, ok := seen[r.ID]; ok {
			return nil, fmt.Errorf("规则 ID 重复: %s", r.ID)
		}
		seen[r.ID] = struct{}{}
		if !r.Enabled {
			continue
		}
		program, err := CompileRule(r)
		if err != nil {
			return nil, fmt.Errorf("规则 %q: %w", r.ID, err)
		}
		engine.rules = append(engine.rules, compiledRule{rule: r, program: program})
	}
	return engine, nil
}

// Evaluate 对一个标准化事件执行所有适用的启用规则。
func (e *Engine) Evaluate(event Event) ([]Alert, error) {
	var (
		payload any
		pid     uint32
		ppid    uint32
		comm    string
		subject string
	)
	switch event.Type {
	case EventTypeExec:
		if event.Exec == nil {
			return nil, errors.New("EXEC 事件缺少进程数据")
		}
		payload = *event.Exec
		pid, ppid, comm = event.Exec.PID, event.Exec.PPID, event.Exec.Comm
		if len(event.Exec.Argv) > 0 {
			subject = event.Exec.Argv[0]
		}
	case EventTypePipe:
		if event.Pipe == nil {
			return nil, errors.New("PIPE 事件缺少管道数据")
		}
		payload = *event.Pipe
		pid, ppid = event.Pipe.PID, event.Pipe.PPID
		subject = fmt.Sprintf("ino=%d dir=%s len=%d", event.Pipe.Ino, event.Pipe.Dir, event.Pipe.Len)
	case EventTypeDNS:
		if event.DNS == nil {
			return nil, errors.New("DNS 事件缺少查询数据")
		}
		payload = *event.DNS
		pid, ppid, subject = event.DNS.PID, event.DNS.PPID, event.DNS.Qname
	case EventTypeSNI:
		if event.SNI == nil {
			return nil, errors.New("SNI 事件缺少 TLS 数据")
		}
		payload = *event.SNI
		pid, ppid, subject = event.SNI.PID, event.SNI.PPID, event.SNI.ServerName
	default:
		return nil, nil
	}

	var (
		alerts []Alert
		errs   []error
	)
	for _, r := range e.rules {
		if r.rule.EventType != event.Type {
			continue
		}
		result, err := expr.Run(r.program, payload)
		if err != nil {
			errs = append(errs, fmt.Errorf("评估规则 %s: %w", r.rule.ID, err))
			continue
		}
		matched, ok := result.(bool)
		if !ok {
			errs = append(errs, fmt.Errorf("评估规则 %s: 表达式结果不是 bool", r.rule.ID))
			continue
		}
		if !matched {
			continue
		}
		alerts = append(alerts, Alert{
			TimestampNS: event.TimestampNS,
			EventType:   event.Type,
			RuleID:      r.rule.ID,
			RuleName:    r.rule.Name,
			Severity:    r.rule.Severity,
			Source:      r.rule.Source,
			Author:      r.rule.Author,
			PID:         pid,
			PPID:        ppid,
			Comm:        comm,
			Subject:     subject,
		})
	}
	return alerts, errors.Join(errs...)
}
