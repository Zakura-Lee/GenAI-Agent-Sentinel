package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/rule"
	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/store"
)

func runRules(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: adr rules <list|add|update|delete>")
	}

	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("rules list 不接受参数")
		}
		return listRules()
	case "add":
		return addRule(args[1:])
	case "update":
		return updateRule(args[1:])
	case "delete":
		return deleteRule(args[1:])
	default:
		return fmt.Errorf("未知规则命令 %q；用法: adr rules <list|add|update|delete>", args[0])
	}
}

func openRuleStore(ctx context.Context) (*store.RuleStore, error) {
	ruleStore, err := store.NewRuleStore(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, err
	}
	return ruleStore, nil
}

func closeRuleStore(ruleStore *store.RuleStore) {
	if err := ruleStore.Close(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func listRules() error {
	ctx := context.Background()
	ruleStore, err := openRuleStore(ctx)
	if err != nil {
		return err
	}
	defer closeRuleStore(ruleStore)

	rules, err := ruleStore.List(ctx)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		fmt.Println("没有规则")
		return nil
	}
	for _, r := range rules {
		fmt.Printf("%s\t%s\t%s\t%t\t%s\t%s\n",
			r.ID, r.EventType, r.Severity, r.Enabled, r.Name, r.Expression)
	}
	return nil
}

func addRule(args []string) error {
	fs := flag.NewFlagSet("rules add", flag.ContinueOnError)
	var r rule.Rule
	fs.StringVar(&r.ID, "id", "", "规则 ID")
	fs.StringVar(&r.Name, "name", "", "规则名称")
	fs.StringVar(&r.Description, "description", "", "规则说明")
	fs.StringVar(&r.EventType, "event-type", rule.EventTypeExec, "事件类型：EXEC、PIPE、DNS、SNI、FORK、EXIT、FILE、NET")
	fs.StringVar(&r.Severity, "severity", "medium", "严重级别：low、medium、high、critical")
	fs.StringVar(&r.Expression, "expression", "", "expr 表达式")
	fs.StringVar(&r.Source, "source", "local", "规则来源")
	fs.StringVar(&r.SourceURL, "source-url", "", "上游规则链接")
	fs.StringVar(&r.UpstreamID, "upstream-id", "", "上游规则 ID")
	fs.StringVar(&r.License, "license", "", "规则许可证")
	fs.StringVar(&r.Author, "author", "", "规则作者")
	fs.BoolVar(&r.Enabled, "enabled", true, "是否启用规则")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("rules add 不接受位置参数")
	}

	ctx := context.Background()
	ruleStore, err := openRuleStore(ctx)
	if err != nil {
		return err
	}
	defer closeRuleStore(ruleStore)
	if err := ruleStore.Create(ctx, r); err != nil {
		return err
	}
	fmt.Printf("已添加规则 %s\n", r.ID)
	return nil
}

func updateRule(args []string) error {
	fs := flag.NewFlagSet("rules update", flag.ContinueOnError)
	id := fs.String("id", "", "要更新的规则 ID")
	name := fs.String("name", "", "规则名称")
	description := fs.String("description", "", "规则说明")
	eventType := fs.String("event-type", "", "事件类型：EXEC、PIPE、DNS、SNI、FORK、EXIT、FILE、NET")
	severity := fs.String("severity", "", "严重级别：low、medium、high、critical")
	expression := fs.String("expression", "", "expr 表达式")
	source := fs.String("source", "", "规则来源")
	sourceURL := fs.String("source-url", "", "上游规则链接")
	upstreamID := fs.String("upstream-id", "", "上游规则 ID")
	license := fs.String("license", "", "规则许可证")
	author := fs.String("author", "", "规则作者")
	enabled := fs.String("enabled", "", "是否启用：true 或 false")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("rules update 不接受位置参数")
	}
	if *id == "" {
		return errors.New("必须指定 --id")
	}

	ctx := context.Background()
	ruleStore, err := openRuleStore(ctx)
	if err != nil {
		return err
	}
	defer closeRuleStore(ruleStore)

	r, err := ruleStore.Get(ctx, *id)
	if err != nil {
		return err
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name":
			r.Name = *name
		case "description":
			r.Description = *description
		case "event-type":
			r.EventType = *eventType
		case "severity":
			r.Severity = *severity
		case "expression":
			r.Expression = *expression
		case "source":
			r.Source = *source
		case "source-url":
			r.SourceURL = *sourceURL
		case "upstream-id":
			r.UpstreamID = *upstreamID
		case "license":
			r.License = *license
		case "author":
			r.Author = *author
		case "enabled":
			value, parseErr := strconv.ParseBool(*enabled)
			if parseErr != nil {
				err = fmt.Errorf("解析 --enabled: %w", parseErr)
				return
			}
			r.Enabled = value
		}
	})
	if err != nil {
		return err
	}
	if err := ruleStore.Update(ctx, r); err != nil {
		return err
	}
	fmt.Printf("已更新规则 %s\n", r.ID)
	return nil
}

func deleteRule(args []string) error {
	fs := flag.NewFlagSet("rules delete", flag.ContinueOnError)
	id := fs.String("id", "", "要删除的规则 ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("rules delete 不接受位置参数")
	}
	if *id == "" {
		return errors.New("必须指定 --id")
	}

	ctx := context.Background()
	ruleStore, err := openRuleStore(ctx)
	if err != nil {
		return err
	}
	defer closeRuleStore(ruleStore)
	if err := ruleStore.Delete(ctx, *id); err != nil {
		return err
	}
	fmt.Printf("已删除规则 %s\n", *id)
	return nil
}
