package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Zakura-Lee/GenAI-Agent-Sentinel/internal/rule"
)

const ruleColumns = `id, name, description, enabled, event_type, severity, expression,
	source, source_url, upstream_id, license, author, created_at, updated_at`

// RuleStore 将规则持久化到 PostgreSQL。
type RuleStore struct {
	conn *pgx.Conn
}

// NewRuleStore 建立 PostgreSQL 连接并确认数据库可用。
func NewRuleStore(ctx context.Context, databaseURL string) (*RuleStore, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, errors.New("DATABASE_URL 未设置")
	}
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("连接 PostgreSQL: %w", err)
	}
	return &RuleStore{conn: conn}, nil
}

// Close 关闭 PostgreSQL 连接。
func (s *RuleStore) Close(ctx context.Context) error {
	if err := s.conn.Close(ctx); err != nil {
		return fmt.Errorf("关闭 PostgreSQL 连接: %w", err)
	}
	return nil
}

// Create 校验并插入一条规则。
func (s *RuleStore) Create(ctx context.Context, r rule.Rule) error {
	if _, err := rule.CompileRule(r); err != nil {
		return fmt.Errorf("校验规则 %q: %w", r.ID, err)
	}
	_, err := s.conn.Exec(ctx, `
		INSERT INTO rules (
			id, name, description, enabled, event_type, severity, expression,
			source, source_url, upstream_id, license, author
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		r.ID, r.Name, r.Description, r.Enabled, r.EventType, r.Severity, r.Expression,
		r.Source, r.SourceURL, r.UpstreamID, r.License, r.Author,
	)
	if err != nil {
		return fmt.Errorf("插入规则 %q: %w", r.ID, err)
	}
	return nil
}

// Update 校验并完整更新一条规则。
func (s *RuleStore) Update(ctx context.Context, r rule.Rule) error {
	if _, err := rule.CompileRule(r); err != nil {
		return fmt.Errorf("校验规则 %q: %w", r.ID, err)
	}
	tag, err := s.conn.Exec(ctx, `
		UPDATE rules SET
			name = $2, description = $3, enabled = $4, event_type = $5,
			severity = $6, expression = $7, source = $8, source_url = $9,
			upstream_id = $10, license = $11, author = $12, updated_at = now()
		WHERE id = $1`,
		r.ID, r.Name, r.Description, r.Enabled, r.EventType, r.Severity, r.Expression,
		r.Source, r.SourceURL, r.UpstreamID, r.License, r.Author,
	)
	if err != nil {
		return fmt.Errorf("更新规则 %q: %w", r.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("规则 %q 不存在", r.ID)
	}
	return nil
}

// Delete 删除指定规则。
func (s *RuleStore) Delete(ctx context.Context, id string) error {
	tag, err := s.conn.Exec(ctx, `DELETE FROM rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("删除规则 %q: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("规则 %q 不存在", id)
	}
	return nil
}

// Get 按 ID 获取规则。
func (s *RuleStore) Get(ctx context.Context, id string) (rule.Rule, error) {
	r, err := scanRule(s.conn.QueryRow(ctx, `SELECT `+ruleColumns+` FROM rules WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Rule{}, fmt.Errorf("规则 %q 不存在", id)
		}
		return rule.Rule{}, fmt.Errorf("读取规则 %q: %w", id, err)
	}
	return r, nil
}

// List 返回所有规则，按 ID 排序。
func (s *RuleStore) List(ctx context.Context) ([]rule.Rule, error) {
	rows, err := s.conn.Query(ctx, `SELECT `+ruleColumns+` FROM rules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("列出规则: %w", err)
	}
	defer rows.Close()
	return collectRules(rows)
}

// ListEnabled 返回所有启用规则，按 ID 排序。
func (s *RuleStore) ListEnabled(ctx context.Context) ([]rule.Rule, error) {
	rows, err := s.conn.Query(ctx, `SELECT `+ruleColumns+` FROM rules WHERE enabled = TRUE ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取启用规则: %w", err)
	}
	defer rows.Close()
	return collectRules(rows)
}

func collectRules(rows pgx.Rows) ([]rule.Rule, error) {
	rules := make([]rule.Rule, 0)
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("解析规则记录: %w", err)
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历规则记录: %w", err)
	}
	return rules, nil
}

func scanRule(row interface{ Scan(...any) error }) (rule.Rule, error) {
	var r rule.Rule
	err := row.Scan(
		&r.ID, &r.Name, &r.Description, &r.Enabled, &r.EventType, &r.Severity, &r.Expression,
		&r.Source, &r.SourceURL, &r.UpstreamID, &r.License, &r.Author, &r.CreatedAt, &r.UpdatedAt,
	)
	return r, err
}
