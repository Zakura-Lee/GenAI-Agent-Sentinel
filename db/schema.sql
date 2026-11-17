-- ADR 日志/事件表（初始骨架，后续按需扩展）
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    source      TEXT NOT NULL,          -- 来源组件: ebpf / agent / audit
    event_type  TEXT NOT NULL,          -- 事件类型: execve / network / ...
    pid         INTEGER,
    comm        TEXT,
    detail      JSONB,
    verdict     TEXT,                   -- 规则/审计结论
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_ts   ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type);

CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    event_type  TEXT NOT NULL CHECK (event_type IN ('EXEC', 'PIPE', 'DNS', 'SNI')),
    severity    TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    expression  TEXT NOT NULL,
    source      TEXT NOT NULL,
    source_url  TEXT NOT NULL DEFAULT '',
    upstream_id TEXT NOT NULL DEFAULT '',
    license     TEXT NOT NULL DEFAULT '',
    author      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rules_enabled_event_type
    ON rules (enabled, event_type);
