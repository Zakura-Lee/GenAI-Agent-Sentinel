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
