CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    event_type  TEXT NOT NULL CHECK (event_type = 'EXEC'),
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
