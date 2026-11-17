ALTER TABLE rules
    DROP CONSTRAINT IF EXISTS rules_event_type_check;

ALTER TABLE rules
    ADD CONSTRAINT rules_event_type_check
    CHECK (event_type IN ('EXEC', 'PIPE', 'DNS', 'SNI'));
