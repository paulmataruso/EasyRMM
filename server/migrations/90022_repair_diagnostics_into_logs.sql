-- A repair step's diagnostics live in the device's agent log (ADR-0069,
-- amended 2026-11-26), where the Logs tab shows them with the other sources
-- and the log retention applies. What repairs hold now moves there, one record
-- per line, and the column goes.

-- +goose Up
INSERT INTO agent_log_records (device_id, seq, source, logged_at, level, message, attrs)
SELECT r.device_id, -1, 'easypatch', coalesce(r.ended_at, r.started_at), 'info', left(l.line, 16000),
       jsonb_build_object('repair', r.id::text, 'target', r.target)
FROM agent_repairs r
CROSS JOIN LATERAL (SELECT line FROM regexp_split_to_table(r.diagnostics, E'\r?\n') WITH ORDINALITY AS t(line, n)
                    WHERE btrim(line) <> '' ORDER BY n) l
WHERE r.diagnostics <> '';
ALTER TABLE agent_repairs DROP COLUMN diagnostics;

-- +goose Down
-- The lines stay in the agent log; the column returns empty.
ALTER TABLE agent_repairs
    ADD COLUMN diagnostics text NOT NULL DEFAULT '' CHECK (octet_length(diagnostics) <= 262144);
