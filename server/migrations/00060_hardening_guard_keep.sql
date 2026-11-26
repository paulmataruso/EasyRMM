-- The console's Keep button (ADR-0054, W3): when someone asked to keep an
-- armed guard's change, the server queues a fresh confirm job and records
-- when, so the console can say it is waiting for the agent.

-- +goose Up
ALTER TABLE hardening_guards ADD COLUMN keep_requested_at timestamptz;

-- +goose Down
ALTER TABLE hardening_guards DROP COLUMN keep_requested_at;
