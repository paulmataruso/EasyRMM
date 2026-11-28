-- Quick Assist limits (ADR-0080): idle limit, one session extension, stale permanent links.

-- +goose Up
ALTER TABLE quick_assist_sessions ADD COLUMN last_activity_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE quick_assist_sessions ADD COLUMN extended boolean NOT NULL DEFAULT false;
ALTER TABLE quick_assist_links ADD COLUMN stale boolean NOT NULL DEFAULT false;

-- Backfill: set last_activity_at to the most recent meaningful timestamp.
UPDATE quick_assist_sessions SET last_activity_at = COALESCE(accepted_at, requested_at);

-- +goose Down
ALTER TABLE quick_assist_links DROP COLUMN stale;
ALTER TABLE quick_assist_sessions DROP COLUMN extended;
ALTER TABLE quick_assist_sessions DROP COLUMN last_activity_at;
