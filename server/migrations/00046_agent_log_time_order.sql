-- The Logs tab reads a device's records in time order across sources, newest
-- first, with the record id breaking ties (ADR-0069, amended 2026-11-26).

-- +goose Up
CREATE INDEX agent_log_records_time_idx ON agent_log_records (device_id, logged_at DESC, id DESC);

-- +goose Down
DROP INDEX agent_log_records_time_idx;
