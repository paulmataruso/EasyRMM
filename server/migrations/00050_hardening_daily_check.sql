-- The daily hardening check (ADR-0054, W2, and its amendments to ADR-0017):
-- jobs gain a batch id, which the day's many small check jobs of an
-- organization share and by which Jobs groups them; such jobs are removed
-- after seven days.

-- +goose Up
ALTER TABLE jobs ADD COLUMN batch_id uuid;
CREATE INDEX jobs_batch ON jobs (batch_id) WHERE batch_id IS NOT NULL;
-- The runtime role reads jobs by column (ADR-0063).
GRANT SELECT (batch_id) ON jobs TO easyrmm_app;

-- +goose Down
DROP INDEX jobs_batch;
ALTER TABLE jobs DROP COLUMN batch_id;
