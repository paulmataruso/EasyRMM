-- Posture P5 (ADR-0082): the log collection dimension. The log store is a
-- database of its own (ADR-0060), which a posture query in the main database
-- cannot join, so the server keeps here the one fact posture needs: when each
-- device last had collected log blocks accepted. It is written when a batch is
-- stored and read like any other posture input.

-- +goose Up
CREATE TABLE posture_log_collection (
    device_id         uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    first_received_at timestamptz NOT NULL,
    last_received_at  timestamptz NOT NULL
);

ALTER TABLE posture_log_collection ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture_log_collection FORCE ROW LEVEL SECURITY;
CREATE POLICY posture_log_collection_read ON posture_log_collection FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY posture_log_collection_write ON posture_log_collection FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON posture_log_collection TO easyrmm_app;

-- +goose Down
DROP TABLE posture_log_collection;
