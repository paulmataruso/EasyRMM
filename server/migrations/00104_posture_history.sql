-- Posture history (ADR-0082, slice P4): a row each time a computer's word or
-- score changes, so the console can show how its security moved. It holds the
-- result, never the reasons. A computer's rows go with it.

-- +goose Up
CREATE TABLE posture_history (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    word        text NOT NULL CHECK (word IN ('meets', 'does not meet', 'cannot tell')),
    percent     integer CHECK (percent BETWEEN 0 AND 100),
    failing     integer NOT NULL CHECK (failing >= 0),
    cannot_tell integer NOT NULL CHECK (cannot_tell >= 0),
    -- The newest result the posture rested on; null when none.
    checked_at  timestamptz,
    recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX posture_history_device ON posture_history (device_id, recorded_at DESC, id DESC);

ALTER TABLE posture_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture_history FORCE ROW LEVEL SECURITY;
CREATE POLICY posture_history_read ON posture_history FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY posture_history_write ON posture_history FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON posture_history TO easyrmm_app;

-- +goose Down
DROP TABLE posture_history;
