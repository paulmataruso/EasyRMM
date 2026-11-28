-- Endpoint security posture, slices P2 and P3 (ADR-0082). The disk encryption
-- control needs to tell "the agent reported no encrypted volume" from "the agent
-- has not reported yet". device_encrypted_volumes keeps only the volumes found,
-- so a report with none leaves no row to say a report was made. This keeps the
-- time of the newest volume report of each kind for each device. It holds no
-- volume, protector or key: only the fact and the time of a report that was
-- already being made.

-- +goose Up
CREATE TABLE device_volume_reports (
    device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('bitlocker', 'luks')),
    reported_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, kind)
);

ALTER TABLE device_volume_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_volume_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY device_volume_reports_read ON device_volume_reports FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_volume_reports_write ON device_volume_reports FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_volume_reports TO easyrmm_app;

-- +goose Down
DROP TABLE device_volume_reports;
