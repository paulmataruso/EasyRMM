-- Alert suppressions (ADR-0085): a user may suppress a kind of alert on a
-- device, so the monitoring system does not open new ones and existing ones
-- resolve as suppressed. Suppressions follow the device.

-- +goose Up

CREATE TABLE alert_suppressions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id        uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    kind             text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{1,39}$'),
    subject          text NOT NULL DEFAULT '',
    reason           text NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_label text NOT NULL DEFAULT '' CHECK (length(created_by_label) <= 320),
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (device_id, kind, subject)
);
CREATE INDEX alert_suppressions_device_idx ON alert_suppressions (device_id);

ALTER TABLE alert_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_suppressions FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_suppressions_read ON alert_suppressions FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY alert_suppressions_write ON alert_suppressions FOR ALL
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id))
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));

ALTER TABLE alerts
    DROP CONSTRAINT alerts_resolution_check,
    ADD CONSTRAINT alerts_resolution_check CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off',
        'policy_changed', 'policy_deleted', 'subject_gone', 'module_off', 'role_removed', 'not_applicable', 'suppressed'));

GRANT SELECT, INSERT, UPDATE, DELETE ON alert_suppressions TO easyrmm_app;

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
ALTER TABLE alerts
    DROP CONSTRAINT alerts_resolution_check,
    ADD CONSTRAINT alerts_resolution_check CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off',
        'policy_changed', 'policy_deleted', 'subject_gone', 'module_off', 'role_removed', 'not_applicable'));
DROP TABLE IF EXISTS alert_suppressions;
