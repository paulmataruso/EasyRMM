-- Windows module alerts (ADR-0073, slice 7). Module alert kinds come from a
-- registry in the server, not from a list in the database, so the kind checks
-- on alert_policies and alerts become a shape check, and the server validates
-- the name against the registry. A policy may be a module's default: owned by
-- the module, one per organization and key, created once and only turned on
-- or off by users. windows_module_conditions remembers since when a grace
-- condition has held. New resolutions: module_off, role_removed, not_applicable.

-- +goose Up
ALTER TABLE alert_policies
    DROP CONSTRAINT alert_policies_kind_check,
    DROP CONSTRAINT alert_policies_threshold_needed,
    ADD CONSTRAINT alert_policies_kind_check CHECK (kind ~ '^[a-z][a-z0-9_]{1,39}$'),
    -- Thresholds of the built-in kinds are unchanged; a module kind's
    -- threshold is checked by the registry.
    ADD CONSTRAINT alert_policies_threshold_needed CHECK (CASE
        WHEN kind IN ('offline', 'remote_down', 'agent_silent') THEN threshold IS NULL
        WHEN kind = 'disk_health' AND check_name = 'failing' THEN threshold IS NULL
        WHEN kind = 'disk_health' AND check_name = 'temperature' THEN true
        WHEN kind IN ('cpu', 'memory', 'disk', 'disk_health') THEN threshold IS NOT NULL
        ELSE true END),
    ADD COLUMN module text CHECK (module IN ('defender', 'active_directory', 'certificate_authority',
                                             'dns', 'dhcp', 'file_shares', 'print', 'windows_backup')),
    ADD COLUMN default_key text CHECK (length(default_key) BETWEEN 1 AND 100),
    ADD CONSTRAINT alert_policies_default_shape CHECK ((default_key IS NULL) = (module IS NULL)),
    ADD CONSTRAINT alert_policies_default_org CHECK (default_key IS NULL OR (organization_id IS NOT NULL AND site_id IS NULL));
CREATE UNIQUE INDEX alert_policies_default_key ON alert_policies (organization_id, module, default_key) WHERE default_key IS NOT NULL;

ALTER TABLE alerts
    DROP CONSTRAINT alerts_kind_check,
    DROP CONSTRAINT alerts_resolution_check,
    ADD CONSTRAINT alerts_kind_check CHECK (kind ~ '^[a-z][a-z0-9_]{1,39}$'),
    ADD CONSTRAINT alerts_resolution_check CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off',
        'policy_changed', 'policy_deleted', 'subject_gone', 'module_off', 'role_removed', 'not_applicable'));

-- Since when a policy's condition has held on a device, for the kinds that
-- wait out a grace period. System scope only; it follows its device.
CREATE TABLE windows_module_conditions (
    policy_id uuid NOT NULL REFERENCES alert_policies (id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    since     timestamptz NOT NULL,
    PRIMARY KEY (policy_id, device_id)
);
CREATE INDEX windows_module_conditions_device_idx ON windows_module_conditions (device_id);
ALTER TABLE windows_module_conditions ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_module_conditions FORCE ROW LEVEL SECURITY;
CREATE POLICY windows_module_conditions_system ON windows_module_conditions FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON windows_module_conditions TO easyrmm_app;

-- +goose Down
DROP TABLE windows_module_conditions;
-- alerts and alert_policies force row-level security, on their owner too.
SELECT set_config('easyrmm.scope_all', 'on', true);
DELETE FROM alerts WHERE kind NOT IN ('offline', 'cpu', 'memory', 'disk', 'disk_health', 'remote_down', 'agent_silent', 'repair_failed');
DELETE FROM alert_policies WHERE kind NOT IN ('offline', 'cpu', 'memory', 'disk', 'disk_health', 'remote_down', 'agent_silent');
UPDATE alerts SET resolution = 'cleared' WHERE resolution IN ('module_off', 'role_removed', 'not_applicable');
DROP INDEX alert_policies_default_key;
ALTER TABLE alerts
    DROP CONSTRAINT alerts_resolution_check,
    DROP CONSTRAINT alerts_kind_check,
    ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health', 'remote_down', 'agent_silent', 'repair_failed')),
    ADD CONSTRAINT alerts_resolution_check CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off',
        'policy_changed', 'policy_deleted', 'subject_gone'));
ALTER TABLE alert_policies
    DROP CONSTRAINT alert_policies_default_org,
    DROP CONSTRAINT alert_policies_default_shape,
    DROP COLUMN default_key,
    DROP COLUMN module,
    DROP CONSTRAINT alert_policies_threshold_needed,
    DROP CONSTRAINT alert_policies_kind_check,
    ADD CONSTRAINT alert_policies_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health', 'remote_down', 'agent_silent')),
    ADD CONSTRAINT alert_policies_threshold_needed CHECK (CASE
        WHEN kind IN ('offline', 'remote_down', 'agent_silent') THEN threshold IS NULL
        WHEN check_name = 'failing' THEN threshold IS NULL
        WHEN check_name = 'temperature' THEN true
        ELSE threshold IS NOT NULL END);
