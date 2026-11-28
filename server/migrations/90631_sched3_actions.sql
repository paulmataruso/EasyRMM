-- Feature 11 slice 3: more actions for scheduled tasks.
--
--   jobs.kind 'maintenance'  restart, shutdown, and service start, stop or
--                     restart: fixed scripts of EasyRMM's own, one per
--                     platform. jobs.maintenance holds the action.
--   automations       step_kind gains software, restart, shutdown and
--                     service; step holds what the step needs (a package, a
--                     service name). A script step still pins a library
--                     script; the other steps have none.
--   device_expected_offline  a restart or shutdown that succeeded says the
--                     device will be offline for a while: monitoring does not
--                     raise offline, remote_down or agent_silent alerts for
--                     it until until_at.

-- +goose Up
ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening', 'winmod', 'registry_query', 'registry_change', 'eventlog_query', 'maintenance')),
    ADD COLUMN maintenance jsonb,
    ADD CONSTRAINT jobs_maintenance_kind CHECK ((kind = 'maintenance') = (maintenance IS NOT NULL));

ALTER TABLE automations
    DROP CONSTRAINT automations_step_kind_check,
    ADD CONSTRAINT automations_step_kind_check CHECK (step_kind IN ('script', 'software', 'restart', 'shutdown', 'service')),
    ALTER COLUMN script_id DROP NOT NULL,
    ALTER COLUMN script_sha256 DROP NOT NULL,
    ADD COLUMN step jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(step) = 'object'),
    ADD CONSTRAINT automations_script_step CHECK ((step_kind = 'script') = (script_id IS NOT NULL AND script_sha256 IS NOT NULL));

GRANT SELECT (maintenance) ON jobs TO easyrmm_app;

CREATE TABLE device_expected_offline (
    device_id  uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    until_at   timestamptz NOT NULL,
    reason     text NOT NULL DEFAULT '' CHECK (length(reason) <= 200),
    job_id     uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_expected_offline_until_idx ON device_expected_offline (until_at);

ALTER TABLE device_expected_offline ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_expected_offline FORCE ROW LEVEL SECURITY;
CREATE POLICY device_expected_offline_read ON device_expected_offline FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_expected_offline_write ON device_expected_offline FOR ALL
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id))
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON device_expected_offline TO easyrmm_app;

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
DROP TABLE device_expected_offline;
DELETE FROM automations WHERE step_kind <> 'script';
ALTER TABLE automations
    DROP CONSTRAINT automations_script_step,
    DROP COLUMN step,
    ALTER COLUMN script_sha256 SET NOT NULL,
    ALTER COLUMN script_id SET NOT NULL,
    DROP CONSTRAINT automations_step_kind_check,
    ADD CONSTRAINT automations_step_kind_check CHECK (step_kind IN ('script'));
DELETE FROM jobs WHERE kind = 'maintenance';
ALTER TABLE jobs
    DROP CONSTRAINT jobs_maintenance_kind,
    DROP COLUMN maintenance,
    DROP CONSTRAINT jobs_kind_check,
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening', 'winmod', 'registry_query', 'registry_change', 'eventlog_query'));
