-- Hardening Linux computers (ADR-0051): jobs that run EasyRMM's own
-- hardening script with the mode, modules and options as arguments, and
-- what the last check found on each device.

-- +goose Up

-- hardening holds {"mode","modules","options"} for people and filters to
-- read; the job's body and arguments are what runs. A job's copy of a
-- script may be larger than a library script (64 KiB): EasyRMM's own
-- hardening script is. Eight of them still fit the agent's 8 MiB limit on
-- one poll answer.
ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check;
ALTER TABLE jobs DROP CONSTRAINT jobs_body_check;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_body_check CHECK (octet_length(body) BETWEEN 1 AND 524288),
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening')),
    ADD COLUMN hardening jsonb,
    ADD CONSTRAINT jobs_hardening_kind CHECK ((kind = 'hardening') = (hardening IS NOT NULL)),
    ADD CONSTRAINT jobs_hardening_object CHECK (hardening IS NULL OR jsonb_typeof(hardening) = 'object');

-- The platform as the last hardening job on a device read it, and whether
-- the script supports it there.
CREATE TABLE device_hardening_checks (
    device_id  uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    platform   jsonb NOT NULL CHECK (jsonb_typeof(platform) = 'object'),
    job_id     uuid REFERENCES jobs (id) ON DELETE SET NULL,
    checked_at timestamptz NOT NULL
);

-- Each module's state as the last job that covered it found it: what is
-- missing, what apply would change, and for the firewall its ports.
CREATE TABLE device_hardening (
    device_id  uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    module     text NOT NULL CHECK (module ~ '^[a-z][a-z0-9-]{0,31}$'),
    state      text NOT NULL CHECK (state IN ('in_place', 'partly', 'not_in_place', 'not_applicable',
                   'managed_elsewhere', 'not_supported', 'half_applied', 'failed')),
    detail     jsonb NOT NULL CHECK (jsonb_typeof(detail) = 'object'),
    job_id     uuid REFERENCES jobs (id) ON DELETE SET NULL,
    checked_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, module)
);
CREATE INDEX device_hardening_state ON device_hardening (module, state);

-- Rows are visible through their device, whose own policy decides; job
-- results are written with the system scope.
ALTER TABLE device_hardening_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_hardening_checks FORCE ROW LEVEL SECURITY;
CREATE POLICY device_hardening_checks_read ON device_hardening_checks FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_hardening_checks_write ON device_hardening_checks FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_hardening_checks TO easyrmm_app;

ALTER TABLE device_hardening ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_hardening FORCE ROW LEVEL SECURITY;
CREATE POLICY device_hardening_read ON device_hardening FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_hardening_write ON device_hardening FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_hardening TO easyrmm_app;

-- +goose Down
DROP TABLE device_hardening;
DROP TABLE device_hardening_checks;
-- jobs forces row-level security, on its owner too.
SELECT set_config('easyrmm.scope_all', 'on', true);
DELETE FROM jobs WHERE kind = 'hardening';
ALTER TABLE jobs
    DROP CONSTRAINT jobs_hardening_object,
    DROP CONSTRAINT jobs_hardening_kind,
    DROP COLUMN hardening,
    DROP CONSTRAINT jobs_kind_check,
    DROP CONSTRAINT jobs_body_check;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software')),
    ADD CONSTRAINT jobs_body_check CHECK (octet_length(body) BETWEEN 1 AND 65536);
