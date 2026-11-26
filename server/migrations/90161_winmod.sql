-- The winmod job kind (ADR-0073, slice 5): one kind for every Windows
-- management module's fixed actions. The job row keeps the module, action,
-- version, the validated parameters without secrets (jobs.params), and the
-- pinned script hash; a secret is sealed in its own short-lived row and put
-- into the params only when the job is delivered. The typed result of a run
-- is kept in its own table, and the jobs are hidden from the Jobs list.

-- +goose Up
ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check;
ALTER TABLE jobs
    ADD COLUMN winmod jsonb,
    ADD COLUMN hidden boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening', 'winmod')),
    ADD CONSTRAINT jobs_winmod_kind CHECK ((kind = 'winmod') = (winmod IS NOT NULL)),
    ADD CONSTRAINT jobs_winmod_object CHECK (winmod IS NULL OR jsonb_typeof(winmod) = 'object'),
    ADD CONSTRAINT jobs_winmod_hidden CHECK (kind <> 'winmod' OR hidden);

-- 00028 grants the server's role every column but the arguments, by name.
GRANT SELECT (winmod, hidden) ON jobs TO easyrmm_app;

-- The retention sweep of winmod jobs finds them by kind and age.
CREATE INDEX jobs_kind_created_idx ON jobs (kind, created_at);

-- Secrets of a winmod job, sealed with the server key (AAD
-- easyrmm:winmod:<job>:<name>). Read and deleted at delivery, or removed at
-- expiry; written and read with the system scope only.
CREATE TABLE winmod_job_secrets (
    job_id     uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (name ~ '^[A-Za-z][A-Za-z0-9_]{0,63}$'),
    sealed     text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (job_id, name)
);
CREATE INDEX winmod_job_secrets_expires_idx ON winmod_job_secrets (expires_at);
ALTER TABLE winmod_job_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE winmod_job_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY winmod_job_secrets_system ON winmod_job_secrets FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
-- The request that creates the job seals its secrets in the same transaction,
-- under the caller's scope: it may add a row for a job it can see, never read one.
CREATE POLICY winmod_job_secrets_create ON winmod_job_secrets FOR INSERT
    WITH CHECK (EXISTS (SELECT 1 FROM jobs j WHERE j.id = job_id AND j.kind = 'winmod'));
GRANT SELECT, INSERT, DELETE ON winmod_job_secrets TO easyrmm_app;

-- The typed result of a run: the decoded value, not the text. Written with
-- the system scope at result time; read through the organization's scope,
-- after the caller's permission is checked in the server. Removed with its
-- run.
CREATE TABLE winmod_run_results (
    run_id          uuid PRIMARY KEY REFERENCES job_runs (id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    module          text NOT NULL,
    action          text NOT NULL,
    version         integer NOT NULL,
    ok              boolean NOT NULL,
    sensitive       boolean NOT NULL DEFAULT false,
    data            jsonb,
    error           jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(data::text) <= 65536)
);
CREATE INDEX winmod_run_results_device_idx ON winmod_run_results (device_id, module, action, created_at DESC);
ALTER TABLE winmod_run_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE winmod_run_results FORCE ROW LEVEL SECURITY;
CREATE POLICY winmod_run_results_read ON winmod_run_results FOR SELECT
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY winmod_run_results_write ON winmod_run_results FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, DELETE ON winmod_run_results TO easyrmm_app;

-- +goose Down
DROP TABLE winmod_run_results;
DROP TABLE winmod_job_secrets;
DROP INDEX jobs_kind_created_idx;
-- jobs forces row-level security, on its owner too.
SELECT set_config('easyrmm.scope_all', 'on', true);
DELETE FROM jobs WHERE kind = 'winmod';
ALTER TABLE jobs DROP CONSTRAINT jobs_winmod_hidden,
    DROP CONSTRAINT jobs_winmod_object,
    DROP CONSTRAINT jobs_winmod_kind,
    DROP CONSTRAINT jobs_kind_check,
    DROP COLUMN hidden,
    DROP COLUMN winmod,
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening'));
