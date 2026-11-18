-- Scripts and jobs (ADR-0017): the script library, jobs that run a script
-- on devices, and one run per device with its output.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Script library
-- ---------------------------------------------------------------------------

-- A script belongs to the shared library (no organization), an organization,
-- or one of its sites.
CREATE TABLE scripts (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid REFERENCES organizations (id) ON DELETE CASCADE,
    site_id          uuid,
    name             text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    description      text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    shell            text NOT NULL CHECK (shell IN ('sh', 'bash', 'python3')),
    body             text NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 65536),
    timeout_seconds  integer NOT NULL DEFAULT 300 CHECK (timeout_seconds BETWEEN 1 AND 14400),
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (site_id IS NULL OR organization_id IS NOT NULL),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX scripts_name_key ON scripts (organization_id, site_id, lower(name)) NULLS NOT DISTINCT;
CREATE INDEX scripts_site_idx ON scripts (site_id) WHERE site_id IS NOT NULL;
-- Only edits count as updates: deleting the user who wrote a script sets
-- created_by and updated_by to NULL and must not make it look changed.
CREATE TRIGGER scripts_touch BEFORE UPDATE OF name, description, shell, body, timeout_seconds ON scripts
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- Everyone reads the shared library; an organization's scripts are read in
-- the organization and its sites; a site's scripts in that site. Writing
-- needs the level itself: the platform, the whole organization, or the site.
ALTER TABLE scripts ENABLE ROW LEVEL SECURITY;
ALTER TABLE scripts FORCE ROW LEVEL SECURITY;
CREATE POLICY scripts_read ON scripts FOR SELECT USING (
    easyrmm_scope_all()
    OR organization_id IS NULL
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR (site_id IS NULL AND organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_read_orgs')))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
);
CREATE POLICY scripts_insert ON scripts FOR INSERT WITH CHECK (
    easyrmm_scope_all()
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
);
CREATE POLICY scripts_update ON scripts FOR UPDATE
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY scripts_delete ON scripts FOR DELETE USING (
    easyrmm_scope_all()
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
);

-- ---------------------------------------------------------------------------
-- Jobs and runs
-- ---------------------------------------------------------------------------

-- A job runs a snapshot of a script on devices. It spans tenants when its
-- devices do, so it has no organization of its own: it is visible through
-- the runs a caller can see.
CREATE TABLE jobs (
    id                uuid PRIMARY KEY,
    script_id         uuid REFERENCES scripts (id) ON DELETE SET NULL,
    script_name       text NOT NULL CHECK (length(script_name) BETWEEN 1 AND 200),
    shell             text NOT NULL CHECK (shell IN ('sh', 'bash', 'python3')),
    body              text NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 65536),
    body_sha256       bytea NOT NULL CHECK (length(body_sha256) = 32),
    args              text[] NOT NULL DEFAULT '{}'
                      CHECK (cardinality(args) <= 32 AND octet_length(array_to_string(args, '')) <= 32768),
    timeout_seconds   integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 14400),
    expires_at        timestamptz NOT NULL,
    created_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_label  text NOT NULL DEFAULT '' CHECK (length(created_by_label) <= 320),
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX jobs_created_idx ON jobs (created_at DESC);
CREATE INDEX jobs_script_idx ON jobs (script_id) WHERE script_id IS NOT NULL;

-- One device's part of a job. Output is kept as UTF-8 text: the first and
-- last 128 KiB of each stream, with a marker where it was cut.
CREATE TABLE job_runs (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id               uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    organization_id      uuid NOT NULL,
    site_id              uuid NOT NULL,
    device_id            uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    status               text NOT NULL DEFAULT 'queued' CHECK (status IN
                         ('queued', 'sent', 'running', 'succeeded', 'failed', 'timed_out', 'canceled', 'expired', 'lost')),
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,
    sent_at              timestamptz,
    deliveries           integer NOT NULL DEFAULT 0 CHECK (deliveries >= 0),
    started_at           timestamptz,
    deadline_at          timestamptz,
    finished_at          timestamptz,
    exit_code            integer,
    stdout               text NOT NULL DEFAULT '' CHECK (octet_length(stdout) <= 263168),
    stderr               text NOT NULL DEFAULT '' CHECK (octet_length(stderr) <= 263168),
    stdout_truncated     boolean NOT NULL DEFAULT false,
    stderr_truncated     boolean NOT NULL DEFAULT false,
    error                text NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    cancel_requested_at  timestamptz,
    canceled_by          uuid REFERENCES users (id) ON DELETE SET NULL,
    cancel_sent_at       timestamptz,
    UNIQUE (job_id, device_id),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE,
    CHECK ((status IN ('queued', 'sent', 'running')) = (finished_at IS NULL)),
    CHECK (status <> 'running' OR (started_at IS NOT NULL AND deadline_at IS NOT NULL))
);
CREATE INDEX job_runs_device_idx ON job_runs (device_id, created_at DESC);
CREATE INDEX job_runs_open_idx ON job_runs (device_id, created_at) WHERE status IN ('queued', 'sent', 'running');
CREATE INDEX job_runs_expiry_idx ON job_runs (expires_at) WHERE status IN ('queued', 'sent');
CREATE INDEX job_runs_deadline_idx ON job_runs (deadline_at) WHERE status = 'running';
CREATE INDEX job_runs_org_idx ON job_runs (organization_id);
CREATE INDEX job_runs_site_idx ON job_runs (site_id);

ALTER TABLE job_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY job_runs_tenant ON job_runs
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );

-- A job is visible through its visible runs (the subquery is itself under
-- job_runs' policy). It is written once, when it is created, and its runs
-- follow in the same transaction; only retention removes it.
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY jobs_read ON jobs FOR SELECT USING (
    easyrmm_scope_all() OR EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = jobs.id)
);
CREATE POLICY jobs_insert ON jobs FOR INSERT WITH CHECK (true);
CREATE POLICY jobs_delete ON jobs FOR DELETE USING (easyrmm_scope_all());

GRANT SELECT, INSERT, UPDATE, DELETE ON scripts, job_runs TO easyrmm_app;
GRANT SELECT, INSERT, DELETE ON jobs TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS job_runs, jobs, scripts;
