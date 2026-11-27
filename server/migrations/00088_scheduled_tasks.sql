-- Feature 11 slice 1: scheduled script jobs. Features 11 and 3 are one
-- engine: a scheduled task is an automation with a schedule trigger and one
-- step. The Scheduled tasks page is a filtered view of these rows.
--
--   automations       what to run, when, and for whom. The script is pinned by
--                     its SHA-256; the targets are a query resolved at each
--                     run; the schedule is read in the zone of the site (or
--                     the organization's sites'). It runs as its owner, whose
--                     permissions are re-checked at each run.
--   automation_runs   one row per occurrence. UNIQUE (automation_id,
--                     occurrence_key) is what keeps two servers from firing
--                     one occurrence. job_ids are the jobs the run made.

-- +goose Up
CREATE TABLE automations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid,
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    trigger_kind    text NOT NULL DEFAULT 'schedule' CHECK (trigger_kind IN ('schedule')),
    step_kind       text NOT NULL DEFAULT 'script' CHECK (step_kind IN ('script')),
    schedule        jsonb NOT NULL CHECK (jsonb_typeof(schedule) = 'object'),
    script_id       uuid NOT NULL,
    script_sha256   text NOT NULL CHECK (script_sha256 ~ '^[0-9a-f]{64}$'),
    script_args     text[] NOT NULL DEFAULT '{}',
    target_query    jsonb NOT NULL CHECK (jsonb_typeof(target_query) = 'object'),
    timezone        text NOT NULL CHECK (length(timezone) BETWEEN 1 AND 64),
    missed_run_rule text NOT NULL DEFAULT 'skip' CHECK (missed_run_rule IN ('run_asap', 'skip')),
    wait_hours      integer NOT NULL DEFAULT 24 CHECK (wait_hours BETWEEN 1 AND 168),
    owner_id        uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    state           text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'paused', 'canceled', 'completed')),
    -- The next occurrence to fire; null while paused, canceled or completed.
    next_run_at     timestamptz,
    last_run_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX automations_due_idx ON automations (next_run_at) WHERE state = 'active';
CREATE INDEX automations_org_idx ON automations (organization_id);
CREATE INDEX automations_site_idx ON automations (site_id) WHERE site_id IS NOT NULL;
CREATE TRIGGER automations_touch BEFORE UPDATE ON automations
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

CREATE TABLE automation_runs (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    automation_id  uuid NOT NULL REFERENCES automations (id) ON DELETE CASCADE,
    organization_id uuid NOT NULL,
    site_id        uuid,
    -- The scheduled instant, in UTC, as RFC 3339.
    occurrence_key text NOT NULL CHECK (length(occurrence_key) BETWEEN 1 AND 40),
    scheduled_for  timestamptz NOT NULL,
    state          text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'skipped')),
    detail         text NOT NULL DEFAULT '' CHECK (length(detail) <= 2000),
    started_at     timestamptz,
    completed_at   timestamptz,
    job_ids        uuid[] NOT NULL DEFAULT '{}',
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (automation_id, occurrence_key)
);
CREATE INDEX automation_runs_automation_idx ON automation_runs (automation_id, scheduled_for DESC);
CREATE INDEX automation_runs_open_idx ON automation_runs (created_at) WHERE state IN ('pending', 'running');
CREATE INDEX automation_runs_org_idx ON automation_runs (organization_id);

ALTER TABLE automations ENABLE ROW LEVEL SECURITY;
ALTER TABLE automations FORCE ROW LEVEL SECURITY;
CREATE POLICY automations_tenant ON automations
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

ALTER TABLE automation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE automation_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY automation_runs_tenant ON automation_runs
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

GRANT SELECT, INSERT, UPDATE, DELETE ON automations, automation_runs TO easyrmm_app;

-- +goose Down
DROP TABLE automation_runs;
DROP TABLE automations;
