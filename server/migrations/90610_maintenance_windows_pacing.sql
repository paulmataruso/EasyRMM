-- Feature 11 slice 2: maintenance windows and pacing for scheduled tasks.
--
--   site_maintenance_windows.purpose  ADR-0053's windows gain a purpose: they
--                     hold notifications (what every window did until now),
--                     allow scheduled tasks, or both (feature plan F4).
--   automations       window_id: the task fires only while that window is
--                     open. stagger_minutes: the devices of a site start
--                     spread over this long, so a site never restarts at
--                     once. only_if_online: offline devices get no job.
--   automation_run_batches  the later starts of a staggered run.

-- +goose Up
ALTER TABLE site_maintenance_windows
    ADD COLUMN purpose text NOT NULL DEFAULT 'notifications' CHECK (purpose IN ('notifications', 'tasks', 'both'));

ALTER TABLE automations
    ADD COLUMN window_id uuid REFERENCES site_maintenance_windows (id) ON DELETE SET NULL,
    ADD COLUMN stagger_minutes integer NOT NULL DEFAULT 0 CHECK (stagger_minutes BETWEEN 0 AND 1440),
    ADD COLUMN only_if_online boolean NOT NULL DEFAULT false;
CREATE INDEX automations_window_idx ON automations (window_id) WHERE window_id IS NOT NULL;

CREATE TABLE automation_run_batches (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          uuid NOT NULL REFERENCES automation_runs (id) ON DELETE CASCADE,
    automation_id   uuid NOT NULL REFERENCES automations (id) ON DELETE CASCADE,
    organization_id uuid NOT NULL,
    site_id         uuid,
    due_at          timestamptz NOT NULL,
    device_ids      uuid[] NOT NULL CHECK (cardinality(device_ids) BETWEEN 1 AND 500),
    state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'running', 'done', 'failed', 'skipped')),
    detail          text NOT NULL DEFAULT '' CHECK (length(detail) <= 2000),
    job_id          uuid,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX automation_run_batches_due_idx ON automation_run_batches (due_at) WHERE state = 'pending';
CREATE INDEX automation_run_batches_run_idx ON automation_run_batches (run_id);

ALTER TABLE automation_run_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE automation_run_batches FORCE ROW LEVEL SECURITY;
CREATE POLICY automation_run_batches_tenant ON automation_run_batches
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
GRANT SELECT, INSERT, UPDATE, DELETE ON automation_run_batches TO easyrmm_app;

-- +goose Down
DROP TABLE automation_run_batches;
ALTER TABLE automations DROP COLUMN only_if_online, DROP COLUMN stagger_minutes, DROP COLUMN window_id;
ALTER TABLE site_maintenance_windows DROP COLUMN purpose;
