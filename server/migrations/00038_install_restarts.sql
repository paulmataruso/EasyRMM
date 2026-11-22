-- Restarts after an install (ADR-0030, amended 2026-11-22): an install can
-- ask to restart each device once it has finished, only if the updates need
-- it or always. The patching engine has no such option, so EasyRMM watches
-- the install job and asks the engine for the restart itself when the job
-- ends, or earlier when the install waits for a restart to go on. The
-- choice is kept here, so that it outlives a restart of EasyRMM's server.

-- +goose Up

-- One device's install asked to restart it afterwards.
CREATE TABLE easypatch_install_restarts (
    -- The device's last install job of the request.
    install_job_id        uuid PRIMARY KEY,
    -- Each of its install jobs, that one included: more than one when the
    -- device had more updates than the engine takes in one job (500), so
    -- they were split. The device restarts once they have all completed.
    install_job_ids       uuid[] NOT NULL CHECK (cardinality(install_job_ids) >= 1),
    device_id             uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- The device's endpoint and organization in the engine when the install
    -- was asked for: the restart goes to them.
    endpoint_id           uuid NOT NULL,
    easypatch_org_id      uuid NOT NULL,
    -- OnlyIfPending: restart if the updates need it; Always: restart when
    -- done. How the people signed in are treated, as for any restart.
    condition             text NOT NULL CHECK (condition IN ('OnlyIfPending', 'Always')),
    mode                  text NOT NULL CHECK (mode IN ('Countdown', 'PromptWithDeadline', 'PromptNoDeadline', 'Immediate')),
    countdown_minutes     integer CHECK (countdown_minutes BETWEEN 1 AND 60),
    deadline_minutes      integer CHECK (deadline_minutes BETWEEN 15 AND 10080),
    expires_after_minutes integer CHECK (expires_after_minutes BETWEEN 15 AND 1440),
    -- A server restarts only when the person ticked it by name.
    server_confirmed      boolean NOT NULL DEFAULT false,
    requested_by          uuid REFERENCES users (id) ON DELETE SET NULL,
    -- A person asked: once requested_by is NULL, they were deleted, and the
    -- device is not restarted on their behalf.
    by_user               boolean NOT NULL DEFAULT false,
    -- Who asked, as the engine records it on the restart.
    requested_label       text NOT NULL DEFAULT '' CHECK (length(requested_label) <= 255),
    requested_at          timestamptz NOT NULL DEFAULT now(),
    -- When the install was scheduled to start (NULL: at once). EasyRMM
    -- waits up to 40 days from then for it to end.
    scheduled_at          timestamptz,
    -- waiting: for the install to end; done: the restart was asked for;
    -- skipped: no restart, as message says; failed: the engine refused it.
    state                 text NOT NULL DEFAULT 'waiting' CHECK (state IN ('waiting', 'done', 'skipped', 'failed')),
    message               text NOT NULL DEFAULT '' CHECK (length(message) <= 1000),
    -- The last restart asked for while the install waited for one to go
    -- on, and how many were (at most 3, one each time it waited again); the
    -- one asked for once it ended.
    midway_job_id         uuid,
    midway_count          integer NOT NULL DEFAULT 0 CHECK (midway_count BETWEEN 0 AND 3),
    restart_job_id        uuid,
    -- Set while a request for a restart may have reached the engine, and
    -- which one (midway or final). A claim left by a server that stopped is
    -- settled from the engine's jobs, so the restart is asked for once.
    claimed_at            timestamptz,
    claimed_for           text CHECK (claimed_for IN ('midway', 'final')),
    checked_at            timestamptz,
    finished_at           timestamptz,
    CHECK ((claimed_at IS NULL) = (claimed_for IS NULL)),
    CHECK ((state = 'waiting') = (finished_at IS NULL)),
    CHECK (state <> 'done' OR restart_job_id IS NOT NULL),
    CHECK (state = 'waiting' OR claimed_at IS NULL),
    CHECK (install_job_id = ANY (install_job_ids)),
    CHECK ((midway_count = 0) = (midway_job_id IS NULL))
);
CREATE INDEX easypatch_install_restarts_waiting ON easypatch_install_restarts (checked_at NULLS FIRST) WHERE state = 'waiting';
CREATE INDEX easypatch_install_restarts_device ON easypatch_install_restarts (device_id);
CREATE INDEX easypatch_install_restarts_restart ON easypatch_install_restarts (restart_job_id) WHERE restart_job_id IS NOT NULL;
CREATE INDEX easypatch_install_restarts_midway ON easypatch_install_restarts (midway_job_id) WHERE midway_job_id IS NOT NULL;
-- A job's restart afterwards is found from any of its install's jobs.
CREATE INDEX easypatch_install_restarts_jobs ON easypatch_install_restarts USING gin (install_job_ids);
-- Deleting a user sets requested_by to NULL on their rows.
CREATE INDEX easypatch_install_restarts_requested_by ON easypatch_install_restarts (requested_by) WHERE requested_by IS NOT NULL;
-- Finished rows are deleted after 180 days, as the engine deletes its jobs.
CREATE INDEX easypatch_install_restarts_finished ON easypatch_install_restarts (finished_at) WHERE finished_at IS NOT NULL;

-- Read through the device, whose own policy decides; changed with the
-- system scope only.
ALTER TABLE easypatch_install_restarts ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_install_restarts FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_install_restarts_read ON easypatch_install_restarts FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY easypatch_install_restarts_insert ON easypatch_install_restarts FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_install_restarts_update ON easypatch_install_restarts FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_install_restarts_delete ON easypatch_install_restarts FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_install_restarts TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS easypatch_install_restarts;
