-- The connectivity guard of a Windows hardening apply (ADR-0054, W2): after
-- a change, the computer's own timer undoes it unless the server's confirm
-- job, which only runs where the agent is reachable, ends the timer first.
-- A row is the server's record of that wait.

-- +goose Up

CREATE TABLE hardening_guards (
    apply_job_id   uuid PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    device_id      uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    confirm_job_id uuid REFERENCES jobs (id) ON DELETE SET NULL,
    -- The setting IDs the apply changed, which the timer would undo.
    settings       text[] NOT NULL DEFAULT '{}',
    armed_at       timestamptz NOT NULL,
    rollback_at    timestamptz NOT NULL,
    -- armed: waiting for the confirmation. confirmed: the agent answered
    -- and the timer was ended. timed_out: it did not in time, so the
    -- computer's timer undoes the change by itself.
    state          text NOT NULL CHECK (state IN ('armed', 'confirmed', 'timed_out')),
    decided_at     timestamptz
);
CREATE INDEX hardening_guards_device ON hardening_guards (device_id, armed_at DESC);
CREATE INDEX hardening_guards_armed ON hardening_guards (rollback_at) WHERE state = 'armed';

ALTER TABLE hardening_guards ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardening_guards FORCE ROW LEVEL SECURITY;
CREATE POLICY hardening_guards_read ON hardening_guards FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY hardening_guards_write ON hardening_guards FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON hardening_guards TO easyrmm_app;

-- +goose Down
DROP TABLE hardening_guards;
