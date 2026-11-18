-- Agent self-update (ADR-0027): the server rolls the agent build it serves
-- out to devices whose agent runs another one, a few at a time.

-- +goose Up

-- The SHA-256 of the agent's executable, as the agent reports it. Agents
-- from before self-update report none and cannot update themselves.
ALTER TABLE devices
    ADD COLUMN agent_sha256 text CHECK (agent_sha256 IS NULL OR agent_sha256 ~ '^[0-9a-f]{64}$');

-- The update of one device's agent to a build the server serves.
CREATE TABLE agent_updates (
    device_id       uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    -- The build, by its SHA-256, and its version for people to read.
    target_sha256   text NOT NULL CHECK (target_sha256 ~ '^[0-9a-f]{64}$'),
    target_version  text NOT NULL DEFAULT '' CHECK (length(target_version) <= 64),
    -- queued: waits for its turn or its next attempt; sent: the agent was
    -- told to update; failed: no further attempts until someone asks.
    state           text NOT NULL CHECK (state IN ('queued', 'sent', 'failed')),
    -- Someone asked for it in the console: it goes out in manual mode too.
    requested       boolean NOT NULL DEFAULT false,
    requested_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    -- The attempt in flight; the agent reports a failure against its id.
    attempt_id      uuid,
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
    sent_at         timestamptz,
    retry_after     timestamptz,
    from_version    text NOT NULL DEFAULT '' CHECK (length(from_version) <= 64),
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 1000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (state <> 'sent' OR (attempt_id IS NOT NULL AND sent_at IS NOT NULL))
);
-- The updates in flight, which the rollout's concurrency limit counts.
CREATE INDEX agent_updates_sent_idx ON agent_updates (sent_at) WHERE state = 'sent';

-- Rows are visible and changed through their device, whose own policy
-- decides; heartbeats run with the system scope.
ALTER TABLE agent_updates ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_updates FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_updates_read ON agent_updates FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_updates_insert ON agent_updates FOR INSERT
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_updates_update ON agent_updates FOR UPDATE
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id))
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_updates_delete ON agent_updates FOR DELETE
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_updates TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS agent_updates;
ALTER TABLE devices DROP COLUMN IF EXISTS agent_sha256;
