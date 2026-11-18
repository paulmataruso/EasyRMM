-- +goose Up
-- The EasyRMM agent installs the EasyPatch agent (ADR-0031).

-- Install the EasyPatch agent on every device of the organization that has
-- none.
ALTER TABLE easypatch_organizations ADD COLUMN auto_install boolean NOT NULL DEFAULT false;

-- One device's EasyPatch agent install: requested by someone or by the
-- organization's automatic installs, sent to the agent in a heartbeat, and
-- how it ended. Enrollment tokens are never stored.
CREATE TABLE easypatch_installs (
    device_id       uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    -- waiting: for the agent's next heartbeat (or for an agent that can
    -- install); sent: the agent is installing attempt_id; succeeded, failed.
    state           text NOT NULL CHECK (state IN ('waiting', 'sent', 'succeeded', 'failed')),
    automatic       boolean NOT NULL DEFAULT false,
    requested_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    attempt_id      uuid,
    -- The EasyPatch enrollment token of the attempt, revoked if it fails.
    token_id        uuid,
    sent_at         timestamptz,
    finished_at     timestamptz,
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 1000),
    -- Why a waiting install has not been sent, such as an agent too old to
    -- install.
    note            text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    CHECK (state <> 'sent' OR (attempt_id IS NOT NULL AND sent_at IS NOT NULL)),
    CHECK ((state = 'failed') = (error <> ''))
);
CREATE INDEX easypatch_installs_sent ON easypatch_installs (sent_at) WHERE state = 'sent';

-- Read through the device, whose own policy decides; changed with the system
-- scope only.
ALTER TABLE easypatch_installs ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_installs FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_installs_read ON easypatch_installs FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY easypatch_installs_insert ON easypatch_installs FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_installs_update ON easypatch_installs FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_installs_delete ON easypatch_installs FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_installs TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS easypatch_installs;
ALTER TABLE easypatch_organizations DROP COLUMN IF EXISTS auto_install;
