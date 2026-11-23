-- Recovery, slice R1 (ADR-0069, Part R): what MeshAgent's state is on a
-- device, when MeshCentral's view of it last changed, the repairs the
-- EasyRMM agent carries out, and the two default alerts, Remote access down
-- and EasyRMM agent silent.

-- +goose Up

-- ---------------------------------------------------------------------------
-- The device
-- ---------------------------------------------------------------------------

-- remote_changed_at is when remote_online last changed (MeshCentral's view,
-- set by the device sync); NULL until it did, when the device's enrollment
-- time stands in. Existing devices start now, so that an upgrade opens no
-- alert for a state that is not new to anyone.
--
-- meshagent_state is what the EasyRMM agent reported about MeshAgent with
-- its last heartbeat (installed, running, the MeshCentral host its settings
-- name, the last error it read) and whether that host is the one the server
-- gives out (hostOk, NULL when the server could not tell); meshagent_state_at
-- is when. mesh_wrong_group: the device sync found the node the agent
-- reported in another site's MeshCentral group and unlinked it; cleared when
-- a sync finds the node in the device's own site.
ALTER TABLE devices
    ADD COLUMN remote_changed_at timestamptz,
    ADD COLUMN meshagent_state jsonb CHECK (meshagent_state IS NULL OR jsonb_typeof(meshagent_state) = 'object'),
    ADD COLUMN meshagent_state_at timestamptz,
    ADD COLUMN mesh_wrong_group boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT devices_meshagent_state_pair CHECK ((meshagent_state IS NULL) = (meshagent_state_at IS NULL));
UPDATE devices SET remote_changed_at = now();

-- +goose StatementBegin
CREATE FUNCTION easyrmm_remote_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.remote_online IS DISTINCT FROM OLD.remote_online THEN
        NEW.remote_changed_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER devices_remote_changed
    BEFORE UPDATE OF remote_online ON devices
    FOR EACH ROW EXECUTE FUNCTION easyrmm_remote_changed();

-- ---------------------------------------------------------------------------
-- Repairs
-- ---------------------------------------------------------------------------

-- One row per repair: a target, the agent that carries it out, and its steps
-- in order. steps is an array of {id, step, state, sentAt, doneAt, error}
-- with state pending (not yet taken), sent (a heartbeat answer carried it),
-- done, failed or skipped. step is the index of the step in hand. wait_seconds
-- is how long the target gets to come back after a step before the next one
-- is tried; next_at is when that wait ends. At most one repair runs per
-- device and target.
CREATE TABLE agent_repairs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id     uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    target        text NOT NULL CHECK (target IN ('easyrmm-agent', 'meshagent', 'easypatch-agent')),
    carried_by    text NOT NULL CHECK (carried_by IN ('easyrmm-agent', 'easypatch-agent')),
    trigger       text NOT NULL CHECK (trigger IN ('manual', 'automatic')),
    requested_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    state         text NOT NULL CHECK (state IN ('running', 'succeeded', 'failed')),
    steps         jsonb NOT NULL CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) BETWEEN 1 AND 4),
    step          integer NOT NULL DEFAULT 0 CHECK (step >= 0),
    wait_seconds  integer NOT NULL CHECK (wait_seconds BETWEEN 0 AND 7200),
    next_at       timestamptz,
    started_at    timestamptz NOT NULL DEFAULT now(),
    ended_at      timestamptz,
    error         text NOT NULL DEFAULT '' CHECK (length(error) <= 1000),
    CHECK ((state = 'running') = (ended_at IS NULL))
);
CREATE UNIQUE INDEX agent_repairs_running ON agent_repairs (device_id, target) WHERE state = 'running';
CREATE INDEX agent_repairs_device ON agent_repairs (device_id, started_at DESC);

-- Rows are visible and written through their device, whose own policy
-- decides; heartbeats and the repair loop run with the system scope.
ALTER TABLE agent_repairs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_repairs FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_repairs_read ON agent_repairs FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_repairs_insert ON agent_repairs FOR INSERT
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_repairs_update ON agent_repairs FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY agent_repairs_delete ON agent_repairs FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_repairs TO easyrmm_app;

-- ---------------------------------------------------------------------------
-- Policies and alerts: remote_down and agent_silent
-- ---------------------------------------------------------------------------

-- Like offline, neither takes a threshold; both take minutes, at least 3.
ALTER TABLE alert_policies
    DROP CONSTRAINT alert_policies_kind_check,
    DROP CONSTRAINT alert_policies_threshold_needed,
    ADD CONSTRAINT alert_policies_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health', 'remote_down', 'agent_silent')),
    ADD CONSTRAINT alert_policies_threshold_needed CHECK (CASE
        WHEN kind IN ('offline', 'remote_down', 'agent_silent') THEN threshold IS NULL
        WHEN check_name = 'failing' THEN threshold IS NULL
        WHEN check_name = 'temperature' THEN true
        ELSE threshold IS NOT NULL END),
    ADD CONSTRAINT alert_policies_remote_minutes CHECK (kind NOT IN ('remote_down', 'agent_silent') OR minutes >= 3);

ALTER TABLE alerts
    DROP CONSTRAINT alerts_kind_check,
    ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health', 'remote_down', 'agent_silent'));

-- The two shared policies, on, on new installations and old ones alike. A
-- name an administrator already uses is tried once more with " (recovery)"
-- appended; an installation that has both names gets no default of that
-- kind. alert_policies forces row-level security, on its owner too.
SELECT set_config('easyrmm.scope_all', 'on', true);
WITH wanted (name, description, kind, minutes, severity) AS (VALUES
    ('Remote access down', 'The EasyRMM agent checks in, but MeshAgent has not been connected to MeshCentral for this long, so no remote session can start.', 'remote_down', 15, 'critical'),
    ('EasyRMM agent silent', 'MeshCentral sees MeshAgent connected, but the EasyRMM agent has not checked in for this long.', 'agent_silent', 15, 'critical')
), first AS (
    INSERT INTO alert_policies (name, description, kind, threshold, minutes, severity, enabled)
    SELECT name, description, kind, NULL, minutes, severity, true FROM wanted
    ON CONFLICT DO NOTHING
    RETURNING kind
)
INSERT INTO alert_policies (name, description, kind, threshold, minutes, severity, enabled)
SELECT name || ' (recovery)', description, kind, NULL, minutes, severity, true
FROM wanted WHERE kind NOT IN (SELECT kind FROM first)
ON CONFLICT DO NOTHING;

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
DELETE FROM alerts WHERE kind IN ('remote_down', 'agent_silent');
DELETE FROM alert_policies WHERE kind IN ('remote_down', 'agent_silent');
ALTER TABLE alerts
    DROP CONSTRAINT alerts_kind_check,
    ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health'));
ALTER TABLE alert_policies
    DROP CONSTRAINT alert_policies_remote_minutes,
    DROP CONSTRAINT alert_policies_threshold_needed,
    DROP CONSTRAINT alert_policies_kind_check,
    ADD CONSTRAINT alert_policies_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health')),
    ADD CONSTRAINT alert_policies_threshold_needed CHECK (CASE
        WHEN kind = 'offline' THEN threshold IS NULL
        WHEN check_name = 'failing' THEN threshold IS NULL
        WHEN check_name = 'temperature' THEN true
        ELSE threshold IS NOT NULL END);
DROP TABLE agent_repairs;
DROP TRIGGER devices_remote_changed ON devices;
DROP FUNCTION easyrmm_remote_changed();
ALTER TABLE devices
    DROP CONSTRAINT devices_meshagent_state_pair,
    DROP COLUMN mesh_wrong_group,
    DROP COLUMN meshagent_state_at,
    DROP COLUMN meshagent_state,
    DROP COLUMN remote_changed_at;
