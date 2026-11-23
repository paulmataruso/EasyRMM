-- Recovery, slice R2 (ADR-0069, Part R): the EasyRMM agent repairs the
-- EasyPatch agent, repairs start by themselves under limits, and a repair
-- that ends with the target still broken raises a warning alert.

-- +goose Up

-- ---------------------------------------------------------------------------
-- What the server needs to know
-- ---------------------------------------------------------------------------

-- agent_seen_at is the EasyPatch agent's last check-in as the patching
-- engine reports it, read every 5 minutes for linked endpoints.
ALTER TABLE easypatch_devices ADD COLUMN agent_seen_at timestamptz;

-- auto_repair: whether the server starts repairs of an organization's
-- devices by itself. Repairs by hand are always available.
ALTER TABLE organizations ADD COLUMN auto_repair boolean NOT NULL DEFAULT true;

-- agent_conditions remembers since when a condition that repairs act on has
-- held for a device and a target: the timer of an automatic repair starts
-- when the condition is first seen. A row goes when the condition does, and
-- all of a target's rows go while conditions cannot be judged.
CREATE TABLE agent_conditions (
    device_id  uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    target     text NOT NULL CHECK (target IN ('easyrmm-agent', 'meshagent', 'easypatch-agent')),
    since      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, target)
);
ALTER TABLE agent_conditions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_conditions FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_conditions_all ON agent_conditions FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_conditions TO easyrmm_app;

-- ---------------------------------------------------------------------------
-- The Repair failed alert
-- ---------------------------------------------------------------------------

-- A warning on a device whose automatic repair ended with the target still
-- broken. It belongs to no policy: subject is the target, detail the last
-- step's diagnostics. At most one is unresolved per device and target.
ALTER TABLE alerts
    DROP CONSTRAINT alerts_kind_check,
    ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health', 'remote_down', 'agent_silent', 'repair_failed'));
CREATE UNIQUE INDEX alerts_repair_failed_key ON alerts (device_id, subject) WHERE kind = 'repair_failed' AND status <> 'resolved';

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
DELETE FROM alerts WHERE kind = 'repair_failed';
DROP INDEX alerts_repair_failed_key;
ALTER TABLE alerts
    DROP CONSTRAINT alerts_kind_check,
    ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health', 'remote_down', 'agent_silent'));
DROP TABLE agent_conditions;
ALTER TABLE organizations DROP COLUMN auto_repair;
ALTER TABLE easypatch_devices DROP COLUMN agent_seen_at;
