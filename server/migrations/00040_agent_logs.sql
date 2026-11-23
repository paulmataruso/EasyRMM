-- Live agent logs (ADR-0069, Part L, slice L1): the records the EasyRMM
-- agent sends (its own, and new lines from the EasyPatch agent's log and
-- MeshAgent's), the verbose mode a technician turns on for a device or a
-- group, and who is watching a device's logs now. Read through the device,
-- whose own policy decides; written with the system scope only.

-- +goose Up

-- One record per device and sequence (the agent's own, from 0): an agent that sends a batch again
-- after a lost answer stores nothing twice. id orders what the console
-- reads and is its cursor; received_at, which the server sets, is what
-- retention counts, since a device's clock may be wrong.
CREATE TABLE agent_log_records (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    seq         bigint NOT NULL CHECK (seq >= -1),
    source      text NOT NULL CHECK (source IN ('agent', 'easypatch', 'meshagent')),
    logged_at   timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    level       text NOT NULL CHECK (level IN ('debug', 'info', 'warn', 'error')),
    message     text NOT NULL CHECK (length(message) <= 16384),
    attrs       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(attrs) = 'object' AND pg_column_size(attrs) <= 32768)
);
-- Sequence -1 marks a record the server wrote itself, to say that records
-- were dropped or refused; there may be many of those.
CREATE UNIQUE INDEX agent_log_records_seq_key ON agent_log_records (device_id, seq) WHERE seq >= 0;
CREATE INDEX agent_log_records_device_idx ON agent_log_records (device_id, id);
CREATE INDEX agent_log_records_received_idx ON agent_log_records (received_at);

-- How many records a device stored on a UTC day: at most 200,000 (the
-- server counts and refuses the rest, and says how many it refused).
CREATE TABLE agent_log_days (
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    day       date NOT NULL,
    stored    integer NOT NULL DEFAULT 0 CHECK (stored >= 0),
    refused   integer NOT NULL DEFAULT 0 CHECK (refused >= 0),
    PRIMARY KEY (device_id, day)
);

-- Verbose logging for a device or for a group's devices, until a time. It
-- ends by itself: the agent stops at until even if it hears nothing more,
-- and the server deletes the row.
CREATE TABLE agent_log_verbose (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    device_id       uuid REFERENCES devices (id) ON DELETE CASCADE,
    group_id        uuid REFERENCES device_groups (id) ON DELETE CASCADE,
    until           timestamptz NOT NULL,
    set_by          uuid REFERENCES users (id) ON DELETE SET NULL,
    set_at          timestamptz NOT NULL DEFAULT now(),
    CHECK ((device_id IS NULL) <> (group_id IS NULL))
);
CREATE UNIQUE INDEX agent_log_verbose_device_key ON agent_log_verbose (device_id) WHERE device_id IS NOT NULL;
CREATE UNIQUE INDEX agent_log_verbose_group_key ON agent_log_verbose (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX agent_log_verbose_org_idx ON agent_log_verbose (organization_id);
CREATE INDEX agent_log_verbose_site_idx ON agent_log_verbose (site_id);
CREATE INDEX agent_log_verbose_until_idx ON agent_log_verbose (until);
CREATE INDEX agent_log_verbose_set_by_idx ON agent_log_verbose (set_by) WHERE set_by IS NOT NULL;

-- Someone is watching the device's logs until this time: the console
-- renews it with each read.
CREATE TABLE agent_log_follow (
    device_id uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    until     timestamptz NOT NULL
);

ALTER TABLE agent_log_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_log_records FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_log_records_read ON agent_log_records FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_log_records_insert ON agent_log_records FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY agent_log_records_delete ON agent_log_records FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, DELETE ON agent_log_records TO easyrmm_app;

ALTER TABLE agent_log_days ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_log_days FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_log_days_read ON agent_log_days FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_log_days_write ON agent_log_days FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_log_days TO easyrmm_app;

ALTER TABLE agent_log_verbose ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_log_verbose FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_log_verbose_read ON agent_log_verbose FOR SELECT
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY agent_log_verbose_write ON agent_log_verbose FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_log_verbose TO easyrmm_app;

ALTER TABLE agent_log_follow ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_log_follow FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_log_follow_read ON agent_log_follow FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_log_follow_write ON agent_log_follow FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_log_follow TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS agent_log_follow;
DROP TABLE IF EXISTS agent_log_verbose;
DROP TABLE IF EXISTS agent_log_days;
DROP TABLE IF EXISTS agent_log_records;
