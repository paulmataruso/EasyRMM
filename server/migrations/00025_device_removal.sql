-- Removing a device (ADR-0050): the device's agent is told to uninstall
-- itself and the device is deleted when it reports that it did; a device
-- removed without that is remembered for a while, so that its agents still
-- uninstall themselves if the computer comes back.

-- +goose Up

-- A removal someone asked for. The heartbeat answer carries the signed
-- instruction while the row exists; the agent reports against id. A report
-- that the agent could not remove itself leaves the row with its error.
CREATE TABLE device_removals (
    device_id    uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    id           uuid NOT NULL UNIQUE,
    requested_at timestamptz NOT NULL DEFAULT now(),
    requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
    -- The first heartbeat answer that carried the instruction.
    sent_at      timestamptz,
    reported_at  timestamptz,
    error        text NOT NULL DEFAULT '' CHECK (length(error) <= 500),
    CHECK (reported_at IS NULL OR sent_at IS NOT NULL),
    CHECK (error = '' OR reported_at IS NOT NULL)
);

-- Rows are visible and changed through their device, whose own policy
-- decides; heartbeats run with the system scope.
ALTER TABLE device_removals ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_removals FORCE ROW LEVEL SECURITY;
CREATE POLICY device_removals_read ON device_removals FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_removals_insert ON device_removals FOR INSERT
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_removals_update ON device_removals FOR UPDATE
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id))
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_removals_delete ON device_removals FOR DELETE
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON device_removals TO easyrmm_app;

-- Devices removed in the last 90 days whose agents may still be on the
-- computer. While a row lasts, the EasyRMM agent holding agent_public_key
-- is answered with the uninstall instruction instead of device_unknown, and
-- a MeshAgent connecting as mesh_node_id is told to uninstall and its node
-- removed. A device enrolled since then that reports the node keeps it.
-- Written in the removing transaction, whoever removes; read and changed
-- only with the system scope.
CREATE TABLE retired_devices (
    device_id        uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    site_id          uuid NOT NULL,
    name             text NOT NULL CHECK (length(name) <= 255),
    -- NULL when there is no EasyRMM agent to wait for: the device had none,
    -- or its agent confirmed that it uninstalled itself.
    agent_public_key bytea CHECK (agent_public_key IS NULL OR length(agent_public_key) = 32),
    mesh_node_id     text CHECK (mesh_node_id IS NULL OR length(mesh_node_id) <= 200),
    removed_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    -- When the agent of a device removed by force confirmed that it
    -- uninstalled itself; its last report, and what failed.
    cleaned_at        timestamptz,
    agent_reported_at timestamptz,
    agent_error       text NOT NULL DEFAULT '' CHECK (length(agent_error) <= 500),
    -- MeshCentral: the last attempt to have the node's MeshAgent uninstall
    -- or the node removed, how many uninstall requests it got while
    -- connected, and the last failure.
    mesh_attempt_at  timestamptz,
    mesh_uninstalls  integer NOT NULL DEFAULT 0 CHECK (mesh_uninstalls >= 0),
    mesh_removed_at  timestamptz,
    mesh_error       text NOT NULL DEFAULT '' CHECK (length(mesh_error) <= 1000),
    CHECK (expires_at > removed_at)
);
CREATE INDEX retired_devices_mesh_node ON retired_devices (mesh_node_id) WHERE mesh_node_id IS NOT NULL;
CREATE INDEX retired_devices_expires ON retired_devices (expires_at);
ALTER TABLE retired_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE retired_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY retired_devices_read ON retired_devices FOR SELECT USING (easyrmm_scope_all());
CREATE POLICY retired_devices_insert ON retired_devices FOR INSERT WITH CHECK (true);
CREATE POLICY retired_devices_update ON retired_devices FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY retired_devices_delete ON retired_devices FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON retired_devices TO easyrmm_app;

-- The nonces of retired devices' agents, as agent_nonces keeps those of
-- enrolled devices: each signed request is accepted once.
CREATE TABLE retired_agent_nonces (
    device_id  uuid NOT NULL REFERENCES retired_devices (device_id) ON DELETE CASCADE,
    nonce      text NOT NULL CHECK (length(nonce) BETWEEN 16 AND 64),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, nonce)
);
CREATE INDEX retired_agent_nonces_expires ON retired_agent_nonces (expires_at);
ALTER TABLE retired_agent_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE retired_agent_nonces FORCE ROW LEVEL SECURITY;
CREATE POLICY retired_agent_nonces_all ON retired_agent_nonces
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON retired_agent_nonces TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS retired_agent_nonces;
DROP TABLE IF EXISTS retired_devices;
DROP TABLE IF EXISTS device_removals;
