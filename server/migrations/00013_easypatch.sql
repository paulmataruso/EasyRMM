-- +goose Up
-- EasyPatch connector (ADR-0030): the EasyPatch server, which EasyPatch
-- organization each EasyRMM organization patches with, and which EasyPatch
-- endpoint each device is. Patch data itself stays in EasyPatch.

-- The EasyPatch server; at most one row.
CREATE TABLE easypatch_connection (
    id              boolean PRIMARY KEY DEFAULT true CHECK (id),
    url             text NOT NULL CHECK (url ~ '^https://' AND length(url) <= 500),
    -- The API token, sealed with the server key (secrets.Sealer).
    token_sealed    text NOT NULL CHECK (token_sealed <> ''),
    ca_cert         text NOT NULL DEFAULT '' CHECK (length(ca_cert) <= 65536),
    -- What the last check found.
    server_version  text NOT NULL DEFAULT '' CHECK (length(server_version) <= 64),
    public_url      text NOT NULL DEFAULT '' CHECK (length(public_url) <= 500),
    capabilities    text[] NOT NULL DEFAULT '{}',
    can_operate     boolean NOT NULL DEFAULT false,
    checked_at      timestamptz,
    last_error      text NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000),
    last_error_at   timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      uuid REFERENCES users (id) ON DELETE SET NULL
);

ALTER TABLE easypatch_connection ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_connection FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_connection_system ON easypatch_connection TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_connection_owner ON easypatch_connection TO easyrmm_owner USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_connection TO easyrmm_app;

-- One EasyRMM organization to one EasyPatch organization.
CREATE TABLE easypatch_organizations (
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    easypatch_id    uuid NOT NULL UNIQUE,
    easypatch_name  text NOT NULL CHECK (length(easypatch_name) <= 200),
    linked_at       timestamptz NOT NULL DEFAULT now(),
    linked_by       uuid REFERENCES users (id) ON DELETE SET NULL
);

-- Read through the organization, whose own policy decides; changed with the
-- system scope only.
ALTER TABLE easypatch_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_organizations_read ON easypatch_organizations FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM organizations o WHERE o.id = organization_id));
CREATE POLICY easypatch_organizations_insert ON easypatch_organizations FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_organizations_update ON easypatch_organizations FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_organizations_delete ON easypatch_organizations FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_organizations TO easyrmm_app;

-- Which EasyPatch endpoint a device is, as its EasyRMM agent reported and the
-- server checked against EasyPatch.
CREATE TABLE easypatch_devices (
    device_id       uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    -- As reported by the device.
    endpoint_id     uuid,
    key_fingerprint text NOT NULL DEFAULT '' CHECK (length(key_fingerprint) <= 128),
    -- pending: not checked yet; linked: checked; unlinked: checked and
    -- refused, reason says why.
    state           text NOT NULL CHECK (state IN ('pending', 'linked', 'unlinked')),
    reason          text NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
    checked_at      timestamptz,
    linked_at       timestamptz,
    CHECK (state <> 'linked' OR (endpoint_id IS NOT NULL AND linked_at IS NOT NULL)),
    CHECK ((state = 'unlinked') = (reason <> ''))
);
CREATE UNIQUE INDEX easypatch_devices_endpoint ON easypatch_devices (endpoint_id) WHERE state = 'linked';
CREATE INDEX easypatch_devices_due ON easypatch_devices (state, checked_at);

ALTER TABLE easypatch_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_devices_read ON easypatch_devices FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY easypatch_devices_insert ON easypatch_devices FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_devices_update ON easypatch_devices FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_devices_delete ON easypatch_devices FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_devices TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS easypatch_devices;
DROP TABLE IF EXISTS easypatch_organizations;
DROP TABLE IF EXISTS easypatch_connection;
