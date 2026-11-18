-- Remote access through MeshCentral (ADR-0004, ADR-0005): devices, the
-- MeshCentral device group of each site, and remote-session grants.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Devices
-- ---------------------------------------------------------------------------

-- A managed endpoint. In this release devices are discovered from
-- MeshCentral (the remote-access agent); the EasyRMM agent adds its own
-- identity and inventory later.
CREATE TABLE devices (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL,
    site_id          uuid NOT NULL,
    device_group_id  uuid,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    hostname         text NOT NULL DEFAULT '' CHECK (length(hostname) <= 255),
    os_description   text NOT NULL DEFAULT '' CHECK (length(os_description) <= 500),
    platform         text NOT NULL DEFAULT 'other' CHECK (platform IN ('windows', 'linux', 'macos', 'other')),
    -- MeshCentral node id (node//<base64>) and agent architecture number.
    mesh_node_id     text UNIQUE CHECK (mesh_node_id IS NULL OR length(mesh_node_id) <= 200),
    mesh_agent_type  integer,
    remote_online    boolean NOT NULL DEFAULT false,
    last_seen_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (site_id, device_group_id) REFERENCES device_groups (site_id, id) ON DELETE SET NULL (device_group_id)
);
CREATE INDEX devices_site_idx ON devices (site_id);
CREATE INDEX devices_org_idx ON devices (organization_id);
CREATE INDEX devices_group_idx ON devices (device_group_id) WHERE device_group_id IS NOT NULL;
CREATE INDEX devices_name_idx ON devices (lower(name));
CREATE TRIGGER devices_touch BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
CREATE POLICY devices_tenant ON devices
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

-- ---------------------------------------------------------------------------
-- MeshCentral device groups: one per site
-- ---------------------------------------------------------------------------

-- Maintained by the synchronizer only (platform scope). The group's
-- description in MeshCentral also names the site, so a group whose site is
-- gone is recognized and removed even after this row has been.
CREATE TABLE mesh_sites (
    site_id          uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    mesh_id          text NOT NULL UNIQUE CHECK (length(mesh_id) BETWEEN 8 AND 200),
    synced_name      text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE TRIGGER mesh_sites_touch BEFORE UPDATE ON mesh_sites
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

ALTER TABLE mesh_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_sites FORCE ROW LEVEL SECURITY;
CREATE POLICY mesh_sites_platform ON mesh_sites
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

-- ---------------------------------------------------------------------------
-- Remote-session grants
-- ---------------------------------------------------------------------------

-- Issued when a technician opens a remote session. The launch token is
-- redeemed once, within a minute, on the MeshCentral hostname; the gateway
-- cookie set then lets that browser use MeshCentral for as long as the
-- EasyRMM session that requested it stays valid. Only hashes are stored.
CREATE TABLE remote_grants (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    launch_hash      bytea NOT NULL UNIQUE,
    cookie_hash      bytea UNIQUE,
    session_id       uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id        uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    organization_id  uuid NOT NULL,
    site_id          uuid NOT NULL,
    kind             text NOT NULL CHECK (kind IN ('desktop', 'terminal', 'files')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    launch_expires_at timestamptz NOT NULL,
    redeemed_at      timestamptz,
    source_ip        inet,
    CHECK ((cookie_hash IS NULL) = (redeemed_at IS NULL))
);
CREATE INDEX remote_grants_session_idx ON remote_grants (session_id);
CREATE INDEX remote_grants_created_idx ON remote_grants (created_at);

ALTER TABLE remote_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY remote_grants_platform ON remote_grants
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

GRANT SELECT, INSERT, UPDATE, DELETE ON devices, mesh_sites, remote_grants TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS remote_grants, mesh_sites, devices;
