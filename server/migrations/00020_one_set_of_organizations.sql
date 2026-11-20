-- +goose Up
-- One set of organizations (one-product plan, B5). With the patching engine
-- in the deployment, EasyRMM makes the engine's organizations, sites and
-- endpoints follow its own.

-- The time zone patching uses for an organization: its monthly reports,
-- and the maintenance windows of devices without a site.
ALTER TABLE organizations ADD COLUMN timezone text NOT NULL DEFAULT 'UTC' CHECK (length(timezone) BETWEEN 1 AND 64);

-- Where a linked device's endpoint is in EasyPatch: the organization link
-- it was checked against, and its site as last read or placed. A device
-- whose organization or site moved no longer matches, which has the
-- reconciler move or remove its endpoint.
ALTER TABLE easypatch_devices ADD COLUMN easypatch_org_id uuid, ADD COLUMN easypatch_site_id uuid;

-- Which engine site each EasyRMM site is, as easypatch_organizations is for
-- organizations.
CREATE TABLE easypatch_sites (
    site_id        uuid PRIMARY KEY REFERENCES sites (id) ON DELETE CASCADE,
    easypatch_id   uuid NOT NULL UNIQUE,
    easypatch_name text NOT NULL CHECK (length(easypatch_name) <= 200),
    linked_at      timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE easypatch_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_sites FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_sites_read ON easypatch_sites FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM sites s WHERE s.id = site_id));
CREATE POLICY easypatch_sites_insert ON easypatch_sites FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_sites_update ON easypatch_sites FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_sites_delete ON easypatch_sites FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_sites TO easyrmm_app;

-- Organizations and sites EasyRMM deleted, which the engine still has: the
-- reconciler renames each to free its name, archives it, and removes the
-- row. Written by the triggers below in the deleting transaction, while the
-- link still names the engine's id, whoever deletes; read only with the
-- system scope.
CREATE TABLE easypatch_forgotten (
    kind         text NOT NULL CHECK (kind IN ('organization', 'site')),
    easypatch_id uuid NOT NULL,
    name         text NOT NULL CHECK (length(name) <= 200),
    forgotten_at timestamptz NOT NULL DEFAULT now(),
    last_error   text NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000),
    PRIMARY KEY (kind, easypatch_id)
);
ALTER TABLE easypatch_forgotten ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_forgotten FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_forgotten_read ON easypatch_forgotten FOR SELECT USING (easyrmm_scope_all());
CREATE POLICY easypatch_forgotten_insert ON easypatch_forgotten FOR INSERT WITH CHECK (true);
CREATE POLICY easypatch_forgotten_update ON easypatch_forgotten FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_forgotten_delete ON easypatch_forgotten FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_forgotten TO easyrmm_app;

-- Engine endpoints whose agent is to be removed: the device was deleted,
-- opted out, or moved to another organization (the engine cannot move an
-- endpoint across organizations). pending: the uninstall job is not sent
-- yet; uninstalling: it is, and the endpoint is revoked if the agent has
-- not removed itself after a grace period. The row goes when the endpoint
-- is no longer active.
CREATE TABLE easypatch_removals (
    endpoint_id  uuid PRIMARY KEY,
    -- The device, while EasyRMM still has it.
    device_id    uuid REFERENCES devices (id) ON DELETE SET NULL,
    reason       text NOT NULL CHECK (reason IN ('deleted', 'opted_out', 'moved')),
    hostname     text NOT NULL DEFAULT '' CHECK (length(hostname) <= 255),
    state        text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'uninstalling')),
    job_id       uuid,
    requested_at timestamptz NOT NULL DEFAULT now(),
    sent_at      timestamptz,
    checked_at   timestamptz,
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error   text NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000),
    CHECK (state <> 'uninstalling' OR sent_at IS NOT NULL)
);
ALTER TABLE easypatch_removals ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_removals FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_removals_read ON easypatch_removals FOR SELECT
    USING (easyrmm_scope_all() OR (device_id IS NOT NULL AND EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id)));
CREATE POLICY easypatch_removals_insert ON easypatch_removals FOR INSERT WITH CHECK (true);
CREATE POLICY easypatch_removals_update ON easypatch_removals FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_removals_delete ON easypatch_removals FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_removals TO easyrmm_app;

-- Devices patching is stopped for: EasyRMM removes their EasyPatch agent
-- and never installs it again, until someone installs it by hand.
CREATE TABLE easypatch_opt_outs (
    device_id    uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    opted_out_at timestamptz NOT NULL DEFAULT now(),
    opted_out_by uuid REFERENCES users (id) ON DELETE SET NULL
);
ALTER TABLE easypatch_opt_outs ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_opt_outs FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_opt_outs_read ON easypatch_opt_outs FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY easypatch_opt_outs_insert ON easypatch_opt_outs FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_opt_outs_update ON easypatch_opt_outs FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_opt_outs_delete ON easypatch_opt_outs FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_opt_outs TO easyrmm_app;

CREATE INDEX easypatch_removals_device ON easypatch_removals (device_id) WHERE device_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION easypatch_forget_organization() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO easypatch_forgotten (kind, easypatch_id, name)
        SELECT 'organization', l.easypatch_id, l.easypatch_name FROM easypatch_organizations l WHERE l.organization_id = OLD.id
        ON CONFLICT DO NOTHING;
    RETURN OLD;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER organizations_easypatch_forget BEFORE DELETE ON organizations
    FOR EACH ROW EXECUTE FUNCTION easypatch_forget_organization();

-- +goose StatementBegin
CREATE FUNCTION easypatch_forget_site() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO easypatch_forgotten (kind, easypatch_id, name)
        SELECT 'site', l.easypatch_id, l.easypatch_name FROM easypatch_sites l WHERE l.site_id = OLD.id
        ON CONFLICT DO NOTHING;
    RETURN OLD;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER sites_easypatch_forget BEFORE DELETE ON sites
    FOR EACH ROW EXECUTE FUNCTION easypatch_forget_site();

-- +goose StatementBegin
CREATE FUNCTION easypatch_forget_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO easypatch_removals (endpoint_id, reason, hostname)
        SELECT l.endpoint_id, 'deleted', left(OLD.name, 255) FROM easypatch_devices l
        WHERE l.device_id = OLD.id AND l.state = 'linked'
        ON CONFLICT (endpoint_id) DO NOTHING;
    RETURN OLD;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER devices_easypatch_forget BEFORE DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION easypatch_forget_device();

-- +goose Down
DROP TRIGGER IF EXISTS devices_easypatch_forget ON devices;
DROP TRIGGER IF EXISTS sites_easypatch_forget ON sites;
DROP TRIGGER IF EXISTS organizations_easypatch_forget ON organizations;
DROP FUNCTION IF EXISTS easypatch_forget_device();
DROP FUNCTION IF EXISTS easypatch_forget_site();
DROP FUNCTION IF EXISTS easypatch_forget_organization();
DROP TABLE IF EXISTS easypatch_opt_outs;
DROP TABLE IF EXISTS easypatch_removals;
DROP TABLE IF EXISTS easypatch_forgotten;
DROP TABLE IF EXISTS easypatch_sites;
ALTER TABLE easypatch_devices DROP COLUMN IF EXISTS easypatch_site_id, DROP COLUMN IF EXISTS easypatch_org_id;
ALTER TABLE organizations DROP COLUMN IF EXISTS timezone;
