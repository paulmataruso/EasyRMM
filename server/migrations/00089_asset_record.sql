-- The asset record (ADR-0066, slice 2): one record per piece of hardware,
-- linked to at most one device, with each identifying field's value kept
-- per source (the agent, entered by hand) beside its effective value; and
-- an organization's age policy. Read with doc.view and written with
-- doc.manage, which the server checks; row-level security keeps each
-- organization's rows to it and site-scoped people to their sites' rows.

-- +goose Up

-- The effective value of each field is a column, derived by the service in
-- the transaction that changes the values it comes from, so lists sort and
-- filter on it. serial_key and maker_key are the match keys made by the
-- one Go function in the assets package.
CREATE TABLE assets (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    device_id       uuid UNIQUE REFERENCES devices (id) ON DELETE SET NULL (device_id),
    kind            text NOT NULL DEFAULT 'workstation' CHECK (kind IN (
        'workstation', 'laptop', 'server', 'virtual_machine', 'virtualization_host', 'firewall', 'router',
        'switch', 'wireless_access_point', 'network_device', 'printer', 'ups', 'storage', 'mobile_device',
        'internet_connection', 'licence', 'other')),
    status          text NOT NULL DEFAULT 'in_use' CHECK (status IN ('ordered', 'in_stock', 'in_use', 'in_repair', 'retired', 'disposed', 'lost')),
    name            text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    manufacturer    text NOT NULL DEFAULT '' CHECK (length(manufacturer) <= 200),
    model           text NOT NULL DEFAULT '' CHECK (length(model) <= 200),
    serial_number   text NOT NULL DEFAULT '' CHECK (length(serial_number) <= 200),
    sku             text NOT NULL DEFAULT '' CHECK (length(sku) <= 200),
    chassis_type    text NOT NULL DEFAULT '' CHECK (length(chassis_type) <= 200),
    asset_tag       text NOT NULL DEFAULT '' CHECK (length(asset_tag) <= 200),
    smbios_uuid     text NOT NULL DEFAULT '' CHECK (length(smbios_uuid) <= 64),
    purchase_date   date,
    warranty_expiry date,
    warranty_status text NOT NULL DEFAULT '' CHECK (warranty_status IN ('', 'active', 'expired', 'unknown')),
    os_eol_date     date,
    notes           text NOT NULL DEFAULT '' CHECK (length(notes) <= 4000),
    serial_key      text NOT NULL DEFAULT '' CHECK (length(serial_key) <= 200),
    maker_key       text NOT NULL DEFAULT '' CHECK (length(maker_key) <= 200),
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX assets_org_idx ON assets (organization_id);
CREATE INDEX assets_site_idx ON assets (site_id);
CREATE INDEX assets_serial_key_idx ON assets (organization_id, serial_key) WHERE serial_key <> '';
CREATE TRIGGER assets_touch BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- One value per field and source. state is the agent's: a value it
-- reported, or why it has none; a manual value is always reported.
CREATE TABLE asset_field_values (
    asset_id        uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    organization_id uuid NOT NULL,
    field           text NOT NULL CHECK (field IN ('name', 'manufacturer', 'model', 'serial_number', 'sku', 'chassis_type',
        'asset_tag', 'smbios_uuid', 'purchase_date', 'warranty_expiry', 'warranty_status', 'os_eol_date')),
    source          text NOT NULL CHECK (source IN ('agent', 'manual')),
    value           text NOT NULL DEFAULT '' CHECK (length(value) <= 200),
    state           text NOT NULL DEFAULT 'reported' CHECK (state IN ('reported', 'unknown', 'unsupported', 'unavailable')),
    reason          text NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
    observed_at     timestamptz,
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    recorded_by     uuid,
    PRIMARY KEY (asset_id, field, source),
    CHECK (source = 'agent' OR state = 'reported')
);
CREATE INDEX asset_field_values_org_idx ON asset_field_values (organization_id);

-- An organization's policy for when hardware is aging and when it is at
-- the end of its life, in months from the purchase date.
CREATE TABLE asset_age_policies (
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    aging_months    integer NOT NULL DEFAULT 36 CHECK (aging_months BETWEEN 1 AND 240),
    eol_months      integer NOT NULL DEFAULT 60 CHECK (eol_months BETWEEN 1 AND 240),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (aging_months < eol_months)
);
CREATE TRIGGER asset_age_policies_touch BEFORE UPDATE ON asset_age_policies
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
CREATE POLICY assets_tenant ON assets
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

-- A value is visible and writable where its asset is.
ALTER TABLE asset_field_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_field_values FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_field_values_tenant ON asset_field_values
    USING (
        easyrmm_scope_all()
        OR EXISTS (SELECT 1 FROM assets a WHERE a.id = asset_id)
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR EXISTS (SELECT 1 FROM assets a WHERE a.id = asset_id AND a.organization_id = asset_field_values.organization_id)
    );

ALTER TABLE asset_age_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_age_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_age_policies_tenant ON asset_age_policies
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

GRANT SELECT, INSERT, UPDATE, DELETE ON assets, asset_field_values, asset_age_policies TO easyrmm_app;

-- +goose Down
DROP TABLE asset_age_policies;
DROP TABLE asset_field_values;
DROP TABLE assets;
