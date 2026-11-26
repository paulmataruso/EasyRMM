-- Which Windows management modules are on (ADR-0073, slice 2): one row per
-- organization and module, and an optional override per site. No row means
-- the module's default, which is on. Read through the organization's own
-- policy; written with the system scope only, after the caller's permission
-- was checked.

-- +goose Up
CREATE TABLE windows_module_settings (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid REFERENCES sites (id) ON DELETE CASCADE,
    module          text NOT NULL CHECK (module IN ('defender', 'active_directory', 'certificate_authority',
                                                    'dns', 'dhcp', 'file_shares', 'print', 'windows_backup')),
    enabled         boolean NOT NULL,
    set_by          text NOT NULL DEFAULT '',
    set_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX windows_module_settings_org_key ON windows_module_settings (organization_id, module) WHERE site_id IS NULL;
CREATE UNIQUE INDEX windows_module_settings_site_key ON windows_module_settings (site_id, module) WHERE site_id IS NOT NULL;

ALTER TABLE windows_module_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_module_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY windows_module_settings_read ON windows_module_settings FOR SELECT
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY windows_module_settings_write ON windows_module_settings FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON windows_module_settings TO easyrmm_app;

-- +goose Down
DROP TABLE windows_module_settings;
