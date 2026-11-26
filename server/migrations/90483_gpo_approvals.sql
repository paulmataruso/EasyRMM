-- Group Policy (ADR-0083, section 7): two-person approval. A request holds the staged change and who asked; a second
-- person with gpo.edit approves or rejects it. The organization's setting says when approval is required.

-- +goose Up
CREATE TABLE gpo_org_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    -- Required for a GPO linked at the domain root, to the Domain Controllers OU or to a site, and for the two Default
    -- policies. On unless an Organization Administrator turns it off (audited).
    approval_sensitive boolean NOT NULL DEFAULT true,
    -- Required for every Group Policy change. Off unless the organization turns it on.
    approval_all       boolean NOT NULL DEFAULT false,
    updated_by         text NOT NULL DEFAULT '',
    updated_at         timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE gpo_org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE gpo_org_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY gpo_org_settings_system ON gpo_org_settings FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
-- The job's gate reads the setting under the caller's scope.
CREATE POLICY gpo_org_settings_read ON gpo_org_settings FOR SELECT
    USING (organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
GRANT SELECT, INSERT, UPDATE, DELETE ON gpo_org_settings TO easyrmm_app;

CREATE TABLE gpo_change_requests (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- "<module>.<action>" and its validated parameters, without any secret.
    action          text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
    params          jsonb NOT NULL CHECK (jsonb_typeof(params) = 'object'),
    -- Why approval is needed: default_policy, sensitive_link, or organization.
    sensitivity     text NOT NULL CHECK (sensitivity IN ('default_policy', 'sensitive_link', 'organization')),
    -- What the change is about, for the list: the GPO's name or the link target.
    summary         text NOT NULL CHECK (length(summary) BETWEEN 1 AND 600),
    reason          text NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    requested_by    uuid NOT NULL,
    requested_label text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    decided_by      uuid,
    decided_label   text NOT NULL DEFAULT '',
    decided_reason  text NOT NULL DEFAULT '',
    decided_at      timestamptz,
    run_id          uuid,
    -- Set when a job ran under the approval: an approval runs once.
    consumed_at     timestamptz,
    CONSTRAINT gpo_change_requests_decided CHECK ((status = 'pending') = (decided_at IS NULL) OR status = 'expired')
);
CREATE INDEX gpo_change_requests_org_idx ON gpo_change_requests (organization_id, status, created_at DESC);
ALTER TABLE gpo_change_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE gpo_change_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY gpo_change_requests_system ON gpo_change_requests FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
-- The job's gate reads the approved request it runs under, and uses it up, under the caller's scope.
CREATE POLICY gpo_change_requests_read ON gpo_change_requests FOR SELECT
    USING (organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')));
CREATE POLICY gpo_change_requests_use ON gpo_change_requests FOR UPDATE
    USING (organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')))
    WITH CHECK (organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')));
GRANT SELECT, INSERT, UPDATE ON gpo_change_requests TO easyrmm_app;

-- +goose Down
DROP TABLE gpo_change_requests;
DROP TABLE gpo_org_settings;
