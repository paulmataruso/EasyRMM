-- Active Directory (ADR-0075, section 3): the controller an operator pinned for a domain. A domain is known
-- by its SID, read from a controller's active_directory.status snapshot; nothing else about a domain is stored.

-- +goose Up
CREATE TABLE ad_domains (
    organization_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_sid          text NOT NULL CHECK (domain_sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+$'),
    preferred_device_id uuid REFERENCES devices (id) ON DELETE SET NULL,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, domain_sid)
);
ALTER TABLE ad_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE ad_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY ad_domains_system ON ad_domains FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON ad_domains TO easyrmm_app;

-- +goose Down
DROP TABLE ad_domains;
