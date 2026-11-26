-- +goose Up
-- ADR-0081 slice 2: reading a recovery key. Two add-on roles that carry the
-- read and approve permissions and nothing else, the two-person setting and its
-- requests, the cursor of the hourly reconciliation, the keystore's alerts and
-- the organization's notices of a read. No table here holds a key.

-- The add-on roles are assigned like any role, at an organization or a site.
-- +goose StatementBegin
DO $$
DECLARE c record;
BEGIN
    FOR c IN SELECT conname FROM pg_constraint
             WHERE conrelid = 'role_assignments'::regclass AND contype = 'c'
               AND (pg_get_constraintdef(oid) LIKE '%technician%') LOOP
        EXECUTE format('ALTER TABLE role_assignments DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE role_assignments
    ADD CONSTRAINT role_assignments_role_check CHECK (role IN ('super_admin', 'org_admin', 'site_admin', 'technician', 'read_only', 'key_reader', 'key_approver')),
    ADD CONSTRAINT role_assignments_site_role_check CHECK (site_id IS NULL OR role IN ('site_admin', 'technician', 'read_only', 'key_reader', 'key_approver'));

CREATE TABLE keystore_org_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    two_person      boolean NOT NULL DEFAULT false,
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- One request for one key by one person. A read waits here for a second
-- person when the organization asks for two; the approval is single-use.
CREATE TABLE recovery_key_requests (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id          uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    device_id        uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    escrow_id        uuid NOT NULL REFERENCES recovery_key_escrows (id) ON DELETE CASCADE,
    requested_by     uuid NOT NULL,
    requested_label  text NOT NULL DEFAULT '' CHECK (length(requested_label) <= 320),
    reason           text NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
    ticket           text NOT NULL DEFAULT '' CHECK (length(ticket) <= 64),
    state            text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'used')),
    approver_id      uuid,
    approver_label   text NOT NULL DEFAULT '' CHECK (length(approver_label) <= 320),
    decided_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    -- A pending request waits until this; an approved one is good until
    -- decided_at + 10 minutes, set when it is approved.
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz,
    CHECK (approver_id IS NULL OR approver_id <> requested_by),
    CHECK ((state IN ('approved', 'used', 'denied')) = (decided_at IS NOT NULL)),
    CHECK ((state = 'used') = (used_at IS NOT NULL))
);
CREATE INDEX recovery_key_requests_org_idx ON recovery_key_requests (organization_id, created_at DESC);
CREATE INDEX recovery_key_requests_open_idx ON recovery_key_requests (requested_by) WHERE state IN ('pending', 'approved');

-- Where the reconciliation has read the keystore's log to: the last entry's
-- sequence number and hash, so that the next run checks the chain from there.
CREATE TABLE keystore_log_cursor (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    last_seq      bigint NOT NULL DEFAULT 0,
    last_hash     text NOT NULL DEFAULT '',
    reconciled_at timestamptz
);
INSERT INTO keystore_log_cursor (id) VALUES (true);

-- The keystore's own alerts. They are not devices' alerts, so they have their
-- own table: one open alert per kind and subject, with the same dedupe.
CREATE TABLE keystore_alerts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    severity        text NOT NULL CHECK (severity IN ('warning', 'critical')),
    subject         text NOT NULL DEFAULT '' CHECK (length(subject) <= 200),
    detail          text NOT NULL CHECK (length(detail) <= 1000),
    opened_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    resolved_at     timestamptz
);
CREATE UNIQUE INDEX keystore_alerts_open_idx ON keystore_alerts (kind, subject) WHERE resolved_at IS NULL;

-- The notice every administrator of the organization gets of a read: who,
-- which device, why. Never the key.
CREATE TABLE keystore_notices (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid NOT NULL,
    device_id       uuid NOT NULL,
    device_name     text NOT NULL DEFAULT '' CHECK (length(device_name) <= 253),
    actor_id        uuid NOT NULL,
    actor_label     text NOT NULL DEFAULT '' CHECK (length(actor_label) <= 320),
    approver_label  text NOT NULL DEFAULT '' CHECK (length(approver_label) <= 320),
    reason          text NOT NULL CHECK (length(reason) <= 500),
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX keystore_notices_org_idx ON keystore_notices (organization_id, created_at DESC);

ALTER TABLE keystore_org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE keystore_org_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY keystore_org_settings_read ON keystore_org_settings FOR SELECT
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
CREATE POLICY keystore_org_settings_write ON keystore_org_settings FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE recovery_key_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_key_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_key_requests_read ON recovery_key_requests FOR SELECT
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY recovery_key_requests_write ON recovery_key_requests FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE keystore_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE keystore_alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY keystore_alerts_read ON keystore_alerts FOR SELECT
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
CREATE POLICY keystore_alerts_write ON keystore_alerts FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE keystore_notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE keystore_notices FORCE ROW LEVEL SECURITY;
CREATE POLICY keystore_notices_read ON keystore_notices FOR SELECT
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
CREATE POLICY keystore_notices_write ON keystore_notices FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

-- The cursor holds no organization data.
GRANT SELECT, INSERT, UPDATE, DELETE ON keystore_org_settings, recovery_key_requests, keystore_log_cursor, keystore_alerts, keystore_notices TO easyrmm_app;

-- +goose Down
DROP TABLE keystore_notices;
DROP TABLE keystore_alerts;
DROP TABLE keystore_log_cursor;
DROP TABLE recovery_key_requests;
DROP TABLE keystore_org_settings;
DELETE FROM role_assignments WHERE role IN ('key_reader', 'key_approver');
ALTER TABLE role_assignments
    DROP CONSTRAINT role_assignments_role_check,
    DROP CONSTRAINT role_assignments_site_role_check;
ALTER TABLE role_assignments
    ADD CONSTRAINT role_assignments_role_check CHECK (role IN ('super_admin', 'org_admin', 'site_admin', 'technician', 'read_only')),
    ADD CONSTRAINT role_assignments_site_role_check CHECK (site_id IS NULL OR role IN ('site_admin', 'technician', 'read_only'));
