-- Saved RDP credentials per device (ADR-0079). The password is sealed with
-- the server's secrets key; the associated data binds it to its row, device,
-- scope and person. Nothing reads a password back out through the API.

-- +goose Up
CREATE TABLE device_rdp_credentials (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    scope           text NOT NULL CHECK (scope IN ('user', 'device')),
    user_id         uuid REFERENCES users (id) ON DELETE CASCADE,
    label           text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 100),
    domain          text NOT NULL DEFAULT '' CHECK (char_length(domain) <= 255),
    username        text NOT NULL CHECK (char_length(username) BETWEEN 1 AND 255),
    sealed_password text NOT NULL CHECK (char_length(sealed_password) <= 4096),
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    rotated_at      timestamptz,
    CHECK ((scope = 'user') = (user_id IS NOT NULL))
);
-- One personal credential per device and person, and one shared per device.
CREATE UNIQUE INDEX device_rdp_credentials_user_uq ON device_rdp_credentials (device_id, user_id) WHERE scope = 'user';
CREATE UNIQUE INDEX device_rdp_credentials_device_uq ON device_rdp_credentials (device_id) WHERE scope = 'device';
CREATE INDEX device_rdp_credentials_org_idx ON device_rdp_credentials (organization_id);

ALTER TABLE device_rdp_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_rdp_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY device_rdp_credentials_tenant ON device_rdp_credentials
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON device_rdp_credentials TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS device_rdp_credentials;
