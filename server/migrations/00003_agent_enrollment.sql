-- The EasyRMM agent (ADR-0009, ADR-0015): deployment tokens, device
-- identities and replay protection for signed agent requests.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Deployment tokens
-- ---------------------------------------------------------------------------

-- A token enrolls devices into one site (and optionally a device group).
-- Only the SHA-256 of the token is stored; the token is shown once.
CREATE TABLE enrollment_tokens (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL,
    site_id          uuid NOT NULL,
    device_group_id  uuid,
    name             text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    token_hash       bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    expires_at       timestamptz NOT NULL,
    max_uses         integer CHECK (max_uses IS NULL OR max_uses BETWEEN 1 AND 100000),
    uses             integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_used_at     timestamptz,
    revoked_at       timestamptz,
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (site_id, device_group_id) REFERENCES device_groups (site_id, id) ON DELETE SET NULL (device_group_id)
);
CREATE INDEX enrollment_tokens_site_idx ON enrollment_tokens (site_id);
CREATE INDEX enrollment_tokens_org_idx ON enrollment_tokens (organization_id);

ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_tokens_tenant ON enrollment_tokens
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
-- Agent identity on devices
-- ---------------------------------------------------------------------------

-- A device enrolled by the EasyRMM agent has its Ed25519 public key. Devices
-- discovered only through MeshCentral have none.
ALTER TABLE devices
    ADD COLUMN agent_public_key    bytea UNIQUE CHECK (agent_public_key IS NULL OR length(agent_public_key) = 32),
    ADD COLUMN agent_version       text CHECK (agent_version IS NULL OR length(agent_version) <= 64),
    ADD COLUMN agent_arch          text CHECK (agent_arch IS NULL OR length(agent_arch) <= 32),
    ADD COLUMN agent_last_seen_at  timestamptz,
    ADD COLUMN enrolled_at         timestamptz,
    ADD COLUMN enrollment_token_id uuid REFERENCES enrollment_tokens (id) ON DELETE SET NULL,
    ADD CONSTRAINT devices_enrolled_has_key CHECK ((enrolled_at IS NULL) = (agent_public_key IS NULL));
CREATE INDEX devices_agent_seen_idx ON devices (agent_last_seen_at) WHERE agent_public_key IS NOT NULL;

-- Heartbeats and connection changes are not edits: updated_at moves only
-- when something else about the device changes.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_touch_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF to_jsonb(NEW) - '{updated_at,last_seen_at,agent_last_seen_at,remote_online}'::text[]
       IS DISTINCT FROM to_jsonb(OLD) - '{updated_at,last_seen_at,agent_last_seen_at,remote_online}'::text[] THEN
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
DROP TRIGGER devices_touch ON devices;
CREATE TRIGGER devices_touch BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_device();

-- ---------------------------------------------------------------------------
-- Replay protection
-- ---------------------------------------------------------------------------

-- Nonces of signed agent requests, kept until their timestamp can no longer
-- be accepted. Written by the agent gateway only (platform scope).
CREATE TABLE agent_nonces (
    device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    nonce       text NOT NULL CHECK (length(nonce) BETWEEN 16 AND 64),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (device_id, nonce)
);
CREATE INDEX agent_nonces_expiry_idx ON agent_nonces (expires_at);

ALTER TABLE agent_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_nonces FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_nonces_platform ON agent_nonces
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_tokens, agent_nonces TO easyrmm_app;

-- +goose Down
DROP TRIGGER IF EXISTS devices_touch ON devices;
CREATE TRIGGER devices_touch BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();
DROP FUNCTION IF EXISTS easyrmm_touch_device();
DROP INDEX IF EXISTS devices_agent_seen_idx;
ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_enrolled_has_key,
    DROP COLUMN IF EXISTS enrollment_token_id,
    DROP COLUMN IF EXISTS enrolled_at,
    DROP COLUMN IF EXISTS agent_last_seen_at,
    DROP COLUMN IF EXISTS agent_arch,
    DROP COLUMN IF EXISTS agent_version,
    DROP COLUMN IF EXISTS agent_public_key;
DROP TABLE IF EXISTS agent_nonces, enrollment_tokens;
