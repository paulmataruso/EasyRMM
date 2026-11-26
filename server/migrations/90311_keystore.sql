-- The keystore and BitLocker escrow (ADR-0081, section 11). None of these
-- tables holds a plaintext key or the KEK: a wrapped private key (AES-256-GCM
-- under the keystore's KEK, which lives only in the keystore process), HPKE
-- ciphertext only the organization's private key opens, and fingerprints that
-- reveal nothing usable.

-- +goose Up

-- What the keystore reported of each KEK version: metadata only.
CREATE TABLE keystore_kek_versions (
    version              integer PRIMARY KEY CHECK (version >= 1),
    check_value          bytea NOT NULL CHECK (octet_length(check_value) = 16),
    mode                 text NOT NULL CHECK (mode IN ('tpm', 'passphrase', 'file')),
    state                text NOT NULL CHECK (state IN ('active', 'pending')),
    created_at           timestamptz NOT NULL,
    recovery_verified_at timestamptz,
    seen_at              timestamptz NOT NULL DEFAULT now()
);

-- An organization's keys. The private half is wrapped: ks1.<kek version>.<base64url>.
CREATE TABLE keystore_org_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    purpose         text NOT NULL CHECK (purpose IN ('escrow', 'service')),
    version         integer NOT NULL CHECK (version >= 1),
    public_key      bytea CHECK (public_key IS NULL OR octet_length(public_key) = 32),
    wrapped_private text NOT NULL CHECK (wrapped_private LIKE 'ks1.%' AND length(wrapped_private) <= 512),
    kek_version     integer NOT NULL CHECK (kek_version >= 1),
    state           text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired', 'destroyed')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    retired_at      timestamptz,
    UNIQUE (organization_id, purpose, version),
    CHECK ((purpose = 'escrow') = (public_key IS NOT NULL))
);
-- One active key per organization and purpose.
CREATE UNIQUE INDEX keystore_org_keys_active_idx ON keystore_org_keys (organization_id, purpose) WHERE state = 'active';

-- The volumes an agent reported with their recovery-password protectors:
-- identifiers only. The console's per-volume state is this and the escrow rows.
CREATE TABLE device_encrypted_volumes (
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    volume_id       text NOT NULL CHECK (length(volume_id) BETWEEN 1 AND 128),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    kind            text NOT NULL DEFAULT 'bitlocker' CHECK (kind IN ('bitlocker', 'luks')),
    mount           text NOT NULL DEFAULT '' CHECK (length(mount) <= 16),
    status          text NOT NULL DEFAULT '' CHECK (length(status) <= 32),
    protectors      jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(protectors) = 'array' AND octet_length(protectors::text) <= 4096),
    reported_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, volume_id)
);

-- One sealed recovery key. state: pending (stored, not yet checked by the
-- keystore), verified, stale (the keystore computed another fingerprint),
-- conflict (a record for a protector that already has a verified one, with
-- another fingerprint; the old one stays current), superseded (kept 30 days),
-- destroyed.
CREATE TABLE recovery_key_escrows (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    volume_id       text NOT NULL CHECK (length(volume_id) BETWEEN 1 AND 128),
    kind            text NOT NULL CHECK (kind IN ('bitlocker', 'luks')),
    protector_id    text NOT NULL CHECK (length(protector_id) BETWEEN 1 AND 128),
    org_key_id      uuid NOT NULL REFERENCES keystore_org_keys (id),
    enc             bytea NOT NULL CHECK (octet_length(enc) = 32),
    ciphertext      bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 512),
    fingerprint     bytea NOT NULL CHECK (octet_length(fingerprint) = 16),
    state           text NOT NULL CHECK (state IN ('pending', 'verified', 'stale', 'conflict', 'superseded', 'destroyed')),
    rotation_due    boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    verified_at     timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
-- Never a second current record for one protector: one pending or one verified.
CREATE UNIQUE INDEX recovery_key_escrows_current_idx ON recovery_key_escrows (device_id, volume_id, protector_id)
    WHERE state IN ('pending', 'verified');
CREATE INDEX recovery_key_escrows_device_idx ON recovery_key_escrows (device_id, created_at DESC);
CREATE INDEX recovery_key_escrows_pending_idx ON recovery_key_escrows (created_at) WHERE state = 'pending';

-- Row-level security on organization_id, like the other per-organization
-- tables: another organization's scope sees no row. Writes are the server's
-- own (system scope).
ALTER TABLE keystore_org_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE keystore_org_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY keystore_org_keys_read ON keystore_org_keys FOR SELECT
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
CREATE POLICY keystore_org_keys_write ON keystore_org_keys FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE device_encrypted_volumes ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_encrypted_volumes FORCE ROW LEVEL SECURITY;
CREATE POLICY device_encrypted_volumes_read ON device_encrypted_volumes FOR SELECT
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY device_encrypted_volumes_write ON device_encrypted_volumes FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE recovery_key_escrows ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_key_escrows FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_key_escrows_read ON recovery_key_escrows FOR SELECT
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY recovery_key_escrows_write ON recovery_key_escrows FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

-- keystore_kek_versions holds no organization data and no key.
GRANT SELECT, INSERT, UPDATE, DELETE ON keystore_kek_versions, keystore_org_keys, device_encrypted_volumes, recovery_key_escrows TO easyrmm_app;

-- +goose Down
DROP TABLE recovery_key_escrows;
DROP TABLE device_encrypted_volumes;
DROP TABLE keystore_org_keys;
DROP TABLE keystore_kek_versions;
