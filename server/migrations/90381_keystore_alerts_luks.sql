-- +goose Up
-- ADR-0081 slice 3. A person can resolve a keystore alert (who is kept, so the
-- monitor does not reopen a standing condition at once), and LUKS volumes need
-- the agent's own verdict on them (can it unlock by itself?), a longer mount
-- name and the hash of the key slot an escrow was made from. No column here
-- holds a key.

ALTER TABLE keystore_alerts
    ADD COLUMN resolved_by       uuid,
    ADD COLUMN resolved_by_label text NOT NULL DEFAULT '' CHECK (length(resolved_by_label) <= 320);

-- escrow_state is the agent's verdict on a LUKS volume: escrowable, cannot_escrow
-- (only a passphrase unlocks it) or managed_elsewhere (Clevis or a distribution's
-- own TPM scheme). Empty for BitLocker.
ALTER TABLE device_encrypted_volumes
    ADD COLUMN escrow_state text NOT NULL DEFAULT '' CHECK (escrow_state IN ('', 'escrowable', 'cannot_escrow', 'managed_elsewhere')),
    ADD COLUMN reason       text NOT NULL DEFAULT '' CHECK (length(reason) <= 200);
ALTER TABLE device_encrypted_volumes DROP CONSTRAINT IF EXISTS device_encrypted_volumes_mount_check;
ALTER TABLE device_encrypted_volumes ADD CONSTRAINT device_encrypted_volumes_mount_check CHECK (length(mount) <= 64);

-- The SHA-256 of the key slot's header area when the record was made; a slot
-- that changed afterwards marks the escrow stale. Empty for BitLocker.
ALTER TABLE recovery_key_escrows
    ADD COLUMN slot_hash bytea CHECK (slot_hash IS NULL OR octet_length(slot_hash) = 32);

-- +goose Down
ALTER TABLE recovery_key_escrows DROP COLUMN slot_hash;
DELETE FROM device_encrypted_volumes WHERE length(mount) > 16;
ALTER TABLE device_encrypted_volumes DROP CONSTRAINT device_encrypted_volumes_mount_check;
ALTER TABLE device_encrypted_volumes ADD CONSTRAINT device_encrypted_volumes_mount_check CHECK (length(mount) <= 16);
ALTER TABLE device_encrypted_volumes DROP COLUMN reason, DROP COLUMN escrow_state;
ALTER TABLE keystore_alerts DROP COLUMN resolved_by_label, DROP COLUMN resolved_by;
