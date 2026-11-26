-- +goose Up
-- ADR-0081 slice 4: actions and rotation. No column here holds a key.

-- A rotation after a read is due from the moment of the read, and the agent
-- waits ten minutes from it (the person has had time to type the key).
ALTER TABLE recovery_key_escrows ADD COLUMN rotation_due_at timestamptz;
UPDATE recovery_key_escrows SET rotation_due_at = updated_at WHERE rotation_due;
CREATE INDEX recovery_key_escrows_rotation_idx ON recovery_key_escrows (device_id) WHERE rotation_due AND state = 'verified';

-- The audit actions of a rotation ('recovery_key.rotated') need no column. A
-- retired organization key is kept until every record that was sealed to it
-- has moved (drained_at), and until the backups that hold keys wrapped by it
-- have expired (slice 5 destroys it); nothing here deletes a key.
ALTER TABLE keystore_org_keys ADD COLUMN drained_at timestamptz;

-- BitLocker's `enable` is a native action: the job names a handler built into
-- the agent instead of a script (ADR-0073 as amended by ADR-0081).
ALTER TABLE jobs DROP CONSTRAINT jobs_shell_check;
-- A builtin job (ADR-0067, migration 00072) still has no shell.
ALTER TABLE jobs ADD CONSTRAINT jobs_shell_check CHECK (shell IN ('powershell', 'pwsh', 'cmd', 'sh', 'bash', 'python3', 'native') OR (executor = 'builtin' AND shell = ''));

-- +goose Down
DELETE FROM jobs WHERE shell = 'native';
ALTER TABLE jobs DROP CONSTRAINT jobs_shell_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_shell_check CHECK (shell IN ('powershell', 'pwsh', 'cmd', 'sh', 'bash', 'python3') OR (executor = 'builtin' AND shell = ''));
ALTER TABLE keystore_org_keys DROP COLUMN drained_at;
DROP INDEX recovery_key_escrows_rotation_idx;
ALTER TABLE recovery_key_escrows DROP COLUMN rotation_due_at;
