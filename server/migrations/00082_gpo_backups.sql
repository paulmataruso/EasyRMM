-- Group Policy (ADR-0083, section 7): the automatic backup taken before every change, kept on the server because the
-- controller may be the thing that failed. The zip is what Backup-GPO wrote, compressed by the controller. Written and
-- read with the system scope only; the service checks gpo.view / gpo.manage first.

-- +goose Up
CREATE TABLE gpo_backups (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id          uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    device_id        uuid REFERENCES devices (id) ON DELETE SET NULL,
    domain           text NOT NULL CHECK (length(domain) BETWEEN 1 AND 255),
    gpo_id           uuid NOT NULL,
    -- The GPO's name when the backup was taken.
    gpo_name         text NOT NULL CHECK (length(gpo_name) BETWEEN 1 AND 256),
    -- The backup's own identifier, the folder name inside the zip (Backup-GPO's BackupId).
    backup_id        uuid NOT NULL,
    computer_version integer NOT NULL DEFAULT 0,
    user_version     integer NOT NULL DEFAULT 0,
    kind             text NOT NULL CHECK (kind IN ('automatic', 'manual')),
    -- The action that took it, such as group_policy.gpo_rename.
    action           text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
    job_id           uuid,
    actor_id         uuid,
    actor_label      text NOT NULL DEFAULT '',
    reason           text NOT NULL DEFAULT '',
    size_bytes       integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 20971520),
    sha256           text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    zip              bytea NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX gpo_backups_gpo_idx ON gpo_backups (organization_id, gpo_id, created_at DESC);
CREATE INDEX gpo_backups_org_idx ON gpo_backups (organization_id, created_at DESC);
ALTER TABLE gpo_backups ENABLE ROW LEVEL SECURITY;
ALTER TABLE gpo_backups FORCE ROW LEVEL SECURITY;
CREATE POLICY gpo_backups_system ON gpo_backups FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
-- A restore is created under the caller's scope, and the job's gate checks the backup it names there.
CREATE POLICY gpo_backups_read ON gpo_backups FOR SELECT
    USING (organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')));
GRANT SELECT, INSERT, DELETE ON gpo_backups TO easyrmm_app;

-- +goose Down
DROP TABLE gpo_backups;
