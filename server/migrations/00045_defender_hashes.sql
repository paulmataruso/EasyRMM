-- Defender exclusions at install and an always-current hash list
-- (ADR-0070, slice A): a device's last reported exclusion state and
-- installed-file hashes, and the console's list of every file the server
-- hands out or the agents install. No organization column: the list is
-- platform-wide, and nothing here is a setting.

-- +goose Up

ALTER TABLE devices
    ADD COLUMN defender jsonb CHECK (defender IS NULL OR (jsonb_typeof(defender) = 'object' AND pg_column_size(defender) <= 32768)),
    ADD COLUMN defender_at timestamptz,
    ADD COLUMN installed_files jsonb CHECK (installed_files IS NULL OR (jsonb_typeof(installed_files) = 'object' AND pg_column_size(installed_files) <= 65536)),
    ADD COLUMN installed_files_at timestamptz;

-- One row per file the console lists. source says where the value comes
-- from: the server's own builds, MeshCentral, or the patching engine. A
-- value that could not be read again keeps its last value, stale = true.
CREATE TABLE agent_file_hashes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source      text NOT NULL CHECK (source IN ('server', 'meshcentral', 'patching')),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 260),
    platform    text NOT NULL CHECK (length(platform) <= 32),
    arch        text NOT NULL CHECK (length(arch) <= 32),
    version     text NOT NULL CHECK (length(version) <= 64),
    size        bigint NOT NULL CHECK (size >= 0),
    md5         text NOT NULL CHECK (md5 = '' OR md5 ~ '^[0-9a-f]{32}$'),
    sha256      text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    signer      text NOT NULL DEFAULT '' CHECK (length(signer) <= 1000),
    computed_at timestamptz NOT NULL,
    stale       boolean NOT NULL DEFAULT false,
    stale_reason text NOT NULL DEFAULT '' CHECK (length(stale_reason) <= 300)
);
CREATE UNIQUE INDEX agent_file_hashes_key ON agent_file_hashes (source, name, version, arch);

ALTER TABLE agent_file_hashes ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_file_hashes FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_file_hashes_platform ON agent_file_hashes
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_file_hashes TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS agent_file_hashes;
ALTER TABLE devices
    DROP COLUMN IF EXISTS installed_files_at,
    DROP COLUMN IF EXISTS installed_files,
    DROP COLUMN IF EXISTS defender_at,
    DROP COLUMN IF EXISTS defender;
