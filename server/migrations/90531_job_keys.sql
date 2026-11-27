-- ADR-0057 slice 1: the ring of job keys, and the servers that share it.
--
--   job_keys         one row per key the server ever made: its generation
--                    (only increases, even across a restore), its public key,
--                    its seed sealed with EASYRMM_SECRET_KEY (additional data
--                    easyrmm:job_key:<generation>; NULL once the seed is
--                    deleted), when, by whom and why it was made, and when it
--                    was cut over to, marked compromised, marked lost, or had
--                    its seed deleted. Not a device's, an organization's or a
--                    site's: the deployment's.
--   server_instances one row per server process sharing the database: its
--                    version, when it started, when it last reloaded the ring
--                    and whether the updater holds it. A row is removed when
--                    its server stops. Not a device's either.
--
-- Both are read and changed only with the system scope. The settings row
-- jobs.signing_key, where the first key lived, is replaced by a tombstone by
-- the server, in one transaction under an advisory lock (jobkeys.Open).

-- +goose Up
CREATE TABLE job_keys (
    generation      bigint PRIMARY KEY CHECK (generation >= 1),
    public_key      bytea NOT NULL UNIQUE CHECK (length(public_key) = 32),
    sealed_seed     text CHECK (sealed_seed IS NULL OR length(sealed_seed) BETWEEN 1 AND 2000),
    -- initial: the key an install made, or the one moved from settings.
    reason          text NOT NULL CHECK (reason IN ('initial', 'planned', 'moving', 'compromised', 'lost_replacement')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_via     text NOT NULL DEFAULT 'server' CHECK (created_via IN ('server', 'console', 'host')),
    cut_over_at     timestamptz,
    compromised_at  timestamptz,
    lost_at         timestamptz,
    seed_deleted_at timestamptz,
    CHECK ((sealed_seed IS NULL) = (seed_deleted_at IS NOT NULL))
);

CREATE TABLE server_instances (
    id          text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    version     text NOT NULL CHECK (length(version) BETWEEN 1 AND 100),
    started_at  timestamptz NOT NULL DEFAULT now(),
    reloaded_at timestamptz NOT NULL DEFAULT now(),
    held        boolean NOT NULL DEFAULT false,
    seen_at     timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE job_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY job_keys_all ON job_keys USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON job_keys TO easyrmm_app;

ALTER TABLE server_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE server_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY server_instances_all ON server_instances USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON server_instances TO easyrmm_app;

-- +goose Down
DROP TABLE server_instances;
DROP TABLE job_keys;
