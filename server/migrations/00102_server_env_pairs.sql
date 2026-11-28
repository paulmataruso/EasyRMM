-- ADR-0061 slice 1: the names each server's .env gives it.
--
--   server_env_pairs one row per server, keyed by the random ID the server
--                    made at its first start and keeps in its data directory
--                    (server-id): the pair of names its EASYRMM_PUBLIC_URL
--                    and EASYRMM_MESH_PUBLIC_URL name, when that pair was
--                    recorded and when the server was last seen (each start,
--                    and hourly while it runs). The mesh name is NULL when
--                    remote access is off. Not a device's, an organization's
--                    or a site's: the deployment's, so it is read and changed
--                    only with the system scope. server_instances (ADR-0057)
--                    are per process and are deleted at stop, so they cannot
--                    hold this.
--
-- Written at every start and acted on by nothing yet: an install that reaches
-- the release that moves agents (slice 4) already has the record of the names
-- its agents use.

-- +goose Up
CREATE TABLE server_env_pairs (
    server_id   text PRIMARY KEY CHECK (length(server_id) BETWEEN 16 AND 64),
    console_url text NOT NULL CHECK (length(console_url) BETWEEN 1 AND 300),
    mesh_url    text CHECK (mesh_url IS NULL OR length(mesh_url) BETWEEN 1 AND 300),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    seen_at     timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE server_env_pairs ENABLE ROW LEVEL SECURITY;
ALTER TABLE server_env_pairs FORCE ROW LEVEL SECURITY;
CREATE POLICY server_env_pairs_all ON server_env_pairs USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON server_env_pairs TO easyrmm_app;

-- +goose Down
DROP TABLE server_env_pairs;
