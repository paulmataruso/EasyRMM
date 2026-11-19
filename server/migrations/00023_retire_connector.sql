-- +goose Up
-- The connector to an EasyPatch server set up in Settings with an API token
-- is retired (ADR-0046, retiring ADR-0030's connection): patching always
-- uses the engine in this deployment. Since phase S, EasyRMM forgot such a
-- server at start, with its links, which name that server's ids. An upgrade
-- straight from a release that still had one does the same here, and
-- records it as that start did.
-- +goose StatementBegin
DO $$
DECLARE
    old_url text;
BEGIN
    SELECT url INTO old_url FROM easypatch_connection;
    IF FOUND THEN
        PERFORM set_config('easyrmm.scope_all', 'on', true);
        DELETE FROM easypatch_devices;
        DELETE FROM easypatch_installs;
        DELETE FROM easypatch_organizations;
        DELETE FROM easypatch_sites;
        DELETE FROM easypatch_removals;
        DELETE FROM easypatch_forgotten;
        PERFORM easyrmm_audit_append(now(), 'system', NULL, 'easypatch', NULL, NULL, NULL,
            'easypatch.connection_delete', 'easypatch', 'connection', 'success', NULL, '',
            jsonb_build_object('url', old_url, 'reason', 'replaced by the patching engine in this deployment'));
    END IF;
END
$$;
-- +goose StatementEnd
DROP TABLE easypatch_connection;

-- +goose Down
-- Recreates the table empty, as 00013 made it: the token is not kept, so a
-- server would have to be set up again.
CREATE TABLE easypatch_connection (
    id              boolean PRIMARY KEY DEFAULT true CHECK (id),
    url             text NOT NULL CHECK (url ~ '^https://' AND length(url) <= 500),
    token_sealed    text NOT NULL CHECK (token_sealed <> ''),
    ca_cert         text NOT NULL DEFAULT '' CHECK (length(ca_cert) <= 65536),
    server_version  text NOT NULL DEFAULT '' CHECK (length(server_version) <= 64),
    public_url      text NOT NULL DEFAULT '' CHECK (length(public_url) <= 500),
    capabilities    text[] NOT NULL DEFAULT '{}',
    can_operate     boolean NOT NULL DEFAULT false,
    checked_at      timestamptz,
    last_error      text NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000),
    last_error_at   timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      uuid REFERENCES users (id) ON DELETE SET NULL
);
ALTER TABLE easypatch_connection ENABLE ROW LEVEL SECURITY;
ALTER TABLE easypatch_connection FORCE ROW LEVEL SECURITY;
CREATE POLICY easypatch_connection_system ON easypatch_connection TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY easypatch_connection_owner ON easypatch_connection TO easyrmm_owner USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON easypatch_connection TO easyrmm_app;
