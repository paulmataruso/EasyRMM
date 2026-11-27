-- ADR-0055, slice 5b3: the name pair added to an installation set up on an IP
-- address.
--
--   tls_added_names  at most one row: the console's name and its remote-access
--                    name, when the pair became trusted, and the evidence of
--                    reachability (the server's own fetch through the name,
--                    and the last browser that loaded the console through it).
--
-- A platform table like tls_names: outside row-level security, reached only
-- through the added-name service, which requires settings.manage.

-- +goose Up
CREATE TABLE tls_added_names (
    console_name        text PRIMARY KEY CHECK (length(console_name) BETWEEN 1 AND 253),
    mesh_name           text NOT NULL CHECK (length(mesh_name) BETWEEN 1 AND 253),
    state               text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'trusted', 'untrusted')),
    added_at            timestamptz NOT NULL DEFAULT now(),
    added_by            uuid REFERENCES users (id) ON DELETE SET NULL,
    trusted_at          timestamptz,
    last_fetch_at       timestamptz,
    last_fetch_ok_at    timestamptz,
    last_fetch_error    text NOT NULL DEFAULT '',
    last_browser_ok_at  timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (console_name <> mesh_name)
);
-- One pair per installation.
CREATE UNIQUE INDEX tls_added_names_one ON tls_added_names ((true));

GRANT SELECT, INSERT, UPDATE, DELETE ON tls_added_names TO easyrmm_app;

-- +goose Down
DROP TABLE tls_added_names;
