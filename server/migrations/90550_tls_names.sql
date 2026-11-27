-- ADR-0055, slice 5b2: per-name certificate sources and moves between them.
--
--   tls_names  one row per DNS name the console has made a choice for: the
--              source it is served from now (env: what .env gives it, acme:
--              Let's Encrypt, authority: the internal authority), and, while
--              a move is waiting on devices, its target and the chain held
--              back (public certificates; no key is stored here).
--
-- A platform table like tls_certificates: outside row-level security,
-- reached only through the certificate service, which requires
-- settings.manage.

-- +goose Up
CREATE TABLE tls_names (
    name              text PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 253),
    source            text NOT NULL DEFAULT 'env' CHECK (source IN ('env', 'acme', 'authority')),
    move_target       text CHECK (move_target IS NULL OR move_target IN ('env', 'acme', 'authority')),
    move_started_at   timestamptz,
    move_started_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    -- The chain the move will serve (DER, base64, leaf first), the
    -- authorities it adds to agents' trust, and notes the page shows (a
    -- skipped trial order, with why).
    move_chain        jsonb NOT NULL DEFAULT '[]',
    move_add_certs    jsonb NOT NULL DEFAULT '[]',
    move_notes        jsonb NOT NULL DEFAULT '[]',
    acme_account_url  text,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CHECK ((move_target IS NULL) = (move_started_at IS NULL)),
    CHECK (move_target IS NULL OR move_target <> source)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON tls_names TO easyrmm_app;

-- +goose Down
DROP TABLE tls_names;
