-- Signing in to Microsoft 365 for mail (ADR-0053, slice 2), and two
-- follow-ups from the review of slice 1.
--
-- mail_server gains a third way to sign in, a Microsoft 365 application:
-- the tenant, the application (client) ID, and a client secret or a
-- certificate with its private key, the secret and the key sealed with
-- EASYRMM_SECRET_KEY (each bound to its column). The mailbox it sends as is
-- the sender's address, and it signs in only over STARTTLS or TLS.
--
-- mail_engine_given keeps the digest of the mail server the patching
-- engine is given under every secret key the server that gives it has,
-- named by the key's ID, so that a server comparing its own during a key
-- rotation finds one key in common rather than reporting that its mail
-- server differs.
--
-- mail_account_buckets carries each account's password-email bucket past
-- the 24 hours mail_sends keeps: rows leaving mail_sends are folded into
-- it, so that the limit of 3 at once and then one every 20 minutes holds
-- exactly, not only over the last 24 hours.
--
-- mail_server and mail_engine_given hold one row each, so nothing here
-- rewrites a big table.

-- +goose Up

ALTER TABLE mail_server
    ADD COLUMN tenant_id           text NOT NULL DEFAULT '' CHECK (length(tenant_id) <= 253),
    ADD COLUMN client_id           text NOT NULL DEFAULT '' CHECK (client_id = '' OR client_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'),
    -- secret or certificate, '' unless an application signs in.
    ADD COLUMN client_credential   text NOT NULL DEFAULT '' CHECK (client_credential IN ('', 'secret', 'certificate')),
    ADD COLUMN client_secret_sealed text NOT NULL DEFAULT '',
    -- The certificate (PEM, with any chain after it) is not secret; its
    -- private key is sealed.
    ADD COLUMN client_certificate  text NOT NULL DEFAULT '' CHECK (length(client_certificate) <= 65536),
    ADD COLUMN client_key_sealed   text NOT NULL DEFAULT '';

ALTER TABLE mail_server DROP CONSTRAINT mail_server_sign_in_check;
ALTER TABLE mail_server ADD CONSTRAINT mail_server_sign_in_check CHECK (sign_in IN ('none', 'password', 'microsoft365'));
ALTER TABLE mail_server ADD CONSTRAINT mail_server_application_check CHECK (
    (sign_in = 'microsoft365') = (tenant_id <> '')
    AND (sign_in = 'microsoft365') = (client_id <> '')
    AND (sign_in = 'microsoft365') = (client_credential <> '')
    AND (client_credential = 'secret') = (client_secret_sealed <> '')
    AND (client_credential = 'certificate') = (client_certificate <> '')
    AND (client_credential = 'certificate') = (client_key_sealed <> ''));
-- A token is sent only over TLS: never with security none.
ALTER TABLE mail_server ADD CONSTRAINT mail_server_application_tls_check CHECK (sign_in <> 'microsoft365' OR security <> 'none');

-- Digests by key ID, hex: {"k1": "…", "k0": "…"}. The leader records them
-- again at its next pass.
ALTER TABLE mail_engine_given DROP COLUMN digest;
ALTER TABLE mail_engine_given ADD COLUMN digests jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(digests) = 'object');

-- Each account's password-email bucket, from the messages that left
-- mail_sends: when it is full again (the generic cell rate algorithm's
-- theoretical arrival time). A row whose time is more than 24 hours past
-- no longer changes anything, and is deleted. No foreign key, as for
-- mail_sends: a row outlives a deleted account for at most a day.
CREATE TABLE mail_account_buckets (
    account_id  uuid PRIMARY KEY,
    full_at     timestamptz NOT NULL
);

ALTER TABLE mail_account_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_account_buckets FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_account_buckets_system ON mail_account_buckets TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON mail_account_buckets TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS mail_account_buckets;

-- As 00030 made it: the leader records its digest again at its next pass.
-- (The migrations' role has no policy on it, so it is made again rather
-- than emptied.)
DROP TABLE mail_engine_given;
CREATE TABLE mail_engine_given (
    id        boolean PRIMARY KEY DEFAULT true CHECK (id),
    digest    bytea NOT NULL CHECK (length(digest) = 32),
    given_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE mail_engine_given ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_engine_given FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_engine_given_system ON mail_engine_given TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE ON mail_engine_given TO easyrmm_app;

-- An application signing in has no place before this migration: the
-- console's mail server is removed, as Delete does, its limits kept.
ALTER TABLE mail_server DROP CONSTRAINT mail_server_application_tls_check;
ALTER TABLE mail_server DROP CONSTRAINT mail_server_application_check;
UPDATE mail_server SET host = '', port = 587, security = 'starttls', sign_in = 'none', username = '', password_sealed = '',
    from_address = '', from_name = '' WHERE sign_in = 'microsoft365';
ALTER TABLE mail_server DROP CONSTRAINT mail_server_sign_in_check;
ALTER TABLE mail_server ADD CONSTRAINT mail_server_sign_in_check CHECK (sign_in IN ('none', 'password'));
ALTER TABLE mail_server
    DROP COLUMN client_key_sealed,
    DROP COLUMN client_certificate,
    DROP COLUMN client_secret_sealed,
    DROP COLUMN client_credential,
    DROP COLUMN client_id,
    DROP COLUMN tenant_id;
