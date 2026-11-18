-- +goose Up
-- EasyRMM as EasyPatch's OpenID provider (ADR-0036). Reached only through the
-- authentication and provider services, like the other authentication tables.

-- How each session signed in, as OpenID Connect amr values (RFC 8176): pwd,
-- fed (single sign-on), otp, hwk, rc (a recovery code) and mfa. Sessions from
-- before this have none, so they cannot sign in to EasyPatch until their
-- person signs in again. authenticated_at is when the session became active.
ALTER TABLE sessions ADD COLUMN amr text[] NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD COLUMN authenticated_at timestamptz;

-- The one client: EasyPatch. Its secret is kept only as a SHA-256 hash (it
-- is 256 random bits); its redirect URI is matched exactly.
CREATE TABLE idp_clients (
    client_id     text PRIMARY KEY CHECK (length(client_id) BETWEEN 8 AND 64),
    secret_hash   bytea NOT NULL CHECK (length(secret_hash) = 32),
    redirect_uri  text NOT NULL CHECK (length(redirect_uri) BETWEEN 8 AND 2048),
    created_at    timestamptz NOT NULL DEFAULT now(),
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    rotated_at    timestamptz,
    rotated_by    uuid REFERENCES users (id) ON DELETE SET NULL
);
-- At most one client.
CREATE UNIQUE INDEX idp_clients_one ON idp_clients ((true));

-- ID token signing keys (ES256), sealed under the secret key (additional
-- data: the key id).
CREATE TABLE idp_signing_keys (
    kid             text PRIMARY KEY CHECK (length(kid) BETWEEN 8 AND 64),
    private_sealed  text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Authorization codes: single use, valid 60 seconds, stored hashed, bound to
-- the client, redirect URI, session, nonce and PKCE challenge.
CREATE TABLE idp_codes (
    code_hash       bytea PRIMARY KEY CHECK (length(code_hash) = 32),
    client_id       text NOT NULL REFERENCES idp_clients (client_id) ON DELETE CASCADE,
    redirect_uri    text NOT NULL,
    session_id      uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    nonce           text NOT NULL CHECK (length(nonce) BETWEEN 1 AND 512),
    code_challenge  text NOT NULL CHECK (length(code_challenge) = 43),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz
);
CREATE INDEX idp_codes_expiry_idx ON idp_codes (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON idp_clients, idp_signing_keys, idp_codes TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS idp_codes, idp_signing_keys, idp_clients;
ALTER TABLE sessions DROP COLUMN IF EXISTS authenticated_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS amr;
