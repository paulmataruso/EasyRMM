-- +goose Up
-- Security keys and passkeys (ADR-0032). Like the other authentication
-- tables, these are reached only through the authentication service.

-- A user's WebAuthn credentials. `credential` is the library's record of the
-- credential (public key, flags, signature counter, transports, AAGUID); the
-- id, owner and name are columns for lookups and the console.
CREATE TABLE user_webauthn_credentials (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE CHECK (length(credential_id) BETWEEN 1 AND 1023),
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    credential    jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    UNIQUE (user_id, name)
);
CREATE INDEX user_webauthn_credentials_user_idx ON user_webauthn_credentials (user_id);

-- A ceremony in progress: what the server asked the browser for, found again
-- by its challenge when the browser answers, and used once. Registration and
-- the second-factor step belong to a sign-in session; passkey sign-in has
-- none yet.
CREATE TABLE webauthn_challenges (
    challenge   text PRIMARY KEY CHECK (length(challenge) BETWEEN 16 AND 128),
    kind        text NOT NULL CHECK (kind IN ('register', 'mfa', 'passkey')),
    session_id  uuid REFERENCES sessions (id) ON DELETE CASCADE,
    data        jsonb NOT NULL,
    expires_at  timestamptz NOT NULL,
    CHECK ((kind = 'passkey') = (session_id IS NULL))
);
CREATE INDEX webauthn_challenges_expiry_idx ON webauthn_challenges (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_webauthn_credentials, webauthn_challenges TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS webauthn_challenges, user_webauthn_credentials;
