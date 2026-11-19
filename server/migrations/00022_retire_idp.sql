-- +goose Up
-- EasyRMM is no longer EasyPatch's OpenID provider (ADR-0046, retiring
-- ADR-0036): the patching engine runs in the deployment and takes EasyRMM's
-- statements instead. Its client, signing keys and codes go. Sessions keep
-- amr and authenticated_at, which EasyRMM's own sign-in still records.
DROP TABLE IF EXISTS idp_codes, idp_signing_keys, idp_clients;

-- +goose Down
-- Recreates the tables empty, as 00019 made them: the client's secret and
-- the signing keys are not kept, so EasyPatch would have to be registered
-- again.
CREATE TABLE idp_clients (
    client_id     text PRIMARY KEY CHECK (length(client_id) BETWEEN 8 AND 64),
    secret_hash   bytea NOT NULL CHECK (length(secret_hash) = 32),
    redirect_uri  text NOT NULL CHECK (length(redirect_uri) BETWEEN 8 AND 2048),
    created_at    timestamptz NOT NULL DEFAULT now(),
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    rotated_at    timestamptz,
    rotated_by    uuid REFERENCES users (id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idp_clients_one ON idp_clients ((true));
CREATE TABLE idp_signing_keys (
    kid             text PRIMARY KEY CHECK (length(kid) BETWEEN 8 AND 64),
    private_sealed  text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
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
