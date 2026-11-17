-- +goose Up
-- Single sign-on with OpenID Connect (ADR-0034). Reached only through the
-- single sign-on service, like the other authentication tables.

-- An identity provider set up by a super administrator. The client secret is
-- sealed under the secret key (additional data: the provider's id).
CREATE TABLE identity_providers (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
    issuer                text NOT NULL CHECK (length(issuer) BETWEEN 8 AND 2048),
    client_id             text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 512),
    client_secret_sealed  text NOT NULL,
    -- Lower-case email domains whose people may sign in through it.
    allowed_domains       text[] NOT NULL CHECK (cardinality(allowed_domains) BETWEEN 1 AND 50),
    -- Its email addresses are managed by the organization, so they count as
    -- verified without an email_verified claim (Microsoft Entra ID).
    trust_email           boolean NOT NULL DEFAULT false,
    -- It enforces multi-factor authentication, so EasyRMM's second factor is
    -- skipped after it.
    trust_mfa             boolean NOT NULL DEFAULT false,
    enabled               boolean NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

-- A provider's account linked to an EasyRMM user: the provider and the ID
-- token's subject identify it. The email is what the provider sent when the
-- link was made, for administrators to read.
CREATE TABLE user_identities (
    provider_id   uuid NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    subject       text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email         text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    PRIMARY KEY (provider_id, subject),
    UNIQUE (provider_id, user_id)
);
CREATE INDEX user_identities_user_idx ON user_identities (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_providers, user_identities TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS user_identities, identity_providers;
