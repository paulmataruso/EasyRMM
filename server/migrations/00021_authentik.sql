-- +goose Up
-- Authentik in the deployment (one-product plan, phase A; ADR-0044).

-- A provider the deployment sets up from its configuration rather than a
-- super administrator: Settings shows it, locked.
ALTER TABLE identity_providers ADD COLUMN managed boolean NOT NULL DEFAULT false;

-- One-time sign-in links that `easyrmm-server recover` prints for a super
-- administrator, for when single sign-on is down. Only the hash of the
-- token is kept; a link is used once and lasts minutes. Reached only
-- through the authentication service, like password_reset_tokens.
CREATE TABLE recovery_links (
    token_hash  bytea PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX recovery_links_user_idx ON recovery_links (user_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_links TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS recovery_links;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS managed;
