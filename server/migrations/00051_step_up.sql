-- Step-up authentication (ADR-0055, "Step-up authentication"): when a session
-- last confirmed a second factor, and the state of a fresh sign-in at the
-- provider that is under way. All of it belongs to the session, so another
-- session of the same person is not stepped up.

-- +goose Up
ALTER TABLE sessions
    -- Set only by a step-up. AuthenticatedAt is not used for it.
    ADD COLUMN stepped_up_at       timestamptz,
    -- The provider the session signed in through, if it did.
    ADD COLUMN sso_provider_id     uuid REFERENCES identity_providers (id) ON DELETE SET NULL,
    -- A fresh sign-in at that provider: the state (hashed), nonce and PKCE
    -- verifier created for this step-up, consumed once by the callback.
    ADD COLUMN step_up_state_hash  bytea,
    ADD COLUMN step_up_nonce       text,
    ADD COLUMN step_up_verifier    text,
    ADD COLUMN step_up_provider_id uuid,
    ADD COLUMN step_up_started_at  timestamptz,
    ADD COLUMN step_up_return      text;
CREATE UNIQUE INDEX sessions_step_up_state_idx ON sessions (step_up_state_hash) WHERE step_up_state_hash IS NOT NULL;
-- A security key's answer to a step-up is a ceremony of its own kind.
ALTER TABLE webauthn_challenges DROP CONSTRAINT webauthn_challenges_kind_check;
ALTER TABLE webauthn_challenges ADD CONSTRAINT webauthn_challenges_kind_check CHECK (kind IN ('register', 'mfa', 'passkey', 'stepup'));

-- +goose Down
DELETE FROM webauthn_challenges WHERE kind = 'stepup';
ALTER TABLE webauthn_challenges DROP CONSTRAINT webauthn_challenges_kind_check;
ALTER TABLE webauthn_challenges ADD CONSTRAINT webauthn_challenges_kind_check CHECK (kind IN ('register', 'mfa', 'passkey'));
DROP INDEX sessions_step_up_state_idx;
ALTER TABLE sessions
    DROP COLUMN stepped_up_at,
    DROP COLUMN sso_provider_id,
    DROP COLUMN step_up_state_hash,
    DROP COLUMN step_up_nonce,
    DROP COLUMN step_up_verifier,
    DROP COLUMN step_up_provider_id,
    DROP COLUMN step_up_started_at,
    DROP COLUMN step_up_return;
