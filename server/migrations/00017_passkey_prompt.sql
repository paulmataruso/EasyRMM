-- +goose Up
-- After signing in with a password and a code, users without a passkey are
-- offered one (ADR-0032). "Not now" puts the offer off until
-- passkey_prompt_after; "Don't ask again" sets passkey_prompt_declined_at.
ALTER TABLE users
    ADD COLUMN passkey_prompt_after timestamptz,
    ADD COLUMN passkey_prompt_declined_at timestamptz;

-- +goose Down
ALTER TABLE users
    DROP COLUMN IF EXISTS passkey_prompt_declined_at,
    DROP COLUMN IF EXISTS passkey_prompt_after;
