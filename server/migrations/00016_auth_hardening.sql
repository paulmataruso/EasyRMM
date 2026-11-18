-- +goose Up
-- Sign-in hardening from the Phase 9 security review.

-- Consecutive wrong second-factor codes (authenticator or recovery codes)
-- across all of a user's sign-ins. Signing in again resets the per-session
-- count but not this one, so someone who knows the password cannot keep
-- guessing codes; past a threshold the account locks like it does after
-- wrong passwords.
ALTER TABLE users ADD COLUMN mfa_failed_attempts integer NOT NULL DEFAULT 0 CHECK (mfa_failed_attempts >= 0);

-- Wrong passwords entered to confirm a sensitive change (password, recovery
-- codes, second factors) from a signed-in session. The session ends after a
-- few, so a stolen session cannot be used to guess the password.
ALTER TABLE sessions ADD COLUMN reauth_failures integer NOT NULL DEFAULT 0 CHECK (reauth_failures >= 0);

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS reauth_failures;
ALTER TABLE users DROP COLUMN IF EXISTS mfa_failed_attempts;
