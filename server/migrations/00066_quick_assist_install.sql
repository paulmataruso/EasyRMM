-- Quick Assist, install permanently (ADR-0080 QA5): the technician's request,
-- the user's consent, the conversion token and the device that results.

-- +goose Up
ALTER TABLE quick_assist_sessions
    ADD COLUMN install_state text NOT NULL DEFAULT 'none'
        CHECK (install_state IN ('none', 'requested', 'consented', 'declined', 'converted')),
    ADD COLUMN install_by uuid REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN install_token_id uuid REFERENCES enrollment_tokens (id) ON DELETE SET NULL,
    ADD COLUMN converted_device_id uuid REFERENCES devices (id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE quick_assist_sessions
    DROP COLUMN IF EXISTS converted_device_id,
    DROP COLUMN IF EXISTS install_token_id,
    DROP COLUMN IF EXISTS install_by,
    DROP COLUMN IF EXISTS install_state;
