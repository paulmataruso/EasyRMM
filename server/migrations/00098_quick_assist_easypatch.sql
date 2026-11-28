-- Quick Assist, EasyPatch ad hoc (ADR-0080 QA6): the enrollment token the
-- server made for a session's EasyPatch agent and the engine site it is for,
-- so the endpoint it made can be revoked when the session ends. The token's
-- secret is never stored.

-- +goose Up
ALTER TABLE quick_assist_sessions
    ADD COLUMN easypatch_state text NOT NULL DEFAULT 'none'
        CHECK (easypatch_state IN ('none', 'issuing', 'issued', 'unavailable', 'removed')),
    ADD COLUMN easypatch_token_id uuid,
    ADD COLUMN easypatch_site_id uuid;

-- +goose Down
ALTER TABLE quick_assist_sessions
    DROP COLUMN IF EXISTS easypatch_site_id,
    DROP COLUMN IF EXISTS easypatch_token_id,
    DROP COLUMN IF EXISTS easypatch_state;
