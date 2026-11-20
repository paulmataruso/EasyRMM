-- +goose Up
-- Deployment and approval tokens can be shown again (ADR-0047): a new
-- token's secret is kept sealed with the server's encryption key, bound to
-- the token's id, beside the hash agents are checked against. Tokens made
-- before keep only their hash, and cannot be shown again.
ALTER TABLE enrollment_tokens
    ADD COLUMN token_sealed text CHECK (token_sealed IS NULL OR length(token_sealed) <= 400);
ALTER TABLE approval_tokens
    ADD COLUMN token_sealed text CHECK (token_sealed IS NULL OR length(token_sealed) <= 400);

-- +goose Down
ALTER TABLE approval_tokens DROP COLUMN IF EXISTS token_sealed;
ALTER TABLE enrollment_tokens DROP COLUMN IF EXISTS token_sealed;
