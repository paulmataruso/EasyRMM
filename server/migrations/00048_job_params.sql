-- Job params (ADR-0073, slice 3).
--
-- A job may carry params: a JSON object the agent writes to the script's
-- standard input. The row keeps the params without any secret (a secret is
-- sealed apart and placed in the params only at delivery) and the SHA-256 of
-- the canonical form, for the audit. A job with params requires the
-- job.params capability, so an agent from before it is never sent one.

-- +goose Up
ALTER TABLE jobs
    ADD COLUMN params jsonb,
    ADD COLUMN params_sha256 bytea,
    ADD CONSTRAINT jobs_params_check CHECK (
        (params IS NULL AND params_sha256 IS NULL)
        OR (jsonb_typeof(params) = 'object' AND length(params_sha256) = 32 AND octet_length(params::text) <= 16384));

-- 00028 grants the server's role every column of this table but the
-- arguments, by name: the new ones too.
GRANT SELECT (params, params_sha256) ON jobs TO easyrmm_app;

-- +goose Down
ALTER TABLE jobs DROP CONSTRAINT jobs_params_check,
    DROP COLUMN params_sha256,
    DROP COLUMN params;
