-- The Windows roles a device's agent reported (ADR-0073, slice 1): the list,
-- when it was reported, and whether someone asked for a rescan. NULL roles
-- means the server was never told, which it reads as unknown, not absent.

-- +goose Up
ALTER TABLE devices
    ADD COLUMN roles          jsonb CHECK (roles IS NULL OR (jsonb_typeof(roles) = 'array' AND pg_column_size(roles) <= 4096)),
    ADD COLUMN roles_at       timestamptz,
    ADD COLUMN roles_rescan   boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE devices
    DROP COLUMN roles_rescan,
    DROP COLUMN roles_at,
    DROP COLUMN roles;
