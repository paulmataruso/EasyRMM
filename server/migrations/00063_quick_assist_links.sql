-- Quick Assist (ADR-0080): the links a technician gives a user, the site
-- that holds a session's devices, and the flag that keeps those devices out
-- of the ordinary device views.

-- +goose Up
ALTER TABLE sites ADD COLUMN kind text NOT NULL DEFAULT 'normal' CHECK (kind IN ('normal', 'quick_assist'));
CREATE UNIQUE INDEX sites_quick_assist_uq ON sites (organization_id) WHERE kind = 'quick_assist';

ALTER TABLE devices ADD COLUMN quick_assist boolean NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN origin_session_id uuid;

CREATE TABLE quick_assist_links (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid,
    kind            text NOT NULL CHECK (kind IN ('one_time', 'permanent')),
    name            text NOT NULL DEFAULT '' CHECK (char_length(name) <= 100),
    note            text NOT NULL DEFAULT '' CHECK (char_length(note) <= 1000),
    token_hash      bytea NOT NULL UNIQUE,
    state           text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'used', 'expired', 'revoked')),
    paused          boolean NOT NULL DEFAULT false,
    -- A test link, made while the link mode was own_test: only its maker
    -- accepts a session from it.
    test            boolean NOT NULL DEFAULT false,
    expires_at      timestamptz,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    used_at         timestamptz,
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    revoked_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    download_count  integer NOT NULL DEFAULT 0,
    -- The per-link token bucket (ADR-0080): tokens left and when they were
    -- last topped up.
    bucket_tokens   double precision NOT NULL DEFAULT 5,
    bucket_at       timestamptz NOT NULL DEFAULT now(),
    last_alert_at   timestamptz,
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE,
    CHECK (kind <> 'one_time' OR (expires_at IS NOT NULL AND expires_at <= created_at + interval '7 days'))
);
CREATE INDEX quick_assist_links_org_idx ON quick_assist_links (organization_id, created_at DESC);

ALTER TABLE quick_assist_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE quick_assist_links FORCE ROW LEVEL SECURITY;
CREATE POLICY quick_assist_links_tenant ON quick_assist_links
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
GRANT SELECT, INSERT, UPDATE, DELETE ON quick_assist_links TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS quick_assist_links;
ALTER TABLE devices DROP COLUMN IF EXISTS origin_session_id;
ALTER TABLE devices DROP COLUMN IF EXISTS quick_assist;
DROP INDEX IF EXISTS sites_quick_assist_uq;
ALTER TABLE sites DROP COLUMN IF EXISTS kind;
