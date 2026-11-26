-- Quick Assist sessions (ADR-0080): one run of the runner on one computer.

-- +goose Up
CREATE TABLE quick_assist_sessions (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id           uuid NOT NULL REFERENCES quick_assist_links (id) ON DELETE CASCADE,
    organization_id   uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id         uuid REFERENCES devices (id) ON DELETE SET NULL,
    state             text NOT NULL DEFAULT 'requested'
        CHECK (state IN ('requested', 'active', 'declined', 'ended', 'lost', 'converted')),
    -- sha256(session id || code); the server alone compares it.
    session_code_hash bytea NOT NULL,
    code_failures     integer NOT NULL DEFAULT 0,
    elevated          boolean NOT NULL DEFAULT false,
    consent_at        timestamptz,
    requested_at      timestamptz NOT NULL DEFAULT now(),
    accepted_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    accepted_at       timestamptz,
    ended_at          timestamptz,
    end_reason        text NOT NULL DEFAULT '',
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    cleanup           text NOT NULL DEFAULT 'none' CHECK (cleanup IN ('none', 'verified', 'residue', 'unconfirmed')),
    cleanup_report    jsonb,
    source_ip         text NOT NULL DEFAULT '',
    expires_at        timestamptz NOT NULL
);
CREATE INDEX quick_assist_sessions_org_idx ON quick_assist_sessions (organization_id, state, requested_at DESC);
CREATE INDEX quick_assist_sessions_link_idx ON quick_assist_sessions (link_id);
CREATE UNIQUE INDEX quick_assist_sessions_device_uq ON quick_assist_sessions (device_id) WHERE device_id IS NOT NULL AND state IN ('requested', 'active');

ALTER TABLE quick_assist_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE quick_assist_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY quick_assist_sessions_tenant ON quick_assist_sessions
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
GRANT SELECT, INSERT, UPDATE, DELETE ON quick_assist_sessions TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS quick_assist_sessions;
