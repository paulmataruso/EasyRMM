-- Enrollment with approval (ADR-0024): an install command that is not tied
-- to a site. Agents installed with it wait until someone approves them in
-- the console and chooses where they belong.

-- +goose Up

-- An approval token enrolls into no site of its own: every device it
-- brings in waits in enrollment_requests. Platform-wide, like the requests.
CREATE TABLE approval_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    token_hash    bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    expires_at    timestamptz NOT NULL,
    -- How many devices may ask to enroll with it; NULL is no limit.
    max_uses      integer CHECK (max_uses IS NULL OR max_uses BETWEEN 1 AND 100000),
    uses          integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

-- A device that asked to enroll with an approval token. The agent keeps
-- asking with the same key until the request is decided; approving it
-- creates the device in the chosen site with that key.
CREATE TABLE enrollment_requests (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id        uuid NOT NULL REFERENCES approval_tokens (id) ON DELETE CASCADE,
    public_key      bytea NOT NULL UNIQUE CHECK (length(public_key) = 32),
    hostname        text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 255),
    os_description  text NOT NULL CHECK (length(os_description) <= 500),
    platform        text NOT NULL CHECK (length(platform) <= 20),
    agent_version   text NOT NULL CHECK (length(agent_version) <= 64),
    agent_arch      text NOT NULL CHECK (length(agent_arch) <= 32),
    source_ip       inet,
    state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'rejected')),
    -- The device an approval created; deleting the device deletes the request.
    device_id       uuid REFERENCES devices (id) ON DELETE CASCADE,
    decided_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    decided_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- When the agent last asked: an agent that stops asking was removed.
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    CHECK ((state = 'approved') = (device_id IS NOT NULL)),
    CHECK ((state = 'pending') = (decided_at IS NULL))
);
CREATE INDEX enrollment_requests_token_idx ON enrollment_requests (token_id);
CREATE INDEX enrollment_requests_state_idx ON enrollment_requests (state, created_at);

ALTER TABLE approval_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY approval_tokens_platform ON approval_tokens
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE enrollment_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_requests_platform ON enrollment_requests
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

GRANT SELECT, INSERT, UPDATE ON approval_tokens TO easyrmm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_requests TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS enrollment_requests;
DROP TABLE IF EXISTS approval_tokens;
