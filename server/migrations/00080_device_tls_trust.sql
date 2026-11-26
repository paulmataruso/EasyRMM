-- ADR-0055 slice 5b1: what each device really trusts. The server asks a
-- device's agent to verify the certificate chain a name is served with, with
-- the trust the computer has (the system's roots, its CA file and what an
-- instruction adds), and keeps the answer per device and chain.
--
--   device_tls_trust  one row per device, scope (the EasyRMM agent's own trust,
--                     or the EasyPatch agent's, which the EasyRMM agent checks
--                     against the system's roots alone), host and purpose
--                     (served now, fallback, or a move's target): the chain
--                     asked about, the instruction it went out in, and the
--                     result. It follows devices: read-only for a person who
--                     can see the device, written by the server.
--   device_tls_state  what the agent last said it is: the origin its requests
--                     arrive at, its build, whether it understands trust
--                     instructions, and what it trusts.
--
-- No key or secret is stored: chains are public certificates.

-- +goose Up
CREATE TABLE device_tls_trust (
    device_id    uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    scope        text NOT NULL CHECK (scope IN ('agent', 'easypatch')),
    host         text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    purpose      text NOT NULL CHECK (purpose IN ('served', 'fallback', 'target')),
    -- The chain asked about: its certificates (DER, base64), leaf first, and
    -- their digest. A different digest is a different question.
    chain        jsonb NOT NULL,
    chain_digest text NOT NULL CHECK (length(chain_digest) = 64),
    -- Certificates the move adds to the agent's trust once the target verifies.
    add_certs    jsonb NOT NULL DEFAULT '[]',
    -- The chain's ID inside the instruction, and the instruction's ID once sent.
    chain_id     text NOT NULL CHECK (length(chain_id) BETWEEN 1 AND 64),
    request_id   text CHECK (length(request_id) <= 64),
    state        text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'passed', 'failed')),
    error        text NOT NULL DEFAULT '' CHECK (length(error) <= 300),
    requested_at timestamptz NOT NULL DEFAULT now(),
    sent_at      timestamptz,
    checked_at   timestamptz,
    PRIMARY KEY (device_id, scope, host, purpose)
);
CREATE INDEX device_tls_trust_pending ON device_tls_trust (device_id) WHERE state = 'pending';

CREATE TABLE device_tls_state (
    device_id    uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    origin       text NOT NULL DEFAULT '' CHECK (length(origin) <= 253),
    agent_sha256 text NOT NULL DEFAULT '' CHECK (length(agent_sha256) <= 64),
    -- Set once the agent's heartbeat listed the capability.
    capable      boolean NOT NULL DEFAULT false,
    capable_at   timestamptz,
    -- What the agent last reported: "system", "ca-file" or "system+ca-file".
    trusts       text NOT NULL DEFAULT '' CHECK (length(trusts) <= 20),
    widened      boolean NOT NULL DEFAULT false,
    reported_at  timestamptz,
    -- The last refusal the agent reported for an instruction, and its ID, so
    -- that a refusal repeated at every heartbeat is audited once.
    refused      text NOT NULL DEFAULT '' CHECK (length(refused) <= 300),
    refused_id   text NOT NULL DEFAULT '' CHECK (length(refused_id) <= 64),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE device_tls_trust ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_tls_trust FORCE ROW LEVEL SECURITY;
CREATE POLICY device_tls_trust_read ON device_tls_trust FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_tls_trust_write ON device_tls_trust FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_tls_trust TO easyrmm_app;

ALTER TABLE device_tls_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_tls_state FORCE ROW LEVEL SECURITY;
CREATE POLICY device_tls_state_read ON device_tls_state FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_tls_state_write ON device_tls_state FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_tls_state TO easyrmm_app;

-- +goose Down
DROP TABLE device_tls_state;
DROP TABLE device_tls_trust;
