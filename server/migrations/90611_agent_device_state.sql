-- Settings that reach the agent, slice 2 (ADR-0058): what each enrolled
-- device's agent understands, the settings document the server last issued
-- for it, and what the agent says it applied.
--
--   agent_device_state   one row per enrolled device, written lazily by its
--                        heartbeats, read FOR UPDATE when a document is
--                        issued, so that two heartbeats at once cannot issue
--                        one version with two contents. It goes with the
--                        device (the foreign key cascades) and follows it in
--                        a move: its organization and site are the device's,
--                        read through devices, so nothing here is updated.
--
-- Not on devices, whose updated_at moves only for real edits.

-- +goose Up
CREATE TABLE agent_device_state (
    device_id            uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    -- What the agent last reported it understands (capabilities: the messages
    -- it accepts and each key with its schema version), the build that
    -- reported it (its SHA-256, or "version:<v>" for an agent that sends
    -- none), and the time the heartbeat carrying it was signed. NULL after a
    -- change of build without a report: the device counts as one whose agent
    -- reports nothing until it reports.
    capabilities         jsonb CHECK (capabilities IS NULL OR jsonb_typeof(capabilities) = 'object'),
    capabilities_build   text CHECK (capabilities_build IS NULL OR length(capabilities_build) <= 300),
    capabilities_at      timestamptz,
    -- The last document issued: its version, the hash of its settings, when
    -- it was issued and under which version of the server's catalogue (it
    -- rises with every release that changes the catalogue).
    doc_version          bigint CHECK (doc_version IS NULL OR doc_version BETWEEN 1 AND 9007199254740991),
    doc_hash             text CHECK (doc_hash IS NULL OR length(doc_hash) = 64),
    doc_issued_at        timestamptz,
    doc_catalog_version  integer CHECK (doc_catalog_version IS NULL OR doc_catalog_version >= 1),
    -- What the agent reported applying: the version, the hash of the document
    -- of that version (when it is the one issued last), when it first
    -- reported it, and the problems it reported.
    applied_version      bigint NOT NULL DEFAULT 0 CHECK (applied_version BETWEEN 0 AND 9007199254740991),
    applied_hash         text CHECK (applied_hash IS NULL OR length(applied_hash) = 64),
    applied_at           timestamptz,
    problems             jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(problems) = 'object' AND octet_length(problems::text) <= 16384),
    -- Heartbeats with the report since the current version was issued
    -- without the version applied; three flag the device (Not applied).
    not_applied_heartbeats integer NOT NULL DEFAULT 0 CHECK (not_applied_heartbeats >= 0),
    -- The signed time of the latest heartbeat processed for the device; one
    -- signed earlier does not move it.
    heartbeat_signed_at  timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE agent_device_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_device_state FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_device_state_read ON agent_device_state FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY agent_device_state_write ON agent_device_state FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_device_state TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS agent_device_state;
