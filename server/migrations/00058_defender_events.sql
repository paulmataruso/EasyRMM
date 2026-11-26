-- Defender events (ADR-0074 section 7): the compact records the agent reads
-- from Microsoft Defender's Operational log, deduplicated on (device, epoch,
-- record). `summary` holds only what defender.view may see; every path, user
-- name, process name and the old and new value of a configuration change
-- goes in `sensitive`, which is cleared after 30 days (the row is deleted
-- after 90). A device removed from the console takes its events with it.

-- +goose Up
CREATE TABLE defender_events (
    id              bigserial PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    epoch           text NOT NULL CHECK (length(epoch) BETWEEN 1 AND 64),
    record_id       bigint NOT NULL CHECK (record_id > 0),
    event_id        integer NOT NULL CHECK (event_id BETWEEN 1 AND 65535),
    occurred_at     timestamptz NOT NULL,
    received_at     timestamptz NOT NULL DEFAULT now(),
    -- Threat severity rank: 1 Low, 2 Moderate, 4 High, 5 Severe; 0 when none.
    severity        smallint NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 5),
    threat_id       text NOT NULL DEFAULT '' CHECK (length(threat_id) <= 200),
    threat_name     text NOT NULL DEFAULT '' CHECK (length(threat_name) <= 200),
    category        text NOT NULL DEFAULT '' CHECK (length(category) <= 200),
    action          text NOT NULL DEFAULT '' CHECK (length(action) <= 200),
    -- What the console shows to defender.view: counts, versions, the error code, the kind of a configuration change.
    summary         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (octet_length(summary::text) <= 4096),
    sensitive       jsonb CHECK (sensitive IS NULL OR octet_length(sensitive::text) <= 4096),
    -- Made by EasyRMM (a winmod Defender change window): shown, never alerted.
    ours            boolean NOT NULL DEFAULT false,
    -- Read on the first run; the server stores it and alerts only for recent events.
    backfill        boolean NOT NULL DEFAULT false,
    UNIQUE (device_id, epoch, record_id)
);
CREATE INDEX defender_events_device_time_idx ON defender_events (device_id, occurred_at DESC);
CREATE INDEX defender_events_received_idx ON defender_events (received_at);

ALTER TABLE defender_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE defender_events FORCE ROW LEVEL SECURITY;
CREATE POLICY defender_events_read ON defender_events FOR SELECT
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY defender_events_write ON defender_events FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON defender_events TO easyrmm_app;
GRANT USAGE, SELECT ON SEQUENCE defender_events_id_seq TO easyrmm_app;

-- +goose Down
DROP TABLE defender_events;
