-- Monitoring and alerts (ADR-0019): alert policies at the shared,
-- organization and site levels, and the alerts they raise on devices.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Alert policies
-- ---------------------------------------------------------------------------

-- A policy watches one condition on the devices of its level: every device
-- (shared), an organization's, or a site's. Offline has no threshold; the
-- others are a percentage held for the number of minutes.
CREATE TABLE alert_policies (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid REFERENCES organizations (id) ON DELETE CASCADE,
    site_id          uuid,
    name             text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    description      text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    kind             text NOT NULL CHECK (kind IN ('offline', 'cpu', 'memory', 'disk')),
    threshold        integer CHECK (threshold BETWEEN 1 AND 100),
    minutes          integer NOT NULL CHECK (minutes BETWEEN 1 AND 1440),
    severity         text NOT NULL CHECK (severity IN ('warning', 'critical')),
    enabled          boolean NOT NULL DEFAULT true,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (site_id IS NULL OR organization_id IS NOT NULL),
    CHECK ((kind = 'offline') = (threshold IS NULL)),
    CHECK (kind <> 'offline' OR minutes >= 3),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX alert_policies_name_key ON alert_policies (organization_id, site_id, lower(name)) NULLS NOT DISTINCT;
CREATE INDEX alert_policies_site_idx ON alert_policies (site_id) WHERE site_id IS NOT NULL;
CREATE TRIGGER alert_policies_touch
    BEFORE UPDATE OF name, description, kind, threshold, minutes, severity, enabled ON alert_policies
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- New installations start watching for the usual trouble. These rows go in
-- before row-level security is on: no caller scope exists here.
INSERT INTO alert_policies (name, description, kind, threshold, minutes, severity) VALUES
    ('Device offline', 'The device has not checked in for 15 minutes.', 'offline', NULL, 15, 'critical'),
    ('Disk almost full', 'A filesystem has been at least 90% full for 5 minutes.', 'disk', 90, 5, 'critical'),
    ('High memory use', 'Memory use has stayed at 95% or more for 15 minutes.', 'memory', 95, 15, 'warning'),
    ('High processor use', 'Processor use has stayed at 95% or more for 15 minutes.', 'cpu', 95, 15, 'warning');

-- Read and written like scripts (ADR-0017): the shared policies are read
-- everywhere, an organization's in it and its sites, a site's in that site;
-- writing needs the level itself.
ALTER TABLE alert_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_policies_read ON alert_policies FOR SELECT USING (
    easyrmm_scope_all()
    OR organization_id IS NULL
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR (site_id IS NULL AND organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_read_orgs')))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
);
CREATE POLICY alert_policies_insert ON alert_policies FOR INSERT WITH CHECK (
    easyrmm_scope_all()
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
);
CREATE POLICY alert_policies_update ON alert_policies FOR UPDATE
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );
CREATE POLICY alert_policies_delete ON alert_policies FOR DELETE USING (
    easyrmm_scope_all()
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
);

-- ---------------------------------------------------------------------------
-- Alerts
-- ---------------------------------------------------------------------------

-- One policy's condition on one device. The alert keeps the policy's name,
-- condition and severity as they were, so it reads the same after the
-- policy changes or goes. seq orders alerts and pages through them.
CREATE TABLE alerts (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq              bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    policy_id        uuid REFERENCES alert_policies (id) ON DELETE SET NULL,
    device_id        uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind             text NOT NULL CHECK (kind IN ('offline', 'cpu', 'memory', 'disk')),
    threshold        integer,
    minutes          integer NOT NULL,
    severity         text NOT NULL CHECK (severity IN ('warning', 'critical')),
    status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    -- Percent for processor, memory and disk; minutes without a check-in
    -- for offline. value raised the alert; last_value is the latest.
    value            double precision NOT NULL,
    last_value       double precision NOT NULL,
    opened_at        timestamptz NOT NULL DEFAULT now(),
    -- Who acknowledged or resolved it, by e-mail as it was then; resolved
    -- by the server leaves resolved_by_label empty.
    acknowledged_at        timestamptz,
    acknowledged_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    acknowledged_by_label  text NOT NULL DEFAULT '' CHECK (length(acknowledged_by_label) <= 320),
    resolved_at            timestamptz,
    resolved_by            uuid REFERENCES users (id) ON DELETE SET NULL,
    resolved_by_label      text NOT NULL DEFAULT '' CHECK (length(resolved_by_label) <= 320),
    resolution             text CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off', 'policy_changed', 'policy_deleted')),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL)),
    CHECK ((status = 'resolved') = (resolution IS NOT NULL)),
    CHECK (status <> 'acknowledged' OR acknowledged_at IS NOT NULL)
);
-- At most one unresolved alert per policy and device.
CREATE UNIQUE INDEX alerts_active_key ON alerts (policy_id, device_id) WHERE status <> 'resolved';
CREATE INDEX alerts_device_idx ON alerts (device_id, seq DESC);
CREATE INDEX alerts_active_idx ON alerts (seq DESC) WHERE status <> 'resolved';
CREATE INDEX alerts_resolved_idx ON alerts (resolved_at) WHERE status = 'resolved';

-- Alerts follow their device: whoever sees the device sees its alerts, and
-- may acknowledge or resolve them (the service checks alert.manage). Only
-- the server (the system scope) raises and removes them.
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY alerts_read ON alerts FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY alerts_insert ON alerts FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY alerts_update ON alerts FOR UPDATE
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id))
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY alerts_delete ON alerts FOR DELETE USING (easyrmm_scope_all());

GRANT SELECT, INSERT, UPDATE, DELETE ON alert_policies, alerts TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS alerts, alert_policies;
