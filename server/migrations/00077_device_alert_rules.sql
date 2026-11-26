-- ADR-0053 slice 4: device alert rules, the alerts' journal, incidents, the
-- planner's records, maintenance windows, site outages and the fleet-wide
-- hold. Every table has row-level security forced.

-- +goose Up

-- ---------------------------------------------------------------------------
-- A device's kind
-- ---------------------------------------------------------------------------

-- agent_role is what the agent reported; role is what someone with
-- monitoring.manage set, which wins. Neither known: the server reads the
-- operating system's description. agent_uninstalled_at is set by slice 7;
-- site outages and the fleet-wide hold already leave such devices out.
ALTER TABLE devices
    ADD COLUMN agent_role text CHECK (agent_role IN ('server', 'workstation')),
    ADD COLUMN role text CHECK (role IN ('server', 'workstation')),
    ADD COLUMN role_set_by uuid,
    ADD COLUMN agent_uninstalled_at timestamptz;

-- ---------------------------------------------------------------------------
-- Rules
-- ---------------------------------------------------------------------------

CREATE TABLE notification_rules (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    owner           uuid NOT NULL,
    source          text NOT NULL DEFAULT 'alerts' CHECK (source IN ('alerts', 'notices')),
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    enabled         boolean NOT NULL DEFAULT true,
    -- Each dimension is any or a list. The three below keep their list in a
    -- table of its own; an empty list matches nothing.
    orgs_mode       text NOT NULL DEFAULT 'any' CHECK (orgs_mode IN ('any', 'list')),
    sites_mode      text NOT NULL DEFAULT 'any' CHECK (sites_mode IN ('any', 'list')),
    groups_mode     text NOT NULL DEFAULT 'any' CHECK (groups_mode IN ('any', 'list')),
    -- NULL is any; an empty array matches nothing.
    device_kinds    text[] CHECK (device_kinds <@ ARRAY['server', 'workstation']),
    severities      text[] CHECK (severities <@ ARRAY['warning', 'critical']),
    -- Alert kinds (offline, cpu, memory, disk, disk_health, ...) or, for
    -- notice rules, notice kinds; agent_removed is the condition of that name.
    conditions      text[],
    -- The disk-health checks, when disk_health is among the conditions.
    checks          text[] CHECK (checks <@ ARRAY['failing', 'errors', 'pending', 'wear', 'temperature']),
    wait_minutes    integer NOT NULL DEFAULT 0 CHECK (wait_minutes BETWEEN 0 AND 1440),
    on_resolve      boolean NOT NULL DEFAULT true,
    on_acknowledge  boolean NOT NULL DEFAULT false,
    reminder_hours  integer NOT NULL DEFAULT 0 CHECK (reminder_hours BETWEEN 0 AND 720),
    ignore_windows  boolean NOT NULL DEFAULT false CHECK (NOT ignore_windows OR owner = '00000000-0000-0000-0000-000000000000'),
    group_outages   boolean NOT NULL DEFAULT true,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT notification_rules_owner CHECK (owner = coalesce(organization_id, '00000000-0000-0000-0000-000000000000')),
    CONSTRAINT notification_rules_org_lists CHECK (orgs_mode = 'any' OR owner = '00000000-0000-0000-0000-000000000000'),
    CONSTRAINT notification_rules_id_owner UNIQUE (id, owner)
);
CREATE UNIQUE INDEX notification_rules_name ON notification_rules (owner, lower(name));
CREATE TRIGGER notification_rules_touch BEFORE UPDATE ON notification_rules
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- A platform rule's organizations.
CREATE TABLE notification_rule_orgs (
    rule_id         uuid NOT NULL,
    owner           uuid NOT NULL CHECK (owner = '00000000-0000-0000-0000-000000000000'),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, organization_id),
    FOREIGN KEY (rule_id, owner) REFERENCES notification_rules (id, owner) ON DELETE CASCADE
);
CREATE INDEX notification_rule_orgs_org ON notification_rule_orgs (organization_id);

-- Sites, as (organization, site): an organization's rule lists only its own.
CREATE TABLE notification_rule_sites (
    rule_id         uuid NOT NULL,
    owner           uuid NOT NULL,
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    PRIMARY KEY (rule_id, site_id),
    CHECK (owner = '00000000-0000-0000-0000-000000000000' OR owner = organization_id),
    FOREIGN KEY (rule_id, owner) REFERENCES notification_rules (id, owner) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX notification_rule_sites_site ON notification_rule_sites (site_id);

-- Device groups, as (site, group), as device_groups itself refers to its site.
CREATE TABLE notification_rule_groups (
    rule_id         uuid NOT NULL,
    owner           uuid NOT NULL,
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    device_group_id uuid NOT NULL,
    PRIMARY KEY (rule_id, device_group_id),
    CHECK (owner = '00000000-0000-0000-0000-000000000000' OR owner = organization_id),
    FOREIGN KEY (rule_id, owner) REFERENCES notification_rules (id, owner) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (site_id, device_group_id) REFERENCES device_groups (site_id, id) ON DELETE CASCADE
);
CREATE INDEX notification_rule_groups_group ON notification_rule_groups (device_group_id);

-- A rule's channels: its owner's own, or a platform channel shared with it.
CREATE TABLE notification_rule_channels (
    rule_id       uuid NOT NULL,
    owner         uuid NOT NULL,
    channel_id    uuid NOT NULL,
    channel_owner uuid NOT NULL,
    PRIMARY KEY (rule_id, channel_id),
    CHECK (channel_owner = owner OR channel_owner = '00000000-0000-0000-0000-000000000000'),
    FOREIGN KEY (rule_id, owner) REFERENCES notification_rules (id, owner) ON DELETE CASCADE,
    FOREIGN KEY (channel_id, channel_owner) REFERENCES notification_channels (id, owner) ON DELETE CASCADE
);
CREATE INDEX notification_rule_channels_channel ON notification_rule_channels (channel_id);

-- An organization's rule may link a platform channel only while it is shared
-- with it; at most 20 channels a rule.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_rule_channel_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF NEW.owner <> '00000000-0000-0000-0000-000000000000'
       AND NEW.channel_owner = '00000000-0000-0000-0000-000000000000'
       AND NOT EXISTS (SELECT 1 FROM notification_channel_shares s
                       WHERE s.channel_id = NEW.channel_id AND s.organization_id = NEW.owner) THEN
        RAISE EXCEPTION 'channel not shared with this organization' USING ERRCODE = '23514', CONSTRAINT = 'notification_rule_channels_shared';
    END IF;
    IF (SELECT count(*) FROM notification_rule_channels WHERE rule_id = NEW.rule_id) >= 20 THEN
        RAISE EXCEPTION 'a rule has at most 20 channels' USING ERRCODE = '23514', CONSTRAINT = 'notification_rule_channels_max';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_rule_channel_check() FROM PUBLIC;
CREATE TRIGGER notification_rule_channels_check BEFORE INSERT ON notification_rule_channels
    FOR EACH ROW EXECUTE FUNCTION easyrmm_rule_channel_check();

-- Unsharing removes the links that depended on it.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_unshare_links() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    DELETE FROM notification_rule_channels WHERE channel_id = OLD.channel_id AND owner = OLD.organization_id;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_unshare_links() FROM PUBLIC;
CREATE TRIGGER notification_channel_shares_unlink AFTER DELETE ON notification_channel_shares
    FOR EACH ROW EXECUTE FUNCTION easyrmm_unshare_links();

-- ---------------------------------------------------------------------------
-- Maintenance windows, per site
-- ---------------------------------------------------------------------------

CREATE TABLE site_maintenance_windows (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    kind            text NOT NULL CHECK (kind IN ('weekly', 'once')),
    -- Weekly: days of the week (0 Sunday to 6 Saturday), a start in the
    -- site's time zone and a length. A window across midnight belongs to the
    -- day it starts.
    days            smallint[] NOT NULL DEFAULT '{}' CHECK (days <@ ARRAY[0, 1, 2, 3, 4, 5, 6]::smallint[]),
    start_local     time,
    -- Once: the start, as the site's wall clock reads it.
    starts_local    timestamp,
    length_minutes  integer NOT NULL CHECK (length_minutes BETWEEN 1 AND 10080),
    enabled         boolean NOT NULL DEFAULT true,
    -- What the planner last saw, so that each start and end is noticed once.
    active          boolean NOT NULL DEFAULT false,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT site_maintenance_windows_shape CHECK (
        (kind = 'weekly' AND cardinality(days) BETWEEN 1 AND 7 AND start_local IS NOT NULL AND starts_local IS NULL AND length_minutes <= 1440)
        OR (kind = 'once' AND cardinality(days) = 0 AND start_local IS NULL AND starts_local IS NOT NULL AND length_minutes <= 10080)),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX site_maintenance_windows_site ON site_maintenance_windows (site_id);
CREATE TRIGGER site_maintenance_windows_touch BEFORE UPDATE ON site_maintenance_windows
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- ---------------------------------------------------------------------------
-- Incidents and what was told
-- ---------------------------------------------------------------------------

-- An incident: the first alert's ID, carried over to an alert that opens on
-- the same policy, device, kind, check and subject within 5 minutes of a
-- policy change. It keeps what it needs to be told about after the alert,
-- the device or the rule is gone. No foreign keys: a deletion cannot take
-- the record with it.
CREATE TABLE alert_incidents (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    organization_name text NOT NULL DEFAULT '',
    site_id          uuid NOT NULL,
    site_name        text NOT NULL DEFAULT '',
    device_group_id  uuid,
    device_id        uuid NOT NULL,
    device_name      text NOT NULL DEFAULT '',
    device_kind      text,
    policy_id        uuid,
    alert_id         uuid NOT NULL,
    alert_kind       text NOT NULL,
    alert_name       text NOT NULL,
    check_name       text,
    subject          text NOT NULL DEFAULT '',
    subject_label    text NOT NULL DEFAULT '',
    key              text NOT NULL DEFAULT '',
    severity         text NOT NULL,
    detail           text NOT NULL DEFAULT '',
    value            double precision NOT NULL DEFAULT 0,
    status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'held', 'resolved')),
    opened_at        timestamptz NOT NULL,
    acknowledged_at  timestamptz,
    acknowledged_by  text NOT NULL DEFAULT '',
    resolved_at      timestamptz,
    resolution       text,
    -- A policy change's resolution waits this long for a successor.
    hold_until       timestamptz,
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX alert_incidents_open ON alert_incidents (site_id) WHERE status <> 'resolved';
CREATE INDEX alert_incidents_held ON alert_incidents (hold_until) WHERE status = 'held';
CREATE INDEX alert_incidents_succ ON alert_incidents (policy_id, device_id) WHERE status = 'held';
CREATE INDEX alert_incidents_resolved ON alert_incidents (resolved_at) WHERE status = 'resolved';

-- Which incident an alert belongs to.
CREATE TABLE alert_incident_alerts (
    alert_id    uuid PRIMARY KEY,
    incident_id uuid NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX alert_incident_alerts_incident ON alert_incident_alerts (incident_id);

-- Site outages, and the incidents folded into them.
CREATE TABLE site_outages (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    site_name       text NOT NULL DEFAULT '',
    started_at      timestamptz NOT NULL DEFAULT now(),
    ended_at        timestamptz,
    devices_total   integer NOT NULL,
    devices_back    integer
);
CREATE UNIQUE INDEX site_outages_open ON site_outages (site_id) WHERE ended_at IS NULL;

-- Per subject (an incident, a site outage or a notice) and channel: what was
-- told and what is due, with the rule's settings as they were when it
-- matched, so that a rule changed or deleted does not change what a channel
-- already told is told next.
CREATE TABLE alert_notifications (
    subject_type    text NOT NULL CHECK (subject_type IN ('incident', 'outage', 'notice')),
    subject_id      uuid NOT NULL,
    channel_id      uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    rule_id         uuid,
    charged_org     uuid NOT NULL,
    wait_minutes    integer NOT NULL DEFAULT 0,
    send_resolved   boolean NOT NULL DEFAULT true,
    send_ack        boolean NOT NULL DEFAULT false,
    reminder_hours  integer NOT NULL DEFAULT 0,
    ignore_windows  boolean NOT NULL DEFAULT false,
    group_outages   boolean NOT NULL DEFAULT true,
    due_at          timestamptz NOT NULL DEFAULT now(),
    held_by_window  boolean NOT NULL DEFAULT false,
    told_opened_at  timestamptz,
    told_ack_at     timestamptz,
    last_told_at    timestamptz,
    folded_outage   uuid,
    done            boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_type, subject_id, channel_id)
);
CREATE INDEX alert_notifications_live ON alert_notifications (subject_type, subject_id) WHERE NOT done;
CREATE INDEX alert_notifications_channel ON alert_notifications (channel_id);

-- The fleet-wide hold: most devices stopped checking in at once.
CREATE TABLE fleet_silences (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,
    ended_by    uuid,
    counted     uuid[] NOT NULL DEFAULT '{}',
    counted_n   integer NOT NULL,
    back_n      integer
);
CREATE UNIQUE INDEX fleet_silences_open ON fleet_silences ((true)) WHERE ended_at IS NULL;

-- ---------------------------------------------------------------------------
-- The alerts' journal
-- ---------------------------------------------------------------------------

-- +goose StatementBegin
CREATE FUNCTION easyrmm_alert_journal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    why text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO notification_events (subject_type, subject_id, event, new_row)
        VALUES ('alert', NEW.id, 'opened', to_jsonb(NEW));
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO notification_events (subject_type, subject_id, event, old_row, new_row)
        VALUES ('alert', NEW.id,
                CASE WHEN NEW.status = 'resolved' AND OLD.status <> 'resolved' THEN 'resolved'
                     WHEN NEW.status <> 'resolved' AND OLD.status = 'resolved' THEN 'reopened'
                     ELSE 'acknowledged' END,
                to_jsonb(OLD), to_jsonb(NEW));
    ELSE
        why := coalesce(nullif(current_setting('easyrmm.alert_delete_reason', true), ''), 'device_removed');
        INSERT INTO notification_events (subject_type, subject_id, event, old_row, new_row)
        VALUES ('alert', OLD.id, 'deleted', to_jsonb(OLD), jsonb_build_object('reason', why));
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_alert_journal() FROM PUBLIC;

CREATE TRIGGER alerts_journal_insert AFTER INSERT ON alerts
    FOR EACH ROW EXECUTE FUNCTION easyrmm_alert_journal();
CREATE TRIGGER alerts_journal_update AFTER UPDATE ON alerts
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.acknowledged_at IS DISTINCT FROM NEW.acknowledged_at)
    EXECUTE FUNCTION easyrmm_alert_journal();
CREATE TRIGGER alerts_journal_delete AFTER DELETE ON alerts
    FOR EACH ROW WHEN (OLD.status <> 'resolved')
    EXECUTE FUNCTION easyrmm_alert_journal();

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

ALTER TABLE notification_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_rules_all ON notification_rules FOR ALL
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

ALTER TABLE notification_rule_orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rule_orgs FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_rule_orgs_all ON notification_rule_orgs FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE notification_rule_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rule_sites FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_rule_sites_all ON notification_rule_sites FOR ALL
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

ALTER TABLE notification_rule_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rule_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_rule_groups_all ON notification_rule_groups FOR ALL
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

ALTER TABLE notification_rule_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rule_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_rule_channels_all ON notification_rule_channels FOR ALL
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

ALTER TABLE site_maintenance_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE site_maintenance_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY site_maintenance_windows_read ON site_maintenance_windows FOR SELECT USING (
    easyrmm_scope_all()
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')));
CREATE POLICY site_maintenance_windows_write ON site_maintenance_windows FOR ALL
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')))
    WITH CHECK (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')));

ALTER TABLE alert_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_incidents FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_incidents_all ON alert_incidents FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE alert_incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_incident_alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_incident_alerts_all ON alert_incident_alerts FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE alert_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_notifications_all ON alert_notifications FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE site_outages ENABLE ROW LEVEL SECURITY;
ALTER TABLE site_outages FORCE ROW LEVEL SECURITY;
CREATE POLICY site_outages_read ON site_outages FOR SELECT USING (
    easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')));
CREATE POLICY site_outages_write ON site_outages FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE fleet_silences ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_silences FORCE ROW LEVEL SECURITY;
CREATE POLICY fleet_silences_all ON fleet_silences FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_rules, notification_rule_orgs, notification_rule_sites, notification_rule_groups,
    notification_rule_channels, site_maintenance_windows, alert_incidents, alert_incident_alerts, alert_notifications,
    site_outages, fleet_silences TO easyrmm_app;

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
DROP TRIGGER IF EXISTS alerts_journal_delete ON alerts;
DROP TRIGGER IF EXISTS alerts_journal_update ON alerts;
DROP TRIGGER IF EXISTS alerts_journal_insert ON alerts;
DROP FUNCTION IF EXISTS easyrmm_alert_journal();
DELETE FROM notification_events WHERE subject_type = 'alert';
DROP TRIGGER IF EXISTS notification_channel_shares_unlink ON notification_channel_shares;
DROP FUNCTION IF EXISTS easyrmm_unshare_links();
DROP TABLE IF EXISTS fleet_silences, alert_notifications, site_outages, alert_incident_alerts, alert_incidents,
    site_maintenance_windows, notification_rule_channels, notification_rule_groups, notification_rule_sites,
    notification_rule_orgs, notification_rules CASCADE;
DROP FUNCTION IF EXISTS easyrmm_rule_channel_check();
ALTER TABLE devices DROP COLUMN IF EXISTS agent_uninstalled_at, DROP COLUMN IF EXISTS role_set_by,
    DROP COLUMN IF EXISTS role, DROP COLUMN IF EXISTS agent_role;
