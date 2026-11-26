-- Settings that reach the agent, slice 1 (ADR-0058): the values operators set
-- at the platform, an organization, a site or one device, and the interval
-- each agent checks in at, which online and monitoring now follow.
--
--   agent_settings            one row per key and scope target. Platform rows
--                             have no organization, site or device; an
--                             organization's has an organization; a site's
--                             an organization and a site; a device's all
--                             three and the device. The value is checked
--                             against the server's catalogue on every write.
--   devices.agent_heartbeat_seconds
--                             the interval the device's agent uses.
--   devices.agent_online_until
--                             when the device stops counting as online: three
--                             of those intervals after its last heartbeat.
--
-- Neither new column moves updated_at, as agent_last_seen_at does not.

-- +goose Up

ALTER TABLE devices
    ADD COLUMN agent_heartbeat_seconds integer NOT NULL DEFAULT 60
        CONSTRAINT devices_agent_heartbeat_seconds_check CHECK (agent_heartbeat_seconds BETWEEN 10 AND 600),
    ADD COLUMN agent_online_until timestamptz;

-- Enrolled devices keep today's behavior: 60 seconds, so online for three
-- minutes after the last heartbeat.
UPDATE devices SET agent_online_until = agent_last_seen_at + interval '3 minutes'
    WHERE agent_last_seen_at IS NOT NULL;

CREATE INDEX devices_agent_online_idx ON devices (agent_online_until) WHERE agent_public_key IS NOT NULL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION easyrmm_touch_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF to_jsonb(NEW) - '{updated_at,last_seen_at,agent_last_seen_at,remote_online,agent_heartbeat_seconds,agent_online_until}'::text[]
       IS DISTINCT FROM to_jsonb(OLD) - '{updated_at,last_seen_at,agent_last_seen_at,remote_online,agent_heartbeat_seconds,agent_online_until}'::text[] THEN
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- A device counts as online for three of its intervals after its agent was
-- last seen. Every writer of agent_last_seen_at (the heartbeat, enrollment,
-- Quick Assist) gets that from here, unless it sets agent_online_until
-- itself.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_device_online_until() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.agent_last_seen_at IS NULL THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.agent_last_seen_at IS NOT DISTINCT FROM OLD.agent_last_seen_at
           OR NEW.agent_online_until IS DISTINCT FROM OLD.agent_online_until THEN
            RETURN NEW;
        END IF;
    END IF;
    NEW.agent_online_until := NEW.agent_last_seen_at + make_interval(secs => 3 * NEW.agent_heartbeat_seconds);
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER devices_online_until BEFORE INSERT OR UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION easyrmm_device_online_until();

CREATE TABLE agent_settings (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key              text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$' AND length(key) <= 64),
    scope            text NOT NULL CHECK (scope IN ('platform', 'organization', 'site', 'device')),
    organization_id  uuid REFERENCES organizations (id) ON DELETE CASCADE,
    site_id          uuid,
    device_id        uuid REFERENCES devices (id) ON DELETE CASCADE,
    value            jsonb NOT NULL CHECK (octet_length(value::text) <= 65536),
    enforced         boolean NOT NULL DEFAULT false,
    set_by           uuid REFERENCES users (id) ON DELETE SET NULL,
    set_by_label     text NOT NULL DEFAULT '' CHECK (length(set_by_label) <= 320),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (CASE scope
        WHEN 'platform'     THEN organization_id IS NULL AND site_id IS NULL AND device_id IS NULL
        WHEN 'organization' THEN organization_id IS NOT NULL AND site_id IS NULL AND device_id IS NULL
        WHEN 'site'         THEN organization_id IS NOT NULL AND site_id IS NOT NULL AND device_id IS NULL
        ELSE                     organization_id IS NOT NULL AND site_id IS NOT NULL AND device_id IS NOT NULL
    END),
    -- A device has nothing below it to enforce over.
    CHECK (scope <> 'device' OR NOT enforced),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX agent_settings_platform_key ON agent_settings (key) WHERE scope = 'platform';
CREATE UNIQUE INDEX agent_settings_org_key ON agent_settings (organization_id, key) WHERE scope = 'organization';
CREATE UNIQUE INDEX agent_settings_site_key ON agent_settings (site_id, key) WHERE scope = 'site';
CREATE UNIQUE INDEX agent_settings_device_key ON agent_settings (device_id, key) WHERE scope = 'device';

-- A device row is for a device with the EasyRMM agent, in the organization
-- and site the row names. The check reads devices as the table's owner, so it
-- sees the device whoever writes the row.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_agent_setting_device_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF NEW.scope = 'device' AND NOT EXISTS (
        SELECT 1 FROM devices d WHERE d.id = NEW.device_id AND d.agent_public_key IS NOT NULL
            AND d.organization_id = NEW.organization_id AND d.site_id = NEW.site_id) THEN
        RAISE EXCEPTION 'a device setting is for a device with the EasyRMM agent, in the site it names'
            USING ERRCODE = '23514', CONSTRAINT = 'agent_settings_device_agent';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_agent_setting_device_check() FROM PUBLIC;
CREATE TRIGGER agent_settings_device_check BEFORE INSERT OR UPDATE ON agent_settings
    FOR EACH ROW EXECUTE FUNCTION easyrmm_agent_setting_device_check();

-- Everyone reads the platform's rows; an organization's are read in the
-- organization and, as inherited values, from its sites; a site's and its
-- devices' in that site. Writing needs the level itself: the platform, the
-- whole organization, or the site.
ALTER TABLE agent_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_settings_read ON agent_settings FOR SELECT USING (
    easyrmm_scope_all()
    OR scope = 'platform'
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR (site_id IS NULL AND organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_read_orgs')))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
);
CREATE POLICY agent_settings_insert ON agent_settings FOR INSERT WITH CHECK (
    easyrmm_scope_all()
    OR (scope = 'organization' AND organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    OR (scope IN ('site', 'device') AND (
        organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))))
);
CREATE POLICY agent_settings_update ON agent_settings FOR UPDATE
    USING (
        easyrmm_scope_all()
        OR (scope = 'organization' AND organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
        OR (scope IN ('site', 'device') AND (
            organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
            OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR (scope = 'organization' AND organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
        OR (scope IN ('site', 'device') AND (
            organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
            OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))))
    );
CREATE POLICY agent_settings_delete ON agent_settings FOR DELETE USING (
    easyrmm_scope_all()
    OR (scope = 'organization' AND organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    OR (scope IN ('site', 'device') AND (
        organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_settings TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS agent_settings;
DROP FUNCTION IF EXISTS easyrmm_agent_setting_device_check();
DROP TRIGGER IF EXISTS devices_online_until ON devices;
DROP FUNCTION IF EXISTS easyrmm_device_online_until();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION easyrmm_touch_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF to_jsonb(NEW) - '{updated_at,last_seen_at,agent_last_seen_at,remote_online}'::text[]
       IS DISTINCT FROM to_jsonb(OLD) - '{updated_at,last_seen_at,agent_last_seen_at,remote_online}'::text[] THEN
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
DROP INDEX IF EXISTS devices_agent_online_idx;
ALTER TABLE devices DROP COLUMN IF EXISTS agent_online_until, DROP COLUMN IF EXISTS agent_heartbeat_seconds;
