-- Disk health (ADR-0065, slice 1): each disk's latest reading and its
-- history, the disk_health alert kind with a check per policy, and alerts
-- with a subject, so that each disk has alerts of its own.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Readings
-- ---------------------------------------------------------------------------

-- The latest reading of each disk a device's agent reported. disk_key is
-- the disk's identity, easyrmm_disk_key (below); unstable: it comes from
-- the disk's name, for want of a serial.
--
-- state, reason and detail are the latest reading's own: its level, or the
-- disk as a whole when it was not read (asleep, unavailable…), with when
-- the agent read it and when the server received it. protocol, route,
-- facts and attributes are from the latest reading that read the disk
-- (facts_at), judged by the server's rules, so that a sleeping disk still
-- shows its last values with their time.
--
-- judged_level, judged_reason, judged_detail and judged_at are the last
-- reading that read the drive's verdict, kept apart so that later readings
-- that could not tell (a timeout, a sleeping disk) do not overwrite them: a
-- failing disk stays failing until a newer judged reading says otherwise.
-- missing_since is set by a report that no longer lists the disk, and
-- cleared by one that does.
CREATE TABLE device_disk_health (
    device_id      uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    disk_key       text NOT NULL CHECK (disk_key ~ '^[0-9a-f]{32}$'),
    unstable       boolean NOT NULL,
    name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    model          text NOT NULL CHECK (length(model) <= 200),
    serial         text NOT NULL CHECK (length(serial) <= 200),
    state          text NOT NULL CHECK (state IN ('healthy', 'warning', 'failing', 'unknown', 'unsupported', 'unavailable')),
    reason         text NOT NULL CHECK (reason ~ '^[a-z_]{0,40}$'),
    detail         text NOT NULL CHECK (length(detail) <= 200),
    read_at        timestamptz NOT NULL,
    received_at    timestamptz NOT NULL,
    protocol       text NOT NULL CHECK (protocol IN ('', 'nvme', 'ata')),
    route          text NOT NULL CHECK (route IN ('', 'device', 'adapter', 'ata', 'nvme', 'sg')),
    facts          jsonb NOT NULL CHECK (jsonb_typeof(facts) = 'array'),
    attributes     jsonb NOT NULL CHECK (jsonb_typeof(attributes) = 'array'),
    facts_at       timestamptz,
    judged_level   text CHECK (judged_level IN ('healthy', 'warning', 'failing', 'unknown')),
    judged_reason  text NOT NULL CHECK (judged_reason ~ '^[a-z_]{0,40}$'),
    judged_detail  text NOT NULL CHECK (length(judged_detail) <= 500),
    judged_at      timestamptz,
    missing_since  timestamptz,
    PRIMARY KEY (device_id, disk_key),
    CHECK ((judged_level IS NULL) = (judged_at IS NULL))
);

-- A disk's identity: the first 16 bytes of the SHA-256 of its model and
-- serial, in hex, or of its name where it has no serial. Text as the
-- inventory stores it, which has no control characters, so a line feed
-- cannot be part of a field.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_disk_key(name text, model text, serial text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT substr(encode(sha256(convert_to(CASE WHEN serial <> '' THEN 'disk' || E'\n' || model || E'\n' || serial
        ELSE 'name' || E'\n' || name END, 'UTF8')), 'hex'), 1, 32)
$$;
-- +goose StatementEnd

-- What the console shows for a disk (ADR-0065, "The five states"), the
-- first that applies: missing (unknown); the disk as a whole unsupported
-- or unavailable; the last judged reading's failing or warning, however old
-- and whatever later readings could not tell; healthy, if the last judged
-- reading was and is at most 2 hours old; else unknown.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_disk_state(missing_since timestamptz, state text, judged_level text, judged_at timestamptz)
RETURNS text LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN missing_since IS NOT NULL THEN 'unknown'
        WHEN state IN ('unsupported', 'unavailable') THEN state
        WHEN judged_level IN ('failing', 'warning') THEN judged_level
        WHEN judged_level = 'healthy' AND judged_at > now() - interval '2 hours' THEN 'healthy'
        ELSE 'unknown'
    END
$$;
-- +goose StatementEnd

-- One row per disk per reading, received at at, for EASYRMM_METRICS_RETENTION;
-- then one row per disk per UTC day (daily, at the day's start) with the
-- day's worst state, its highest temperature and its last counts and wear,
-- for EASYRMM_HARDWARE_RETENTION. A fact not read is NULL. judged: the
-- reading read the drive's verdict (for a day, any reading did).
CREATE TABLE device_disk_health_samples (
    device_id          uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    disk_key           text NOT NULL CHECK (disk_key ~ '^[0-9a-f]{32}$'),
    at                 timestamptz NOT NULL,
    daily              boolean NOT NULL DEFAULT false,
    state              text NOT NULL CHECK (state IN ('healthy', 'warning', 'failing', 'unknown', 'unsupported', 'unavailable')),
    judged             boolean NOT NULL,
    temperature        smallint CHECK (temperature BETWEEN -40 AND 150),
    temperature_limit  smallint CHECK (temperature_limit BETWEEN -40 AND 150),
    wear               smallint CHECK (wear BETWEEN 0 AND 255),
    reallocated        bigint CHECK (reallocated >= 0),
    media_errors       bigint CHECK (media_errors >= 0),
    pending            bigint CHECK (pending >= 0),
    uncorrectable      bigint CHECK (uncorrectable >= 0),
    drive_errors       bigint CHECK (drive_errors >= 0),
    power_on_hours     bigint CHECK (power_on_hours >= 0),
    PRIMARY KEY (device_id, disk_key, at)
);
CREATE INDEX device_disk_health_samples_at_idx ON device_disk_health_samples USING brin (at);

-- Rows are visible through their device, whose own policy decides, and
-- written only by the agent API and maintenance with the system scope.
ALTER TABLE device_disk_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_disk_health FORCE ROW LEVEL SECURITY;
CREATE POLICY device_disk_health_read ON device_disk_health FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_disk_health_write ON device_disk_health FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_disk_health TO easyrmm_app;

ALTER TABLE device_disk_health_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_disk_health_samples FORCE ROW LEVEL SECURITY;
CREATE POLICY device_disk_health_samples_read ON device_disk_health_samples FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_disk_health_samples_insert ON device_disk_health_samples FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY device_disk_health_samples_delete ON device_disk_health_samples FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT, INSERT, DELETE ON device_disk_health_samples TO easyrmm_app;

-- ---------------------------------------------------------------------------
-- Policies: the disk_health kind and its checks
-- ---------------------------------------------------------------------------

-- check_name says what a disk_health policy watches (check is a reserved
-- word). Its threshold is a count for errors and pending, a percentage for
-- wear and degrees Celsius for temperature, where none means the drive's
-- own limit; failing has none. Minutes apply to temperature, at least two
-- reading intervals so that its window holds two readings; the other checks
-- take the reading interval.
ALTER TABLE alert_policies
    DROP CONSTRAINT alert_policies_kind_check,
    DROP CONSTRAINT alert_policies_check1,
    ADD CONSTRAINT alert_policies_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health')),
    ADD COLUMN check_name text CHECK (check_name IN ('failing', 'errors', 'pending', 'wear', 'temperature')),
    ADD CONSTRAINT alert_policies_check_name CHECK ((kind = 'disk_health') = (check_name IS NOT NULL)),
    ADD CONSTRAINT alert_policies_threshold_needed CHECK (CASE
        WHEN kind = 'offline' THEN threshold IS NULL
        WHEN check_name = 'failing' THEN threshold IS NULL
        WHEN check_name = 'temperature' THEN true
        ELSE threshold IS NOT NULL END),
    ADD CONSTRAINT alert_policies_disk_minutes CHECK (kind <> 'disk_health'
        OR minutes >= CASE check_name WHEN 'temperature' THEN 60 ELSE 30 END);

DROP TRIGGER alert_policies_touch ON alert_policies;
CREATE TRIGGER alert_policies_touch
    BEFORE UPDATE OF name, description, kind, check_name, threshold, minutes, severity, enabled ON alert_policies
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- ---------------------------------------------------------------------------
-- Alerts: a check and a subject
-- ---------------------------------------------------------------------------

-- subject is what on the device the alert is about: a disk's identity for
-- disk_health, empty for the other kinds, so that they still allow one
-- unresolved alert per policy and device (an empty string, not NULL, which
-- a unique index would never count as equal). subject_label names it for
-- people ("PhysicalDrive1 · Samsung SSD 870 EVO 1TB"), never with a serial;
-- detail says what holds ("Pending sectors 8, reallocated 0").
-- subject_gone: the disk has been missing for 14 days, and no hardware
-- report since has listed it.
ALTER TABLE alerts
    DROP CONSTRAINT alerts_kind_check,
    DROP CONSTRAINT alerts_resolution_check,
    ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'disk_health')),
    ADD COLUMN check_name text CHECK (check_name IN ('failing', 'errors', 'pending', 'wear', 'temperature')),
    ADD COLUMN subject text NOT NULL DEFAULT '' CHECK (length(subject) <= 64),
    ADD COLUMN subject_label text NOT NULL DEFAULT '' CHECK (length(subject_label) <= 300),
    ADD COLUMN detail text NOT NULL DEFAULT '' CHECK (length(detail) <= 500),
    ADD CONSTRAINT alerts_check_name CHECK ((kind = 'disk_health') = (check_name IS NOT NULL)),
    ADD CONSTRAINT alerts_resolution_check CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off',
        'policy_changed', 'policy_deleted', 'subject_gone'));

-- At most one unresolved alert per policy, device and subject.
DROP INDEX alerts_active_key;
CREATE UNIQUE INDEX alerts_active_key ON alerts (policy_id, device_id, subject) WHERE status <> 'resolved';

-- ---------------------------------------------------------------------------
-- The shared disk_health policies, on new installations and old ones alike
-- ---------------------------------------------------------------------------

-- Only Disk failing is on: a failing drive is worth a message everywhere;
-- a reallocated sector, wear or a warm drive is each MSP's call. A name an
-- administrator already uses is tried once more with " (disk health)"
-- appended; an installation that has both names gets no default for that
-- check. alert_policies forces row-level security, on its owner too.
SELECT set_config('easyrmm.scope_all', 'on', true);
WITH wanted (name, description, check_name, threshold, minutes, severity, enabled) AS (VALUES
    ('Disk failing', 'A disk''s own verdict says it is failing: SMART status threshold exceeded, a pre-fail attribute at its threshold, or an NVMe critical warning about its spare, reliability, read-only media or volatile memory backup.', 'failing', NULL::integer, 30, 'critical', true),
    ('Disk errors', 'A disk has at least this many reallocated sectors and NVMe media errors.', 'errors', 1, 30, 'warning', false),
    ('Disk sectors pending', 'A disk has at least this many sectors pending reallocation or found uncorrectable offline.', 'pending', 1, 30, 'warning', false),
    ('Disk wearing out', 'A disk has used at least this percentage of its rated endurance.', 'wear', 90, 30, 'warning', false),
    ('Disk too hot', 'A disk has stayed at or above its own warning temperature for an hour.', 'temperature', NULL, 60, 'warning', false)
), first AS (
    INSERT INTO alert_policies (name, description, kind, check_name, threshold, minutes, severity, enabled)
    SELECT name, description, 'disk_health', check_name, threshold, minutes, severity, enabled FROM wanted
    ON CONFLICT DO NOTHING
    RETURNING check_name
)
INSERT INTO alert_policies (name, description, kind, check_name, threshold, minutes, severity, enabled)
SELECT name || ' (disk health)', description, 'disk_health', check_name, threshold, minutes, severity, enabled
FROM wanted WHERE check_name NOT IN (SELECT check_name FROM first)
ON CONFLICT DO NOTHING;

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
DELETE FROM alerts WHERE kind = 'disk_health';
DELETE FROM alert_policies WHERE kind = 'disk_health';
DROP INDEX alerts_active_key;
CREATE UNIQUE INDEX alerts_active_key ON alerts (policy_id, device_id) WHERE status <> 'resolved';
ALTER TABLE alerts
    DROP CONSTRAINT alerts_resolution_check,
    DROP CONSTRAINT alerts_check_name,
    DROP COLUMN detail,
    DROP COLUMN subject_label,
    DROP COLUMN subject,
    DROP COLUMN check_name,
    DROP CONSTRAINT alerts_kind_check,
    ADD CONSTRAINT alerts_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk')),
    ADD CONSTRAINT alerts_resolution_check CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off',
        'policy_changed', 'policy_deleted'));
DROP TRIGGER alert_policies_touch ON alert_policies;
CREATE TRIGGER alert_policies_touch
    BEFORE UPDATE OF name, description, kind, threshold, minutes, severity, enabled ON alert_policies
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();
ALTER TABLE alert_policies
    DROP CONSTRAINT alert_policies_disk_minutes,
    DROP CONSTRAINT alert_policies_threshold_needed,
    DROP CONSTRAINT alert_policies_check_name,
    DROP COLUMN check_name,
    DROP CONSTRAINT alert_policies_kind_check,
    ADD CONSTRAINT alert_policies_kind_check CHECK (kind IN ('offline', 'cpu', 'memory', 'disk')),
    ADD CONSTRAINT alert_policies_check1 CHECK ((kind = 'offline') = (threshold IS NULL));
DROP FUNCTION easyrmm_disk_state(timestamptz, text, text, timestamptz);
DROP FUNCTION easyrmm_disk_key(text, text, text);
DROP TABLE device_disk_health_samples;
DROP TABLE device_disk_health;
