-- The log store (ADR-0060, slice 2). This schema lives in a PostgreSQL
-- instance of its own, apart from the main database: nothing here refers to
-- a table there (devices, organizations and sites are plain ids), and the
-- migrations of this directory run only against it.
--
-- Logs are kept as compressed blocks (one batch's events of one source from
-- one device) with their facts beside them, partitioned in two levels: by
-- retention class (list), then by the block's start time (range, a month a
-- partition). A class's retention ends by dropping whole partitions, never
-- by deleting rows one by one, apart from the part of the newest partition
-- that has passed its time. Row-level security keeps each organization's
-- blocks to it and site-scoped people to their sites', as in the main
-- database, from the same session settings.
--
-- Roles (made by the deployment's initialisation, not here):
--   easyrmm_logs_owner  owns the schema, runs migrations and the partition
--                       functions
--   easyrmm_logs_app    the server's runtime role

-- +goose Up

-- +goose StatementBegin
CREATE FUNCTION easyrmm_scope_all() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT coalesce(current_setting('easyrmm.scope_all', true), '') = 'on'
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION easyrmm_scope_ids(setting text) RETURNS uuid[]
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT coalesce(nullif(current_setting(setting, true), ''), '{}')::uuid[]
$$;
-- +goose StatementEnd

-- The position of each device's stream: the highest block sequence stored or
-- knowingly refused. A block at or below it is a repeat and is stored once.
CREATE TABLE log_streams (
    device_id       uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    acked_seq       bigint NOT NULL DEFAULT 0,
    stored_blocks   bigint NOT NULL DEFAULT 0,
    refused_blocks  bigint NOT NULL DEFAULT 0,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE log_blocks (
    id              bigint GENERATED ALWAYS AS IDENTITY,
    device_id       uuid NOT NULL,
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    seq             bigint NOT NULL,
    source          text NOT NULL CHECK (source ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    retention_class text NOT NULL CHECK (retention_class IN ('security', 'operational', 'debug')),
    start_time      timestamptz NOT NULL,
    end_time        timestamptz NOT NULL CHECK (end_time >= start_time),
    event_count     integer NOT NULL CHECK (event_count > 0),
    raw_bytes       integer NOT NULL CHECK (raw_bytes > 0),
    codec           text NOT NULL CHECK (codec IN ('deflate')),
    compressed_data bytea NOT NULL,
    facts           jsonb NOT NULL,
    received_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (retention_class, start_time, id),
    -- A device's block is stored once. The partition keys are part of the
    -- key; the stream's position is what really stops a repeat.
    UNIQUE (device_id, seq, retention_class, start_time)
) PARTITION BY LIST (retention_class);

CREATE TABLE log_blocks_security    PARTITION OF log_blocks FOR VALUES IN ('security')    PARTITION BY RANGE (start_time);
CREATE TABLE log_blocks_operational PARTITION OF log_blocks FOR VALUES IN ('operational') PARTITION BY RANGE (start_time);
CREATE TABLE log_blocks_debug       PARTITION OF log_blocks FOR VALUES IN ('debug')       PARTITION BY RANGE (start_time);

-- A block that starts outside every month made (a device with a wrong clock)
-- still has somewhere to go.
CREATE TABLE log_blocks_security_default    PARTITION OF log_blocks_security    DEFAULT;
CREATE TABLE log_blocks_operational_default PARTITION OF log_blocks_operational DEFAULT;
CREATE TABLE log_blocks_debug_default       PARTITION OF log_blocks_debug       DEFAULT;

CREATE INDEX log_blocks_device_time_idx ON log_blocks (device_id, start_time DESC);
CREATE INDEX log_blocks_device_end_idx ON log_blocks (device_id, end_time DESC);
CREATE INDEX log_blocks_device_received_idx ON log_blocks (device_id, received_at);
CREATE INDEX log_blocks_org_time_idx ON log_blocks (organization_id, start_time DESC);

-- Hourly facts: what each device logged each hour, by source and level, for
-- the timeline and for sizing, without opening a block.
CREATE TABLE log_hourly_facts (
    device_id       uuid NOT NULL,
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    hour            timestamptz NOT NULL,
    source          text NOT NULL,
    level           text NOT NULL,
    events          bigint NOT NULL,
    bytes           bigint NOT NULL,
    PRIMARY KEY (device_id, hour, source, level)
);
CREATE INDEX log_hourly_facts_org_hour_idx ON log_hourly_facts (organization_id, hour);

-- Partitions: a month each, made ahead of time by this function, which the
-- server calls every day and at start. A partition already there is left.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_logs_ensure_partitions(months_ahead integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    cls text;
    m date;
    made integer := 0;
    part text;
BEGIN
    IF months_ahead < 0 OR months_ahead > 24 THEN
        RAISE EXCEPTION 'months_ahead out of range';
    END IF;
    FOREACH cls IN ARRAY ARRAY['security', 'operational', 'debug'] LOOP
        -- From the month before this one: blocks that started a little ago.
        FOR i IN -1..months_ahead LOOP
            m := (date_trunc('month', now() AT TIME ZONE 'UTC') + make_interval(months => i))::date;
            part := format('log_blocks_%s_%s', cls, to_char(m, 'YYYYMM'));
            IF to_regclass(part) IS NULL THEN
                EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                    part, 'log_blocks_' || cls, (m::timestamp AT TIME ZONE 'UTC'), ((m + interval '1 month')::timestamp AT TIME ZONE 'UTC'));
                made := made + 1;
            END IF;
        END LOOP;
    END LOOP;
    RETURN made;
END
$$;
-- +goose StatementEnd

-- Retention: drops each class's monthly partitions that lie wholly past its
-- time, deletes what has passed it in the others (and in the default
-- partitions), and drops hourly facts older than the longest class. Returns
-- the partitions dropped and the rows deleted.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_logs_purge(OUT partitions_dropped integer, OUT blocks_deleted bigint) RETURNS record
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    cls text;
    keep interval;
    r record;
    n bigint;
BEGIN
    partitions_dropped := 0;
    blocks_deleted := 0;
    FOR cls, keep IN VALUES ('security', interval '365 days'), ('operational', interval '90 days'), ('debug', interval '7 days') LOOP
        FOR r IN
            SELECT c.relname,
                   (regexp_match(pg_get_expr(c.relpartbound, c.oid), 'TO \(''([^'']+)''\)'))[1]::timestamptz AS upper_bound
              FROM pg_inherits i
              JOIN pg_class c ON c.oid = i.inhrelid
              JOIN pg_class p ON p.oid = i.inhparent
             WHERE p.relname = 'log_blocks_' || cls
               AND pg_get_expr(c.relpartbound, c.oid) <> 'DEFAULT'
        LOOP
            -- Every block in it started before the upper bound; one that
            -- ended later than that is kept by the delete below, so only a
            -- partition whose bound is past the class's time and a day
            -- more (blocks span up to a day) is dropped whole.
            IF r.upper_bound IS NOT NULL AND r.upper_bound < now() - keep - interval '2 days' THEN
                EXECUTE format('DROP TABLE %I', r.relname);
                partitions_dropped := partitions_dropped + 1;
            END IF;
        END LOOP;
        EXECUTE format('DELETE FROM %I WHERE end_time < now() - %L::interval', 'log_blocks_' || cls, keep);
        GET DIAGNOSTICS n = ROW_COUNT;
        blocks_deleted := blocks_deleted + n;
    END LOOP;
    DELETE FROM log_hourly_facts WHERE hour < now() - interval '366 days';
    RETURN;
END
$$;
-- +goose StatementEnd

SELECT easyrmm_logs_ensure_partitions(2);

-- Row-level security. The server sets the same session settings as for the
-- main database (database.Scope). Ingest and purges run with the unrestricted
-- scope; the functions above act as the owner, which FORCE binds too, so the
-- owner has policies of its own.
ALTER TABLE log_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_streams FORCE ROW LEVEL SECURITY;
ALTER TABLE log_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_blocks FORCE ROW LEVEL SECURITY;
ALTER TABLE log_hourly_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_hourly_facts FORCE ROW LEVEL SECURITY;

CREATE POLICY log_streams_tenant ON log_streams TO easyrmm_logs_app
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')))
    WITH CHECK (easyrmm_scope_all());
CREATE POLICY log_blocks_tenant ON log_blocks TO easyrmm_logs_app
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')))
    WITH CHECK (easyrmm_scope_all());
CREATE POLICY log_hourly_facts_tenant ON log_hourly_facts TO easyrmm_logs_app
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')))
    WITH CHECK (easyrmm_scope_all());
CREATE POLICY log_streams_owner ON log_streams TO easyrmm_logs_owner USING (true) WITH CHECK (true);
CREATE POLICY log_blocks_owner ON log_blocks TO easyrmm_logs_owner USING (true) WITH CHECK (true);
CREATE POLICY log_hourly_facts_owner ON log_hourly_facts TO easyrmm_logs_owner USING (true) WITH CHECK (true);

-- The runtime role reads and writes the data and nothing else: it cannot
-- change the schema, drop a partition itself or delete blocks (only the
-- purge function does).
GRANT USAGE ON SCHEMA public TO easyrmm_logs_app;
GRANT SELECT, INSERT, UPDATE ON log_streams TO easyrmm_logs_app;
GRANT SELECT, INSERT ON log_blocks TO easyrmm_logs_app;
GRANT SELECT, INSERT, UPDATE ON log_hourly_facts TO easyrmm_logs_app;
REVOKE EXECUTE ON FUNCTION easyrmm_logs_ensure_partitions(integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION easyrmm_logs_purge() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_logs_ensure_partitions(integer) TO easyrmm_logs_app;
GRANT EXECUTE ON FUNCTION easyrmm_logs_purge() TO easyrmm_logs_app;

-- +goose Down
-- The log store is never migrated down: dropping it is deleting the logs.
SELECT 1;
