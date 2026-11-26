-- F2: job kinds with a signed input and a stored result (ADR-0067, slice 1).
--
-- * A job may run a builtin of the agent instead of a script: jobs.executor
--   and jobs.builtin say so, and two kinds, registry_query and
--   registry_change, are tied to it. Their rows hold no script: an empty
--   shell and body.
-- * The input of such a job is kept in job_inputs, apart from jobs, which is
--   written once; its result is job_runs.result, a JSON array of the lines
--   the builtin wrote. The runtime role cannot select either one: they are
--   read through functions that check the caller's permissions and, for a
--   query, that the caller asked (ADR-0063's rule).
-- * registry_masked_values is the store of masked data, which no role but
--   the owner reads.
-- * A job keeps the signed size of its payload, which the claim fills an
--   answer by; a run keeps the version and build that ran it.

-- +goose Up
ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check;
ALTER TABLE jobs DROP CONSTRAINT jobs_shell_check;
ALTER TABLE jobs DROP CONSTRAINT jobs_body_check;
ALTER TABLE jobs
    ADD COLUMN executor text NOT NULL DEFAULT 'script' CHECK (executor IN ('script', 'builtin')),
    ADD COLUMN builtin text CHECK (builtin ~ '^[a-z]{1,32}$'),
    ADD COLUMN lane text CHECK (lane = 'quick'),
    ADD COLUMN signed_bytes integer NOT NULL DEFAULT 0 CHECK (signed_bytes BETWEEN 0 AND 2097152);
ALTER TABLE jobs
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening', 'winmod', 'registry_query', 'registry_change')),
    ADD CONSTRAINT jobs_shell_check CHECK (shell IN ('powershell', 'pwsh', 'cmd', 'sh', 'bash', 'python3') OR (executor = 'builtin' AND shell = '')),
    ADD CONSTRAINT jobs_body_check CHECK (octet_length(body) BETWEEN 1 AND 524288 OR (executor = 'builtin' AND body = '')),
    ADD CONSTRAINT jobs_builtin_executor CHECK ((executor = 'builtin') = (builtin IS NOT NULL)),
    ADD CONSTRAINT jobs_builtin_kind CHECK ((executor = 'builtin') = (kind IN ('registry_query', 'registry_change'))),
    ADD CONSTRAINT jobs_builtin_hidden CHECK (executor <> 'builtin' OR hidden);
GRANT SELECT (executor, builtin, lane, signed_bytes) ON jobs TO easyrmm_app;

-- The result of a structured run. result_stored_at is when it arrived and
-- is set only while there is a result; result_removed_at when retention or a
-- person removed it. result_complete is false for a result without its end
-- line or one the agent cut.
ALTER TABLE job_runs
    ADD COLUMN result jsonb CHECK (jsonb_typeof(result) = 'array'),
    ADD COLUMN result_bytes integer NOT NULL DEFAULT 0,
    ADD COLUMN result_stored_at timestamptz,
    ADD COLUMN result_removed_at timestamptz,
    ADD COLUMN result_complete boolean NOT NULL DEFAULT false,
    ADD COLUMN ran_agent_version text CHECK (length(ran_agent_version) <= 64),
    ADD COLUMN ran_agent_sha256 text CHECK (length(ran_agent_sha256) <= 64),
    ADD CONSTRAINT job_runs_result_stored CHECK ((result_stored_at IS NOT NULL) = (result IS NOT NULL)),
    ADD CONSTRAINT job_runs_result_removed CHECK (result_removed_at IS NULL OR result_stored_at IS NULL);
CREATE INDEX job_runs_result_stored_idx ON job_runs (result_stored_at) WHERE result_stored_at IS NOT NULL;
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_runs_result_size() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.result_bytes := coalesce(octet_length(NEW.result::text), 0);
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER job_runs_result_size BEFORE INSERT OR UPDATE OF result, result_bytes ON job_runs
    FOR EACH ROW EXECUTE FUNCTION easyrmm_job_runs_result_size();
GRANT SELECT (result_bytes, result_stored_at, result_removed_at, result_complete, ran_agent_version, ran_agent_sha256)
    ON job_runs TO easyrmm_app;

-- The input of a job, one row per job. NULL once removed with the results.
CREATE TABLE job_inputs (
    job_id        uuid PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    input         jsonb CHECK (jsonb_typeof(input) = 'object'),
    input_bytes   integer NOT NULL CHECK (input_bytes BETWEEN 1 AND 1048576),
    stored_at     timestamptz NOT NULL DEFAULT now(),
    removed_at    timestamptz,
    CHECK ((input IS NULL) = (removed_at IS NOT NULL))
);
ALTER TABLE job_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_inputs FORCE ROW LEVEL SECURITY;
-- Visible through the runs a caller can see, as jobs are.
CREATE POLICY job_inputs_read ON job_inputs FOR SELECT USING (
    easyrmm_scope_all() OR EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = job_inputs.job_id)
);
CREATE POLICY job_inputs_insert ON job_inputs FOR INSERT WITH CHECK (true);
CREATE POLICY job_inputs_system ON job_inputs FOR UPDATE USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY job_inputs_delete ON job_inputs FOR DELETE USING (easyrmm_scope_all());
GRANT SELECT (job_id, input_bytes, stored_at, removed_at), INSERT, UPDATE, DELETE ON job_inputs TO easyrmm_app;

-- Masked data (ADR-0067, Masked values): the data a person types for a
-- masked value, and a masked value's backup. Slice 1 stores none; the table,
-- its grants and its purge are here so that nothing later can be readable
-- by accident. The runtime role reads everything but data.
CREATE TABLE registry_masked_values (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    job_id          uuid REFERENCES jobs (id) ON DELETE CASCADE,
    run_id          uuid REFERENCES job_runs (id) ON DELETE CASCADE,
    hive            text NOT NULL,
    view            text NOT NULL CHECK (view IN ('64', '32')),
    path            text[] NOT NULL,
    value_name      text NOT NULL,
    value_type      integer NOT NULL,
    data            bytea CHECK (octet_length(data) <= 524288),
    stored_at       timestamptz NOT NULL DEFAULT now(),
    removed_at      timestamptz,
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE,
    CHECK ((data IS NULL) = (removed_at IS NOT NULL))
);
CREATE INDEX registry_masked_values_run_idx ON registry_masked_values (run_id);
ALTER TABLE registry_masked_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_masked_values FORCE ROW LEVEL SECURITY;
CREATE POLICY registry_masked_values_system ON registry_masked_values FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT (id, organization_id, site_id, device_id, job_id, run_id, hive, view, path, value_name, value_type, stored_at, removed_at),
    INSERT, UPDATE, DELETE ON registry_masked_values TO easyrmm_app;

-- A run's result for a person. view is the caller's job.view scope, read
-- their job.view_sensitive scope, kind the scope of the kind's own
-- permission (registry.view). For the kinds in p_asker_kinds only the person
-- who asked reads it. p_record maps a kind to the action recorded, in this
-- transaction, on a successful read of it. The answer is not_found, forbidden (recorded as denied,
-- bounded), run_open, result_removed, empty (the run ended without a
-- result: its status and error are returned), or ok.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_run_result(
    p_run uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[],
    p_kind_all boolean, p_kind_orgs uuid[], p_kind_sites uuid[],
    p_asker_kinds text[], p_record jsonb,
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text
) RETURNS TABLE (result text, res jsonb, complete boolean, run_status text, run_error text, started timestamptz,
                 finished timestamptz, agent_version text, job_kind text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    r record;
    s record;
    about jsonb;
BEGIN
    SELECT jr.organization_id AS org, jr.site_id AS site, jr.device_id AS device, jr.job_id AS job,
           d.name AS device_name, j.kind AS kind, j.created_by AS asker, j.executor AS executor
      INTO r
      FROM public.job_runs jr
      JOIN public.jobs j ON j.id = jr.job_id
      JOIN public.devices d ON d.id = jr.device_id
     WHERE jr.id = p_run;
    IF NOT FOUND OR r.executor <> 'builtin'
       OR NOT public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, r.org, r.site) THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::jsonb, NULL::boolean, NULL::text, NULL::text, NULL::timestamptz,
            NULL::timestamptz, NULL::text, NULL::text;
        RETURN;
    END IF;
    about := jsonb_build_object('device', r.device_name, 'jobId', r.job::text, 'kind', r.kind);
    IF NOT public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, r.org, r.site)
       OR NOT public.easyrmm_job_scope_covers(p_kind_all, p_kind_orgs, p_kind_sites, r.org, r.site)
       OR (r.kind = ANY (p_asker_kinds) AND r.asker IS DISTINCT FROM p_actor_id) THEN
        PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, r.org, r.site,
            r.device, 'job_run.result_view', 'job_run', p_run::text, p_source_ip, p_user_agent, about);
        RETURN QUERY SELECT 'forbidden'::text, NULL::jsonb, NULL::boolean, NULL::text, NULL::text, NULL::timestamptz,
            NULL::timestamptz, NULL::text, NULL::text;
        RETURN;
    END IF;
    -- The lock keeps a removal from emptying the result between the checks
    -- below and the read.
    SELECT jr.status AS status, jr.error AS err, jr.started_at AS started, jr.finished_at AS finished,
           jr.result_stored_at AS stored, jr.result_removed_at AS removed, jr.result_complete AS complete,
           jr.ran_agent_version AS agent
      INTO s
      FROM public.job_runs jr
     WHERE jr.id = p_run
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::jsonb, NULL::boolean, NULL::text, NULL::text, NULL::timestamptz,
            NULL::timestamptz, NULL::text, NULL::text;
        RETURN;
    END IF;
    IF s.status IN ('queued', 'sent', 'running') THEN
        RETURN QUERY SELECT 'run_open'::text, NULL::jsonb, NULL::boolean, s.status, NULL::text, s.started,
            NULL::timestamptz, NULL::text, r.kind;
        RETURN;
    END IF;
    IF s.removed IS NOT NULL THEN
        RETURN QUERY SELECT 'result_removed'::text, NULL::jsonb, NULL::boolean, s.status, s.err, s.started, s.finished, s.agent, r.kind;
        RETURN;
    END IF;
    IF s.stored IS NULL THEN
        RETURN QUERY SELECT 'empty'::text, NULL::jsonb, false, s.status, s.err, s.started, s.finished, s.agent, r.kind;
        RETURN;
    END IF;
    IF p_record ->> r.kind IS NOT NULL THEN
        PERFORM public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label, r.org, r.site, r.device,
            p_record ->> r.kind, 'job_run', p_run::text, 'success', p_source_ip, p_user_agent, about);
    END IF;
    RETURN QUERY SELECT 'ok'::text, jr.result, s.complete, s.status, s.err, s.started, s.finished, s.agent, r.kind
        FROM public.job_runs jr WHERE jr.id = p_run;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_run_result(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], jsonb, timestamptz, text, uuid, text, inet, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_run_result(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], jsonb, timestamptz, text, uuid, text, inet, text) TO easyrmm_app;

-- A structured job's input for a person, under the same checks as its
-- results: job.view_sensitive and the kind's permission at the site of a
-- run the caller can see, and for a query, that the caller asked.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_input(
    p_job uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[],
    p_kind_all boolean, p_kind_orgs uuid[], p_kind_sites uuid[],
    p_asker_kinds text[],
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text
) RETURNS TABLE (result text, job_input jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    j record;
    v_org uuid;
    v_site uuid;
    v_n bigint;
    allowed boolean;
BEGIN
    SELECT jb.kind AS kind, jb.created_by AS asker, jb.executor AS executor INTO j FROM public.jobs jb WHERE jb.id = p_job;
    IF NOT FOUND OR j.executor <> 'builtin' THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::jsonb;
        RETURN;
    END IF;
    SELECT bool_or(public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, jr.organization_id, jr.site_id)
               AND public.easyrmm_job_scope_covers(p_kind_all, p_kind_orgs, p_kind_sites, jr.organization_id, jr.site_id)),
           min(jr.organization_id::text)::uuid, min(jr.site_id::text)::uuid, count(*)
      INTO allowed, v_org, v_site, v_n
      FROM public.job_runs jr
     WHERE jr.job_id = p_job
       AND public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id);
    IF v_n IS NULL OR v_n = 0 THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::jsonb;
        RETURN;
    END IF;
    IF NOT coalesce(allowed, false) OR (j.kind = ANY (p_asker_kinds) AND j.asker IS DISTINCT FROM p_actor_id) THEN
        PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, v_org, v_site, NULL,
            'job.arguments_view', 'job', p_job::text, p_source_ip, p_user_agent,
            jsonb_build_object('jobId', p_job::text, 'kind', j.kind));
        RETURN QUERY SELECT 'forbidden'::text, NULL::jsonb;
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.job_inputs ji WHERE ji.job_id = p_job AND ji.removed_at IS NULL) THEN
        RETURN QUERY SELECT 'result_removed'::text, NULL::jsonb;
        RETURN;
    END IF;
    RETURN QUERY SELECT 'ok'::text, ji.input FROM public.job_inputs ji WHERE ji.job_id = p_job;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_input(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], timestamptz, text, uuid, text, inet, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_input(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], timestamptz, text, uuid, text, inet, text) TO easyrmm_app;

-- The inputs of runs the poll has just delivered. Like
-- easyrmm_job_delivery_args, it answers only under the system scope.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_delivery_inputs(p_device uuid, p_runs uuid[])
RETURNS TABLE (run_id uuid, run_input jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT jr.id, ji.input
      FROM public.job_runs jr JOIN public.job_inputs ji ON ji.job_id = jr.job_id
     WHERE public.easyrmm_scope_all() AND jr.device_id = p_device AND jr.id = ANY (p_runs) AND jr.status = 'sent'
       AND ji.removed_at IS NULL
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_delivery_inputs(uuid, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_delivery_inputs(uuid, uuid[]) TO easyrmm_app;

-- The input of one run's job, for the server when the run's result arrives,
-- to check the result against it. Under the system scope only.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_run_input_system(p_run uuid)
RETURNS TABLE (job_kind text, job_input jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT j.kind, ji.input
      FROM public.job_runs jr JOIN public.jobs j ON j.id = jr.job_id
      LEFT JOIN public.job_inputs ji ON ji.job_id = jr.job_id
     WHERE public.easyrmm_scope_all() AND jr.id = p_run
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_run_input_system(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_run_input_system(uuid) TO easyrmm_app;

-- +goose Down
DROP FUNCTION easyrmm_job_run_input_system(uuid);
DROP FUNCTION easyrmm_job_delivery_inputs(uuid, uuid[]);
DROP FUNCTION easyrmm_job_input(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], timestamptz, text, uuid, text, inet, text);
DROP FUNCTION easyrmm_job_run_result(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], jsonb, timestamptz, text, uuid, text, inet, text);
DROP TABLE registry_masked_values;
DROP TABLE job_inputs;
DROP TRIGGER job_runs_result_size ON job_runs;
DROP FUNCTION easyrmm_job_runs_result_size();
DROP INDEX job_runs_result_stored_idx;
ALTER TABLE job_runs
    DROP CONSTRAINT job_runs_result_removed,
    DROP CONSTRAINT job_runs_result_stored,
    DROP COLUMN ran_agent_sha256,
    DROP COLUMN ran_agent_version,
    DROP COLUMN result_complete,
    DROP COLUMN result_removed_at,
    DROP COLUMN result_stored_at,
    DROP COLUMN result_bytes,
    DROP COLUMN result;
DELETE FROM jobs WHERE executor = 'builtin';
ALTER TABLE jobs
    DROP CONSTRAINT jobs_builtin_hidden,
    DROP CONSTRAINT jobs_builtin_kind,
    DROP CONSTRAINT jobs_builtin_executor,
    DROP CONSTRAINT jobs_body_check,
    DROP CONSTRAINT jobs_shell_check,
    DROP CONSTRAINT jobs_kind_check;
ALTER TABLE jobs
    DROP COLUMN signed_bytes,
    DROP COLUMN lane,
    DROP COLUMN builtin,
    DROP COLUMN executor;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening', 'winmod')),
    ADD CONSTRAINT jobs_shell_check CHECK (shell IN ('powershell', 'pwsh', 'cmd', 'sh', 'bash', 'python3')),
    ADD CONSTRAINT jobs_body_check CHECK (octet_length(body) BETWEEN 1 AND 524288);
