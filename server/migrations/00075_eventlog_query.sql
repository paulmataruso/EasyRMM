-- ADR-0068, slice 1: the event viewer's kind of job, eventlog_query, beside
-- ADR-0067's two. It reads a Windows computer's event logs through a builtin
-- of the agent; its input and result are kept an hour, for the person who
-- asked only. This migration:
--   * admits the kind;
--   * counts eventlog.refused in the refusal bound (20 per caller in 10
--     minutes), as ADR-0067 counts registry.refused;
--   * records a refusal of the Security log, a refused channel name or a
--     previous page that is not the caller's (easyrmm_eventlog_refusal);
--   * reads a result and an input with the permission the input asked for a
--     second time (easyrmm_eventlog_result, easyrmm_eventlog_input): a query
--     for sensitive data is read only by someone who still holds
--     log.view_sensitive, whatever the first check said an hour before;
--   * returns the input and cursor a next page is built from
--     (easyrmm_eventlog_page), so that the filters are the same by
--     construction and easyrmm_app has no grant on the input or the result.

-- +goose Up
ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check;
ALTER TABLE jobs DROP CONSTRAINT jobs_builtin_kind;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening', 'winmod', 'registry_query', 'registry_change', 'eventlog_query')),
    ADD CONSTRAINT jobs_builtin_kind CHECK ((executor = 'builtin') = (kind IN ('registry_query', 'registry_change', 'eventlog_query')));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION easyrmm_job_refusal(
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_organization_id uuid, p_site_id uuid, p_device_id uuid, p_action text,
    p_target_type text, p_target_id text, p_source_ip inet, p_user_agent text, p_details jsonb
) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(63, hashtext(coalesce(p_actor_id::text, p_actor_label)));
    IF EXISTS (SELECT 1 FROM public.audit_log a
                WHERE a.actor_id = p_actor_id AND a.occurred_at > p_at - interval '10 minutes'
                  AND a.action = p_action AND a.target_id = p_target_id AND a.outcome = 'denied'
                  AND a.organization_id IS NOT DISTINCT FROM p_organization_id)
       OR (SELECT count(*) FROM public.audit_log a
            WHERE a.actor_id = p_actor_id AND a.occurred_at > p_at - interval '10 minutes'
              AND a.action IN ('job_run.output_view', 'job.arguments_view', 'job_run.result_view', 'registry.refused', 'eventlog.refused')
              AND a.outcome = 'denied') >= 20 THEN
        RETURN;
    END IF;
    PERFORM public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label, p_organization_id,
        p_site_id, p_device_id, p_action, p_target_type, p_target_id, 'denied', p_source_ip, p_user_agent, p_details);
END
$$;
-- +goose StatementEnd

-- Records that the server refused an event log request, as eventlog.refused,
-- within the bound above. The device is looked up under the request's own
-- scope, so a person can only have a refusal recorded for a device they can see.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_eventlog_refusal(
    p_device uuid, p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text, p_details jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    d record;
BEGIN
    SELECT dv.organization_id AS org, dv.site_id AS site INTO d FROM public.devices dv WHERE dv.id = p_device;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, d.org, d.site, p_device,
        'eventlog.refused', 'device', p_device::text, p_source_ip, p_user_agent, p_details);
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_eventlog_refusal(uuid, timestamptz, text, uuid, text, inet, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_eventlog_refusal(uuid, timestamptz, text, uuid, text, inet, text, jsonb) TO easyrmm_app;

-- A result for a person: easyrmm_job_run_result's answer, after asking for
-- log.view_sensitive again where the input said sensitive. The input is read
-- here, under the function's own rights; a result with no input to say is
-- treated as sensitive, and one that was removed is not (it answers
-- result_removed to everyone).
-- +goose StatementBegin
CREATE FUNCTION easyrmm_eventlog_result(
    p_run uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[],
    p_kind_all boolean, p_kind_orgs uuid[], p_kind_sites uuid[],
    p_asker_kinds text[], p_record jsonb,
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text,
    p_sens_all boolean, p_sens_orgs uuid[], p_sens_sites uuid[]
) RETURNS TABLE (result text, res jsonb, complete boolean, run_status text, run_error text, started timestamptz,
                 finished timestamptz, agent_version text, job_kind text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    r record;
BEGIN
    SELECT jr.organization_id AS org, jr.site_id AS site, jr.device_id AS device, jr.job_id AS job, j.kind AS kind,
           d.name AS device_name,
           coalesce(ji.input ->> 'sensitive', CASE WHEN jr.result_stored_at IS NOT NULL THEN 'true' ELSE 'false' END) AS sens
      INTO r
      FROM public.job_runs jr
      JOIN public.jobs j ON j.id = jr.job_id
      JOIN public.devices d ON d.id = jr.device_id
      LEFT JOIN public.job_inputs ji ON ji.job_id = jr.job_id
     WHERE jr.id = p_run;
    IF FOUND AND r.kind = 'eventlog_query' AND r.sens = 'true'
       AND public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, r.org, r.site)
       AND NOT public.easyrmm_job_scope_covers(p_sens_all, p_sens_orgs, p_sens_sites, r.org, r.site) THEN
        PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, r.org, r.site, r.device,
            'job_run.result_view', 'job_run', p_run::text, p_source_ip, p_user_agent,
            jsonb_build_object('device', r.device_name, 'jobId', r.job::text, 'kind', r.kind));
        RETURN QUERY SELECT 'forbidden'::text, NULL::jsonb, NULL::boolean, NULL::text, NULL::text, NULL::timestamptz,
            NULL::timestamptz, NULL::text, NULL::text;
        RETURN;
    END IF;
    RETURN QUERY SELECT * FROM public.easyrmm_job_run_result(p_run, p_view_all, p_view_orgs, p_view_sites,
        p_read_all, p_read_orgs, p_read_sites, p_kind_all, p_kind_orgs, p_kind_sites, p_asker_kinds, p_record,
        p_at, p_actor_type, p_actor_id, p_actor_label, p_source_ip, p_user_agent);
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_eventlog_result(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], jsonb, timestamptz, text, uuid, text, inet, text, boolean, uuid[], uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_eventlog_result(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], jsonb, timestamptz, text, uuid, text, inet, text, boolean, uuid[], uuid[]) TO easyrmm_app;

-- The same for a job's input (a person reading the arguments of a query).
-- +goose StatementBegin
CREATE FUNCTION easyrmm_eventlog_input(
    p_job uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[],
    p_kind_all boolean, p_kind_orgs uuid[], p_kind_sites uuid[],
    p_asker_kinds text[],
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text,
    p_sens_all boolean, p_sens_orgs uuid[], p_sens_sites uuid[]
) RETURNS TABLE (result text, job_input jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    j record;
BEGIN
    SELECT jb.kind AS kind, coalesce(ji.input ->> 'sensitive', CASE WHEN ji.job_id IS NOT NULL THEN 'false' ELSE 'true' END) AS sens,
           (SELECT min(jr.organization_id::text)::uuid FROM public.job_runs jr WHERE jr.job_id = jb.id) AS org,
           (SELECT min(jr.site_id::text)::uuid FROM public.job_runs jr WHERE jr.job_id = jb.id) AS site
      INTO j
      FROM public.jobs jb LEFT JOIN public.job_inputs ji ON ji.job_id = jb.id
     WHERE jb.id = p_job;
    IF FOUND AND j.kind = 'eventlog_query' AND j.sens = 'true'
       AND public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, j.org, j.site)
       AND NOT public.easyrmm_job_scope_covers(p_sens_all, p_sens_orgs, p_sens_sites, j.org, j.site) THEN
        PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, j.org, j.site, NULL,
            'job.arguments_view', 'job', p_job::text, p_source_ip, p_user_agent,
            jsonb_build_object('jobId', p_job::text, 'kind', j.kind));
        RETURN QUERY SELECT 'forbidden'::text, NULL::jsonb;
        RETURN;
    END IF;
    RETURN QUERY SELECT * FROM public.easyrmm_job_input(p_job, p_view_all, p_view_orgs, p_view_sites,
        p_read_all, p_read_orgs, p_read_sites, p_kind_all, p_kind_orgs, p_kind_sites, p_asker_kinds,
        p_at, p_actor_type, p_actor_id, p_actor_label, p_source_ip, p_user_agent);
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_eventlog_input(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], timestamptz, text, uuid, text, inet, text, boolean, uuid[], uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_eventlog_input(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], timestamptz, text, uuid, text, inet, text, boolean, uuid[], uuid[]) TO easyrmm_app;

-- What a next page is built from: the previous run's input and the last line
-- of its result (the end line, which holds the cursor). The caller must be
-- the person who asked, for the same device, within the hour; a query for
-- sensitive data needs log.view_sensitive again. Answers not_found,
-- forbidden (recorded as eventlog.refused, within the bound), run_open,
-- expired (a result removed, or not there) or ok.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_eventlog_page(
    p_prev uuid, p_device uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_sens_all boolean, p_sens_orgs uuid[], p_sens_sites uuid[],
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text
) RETURNS TABLE (result text, prev_input jsonb, last_line jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    r record;
BEGIN
    SELECT jr.organization_id AS org, jr.site_id AS site, jr.device_id AS device, jr.status AS status,
           jr.result_stored_at AS stored, jr.result_removed_at AS removed, j.kind AS kind, j.created_by AS asker,
           ji.input AS input, jr.result -> -1 AS last
      INTO r
      FROM public.job_runs jr
      JOIN public.jobs j ON j.id = jr.job_id
      LEFT JOIN public.job_inputs ji ON ji.job_id = jr.job_id AND ji.removed_at IS NULL
     WHERE jr.id = p_prev;
    IF NOT FOUND OR r.kind <> 'eventlog_query'
       OR NOT public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, r.org, r.site) THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::jsonb, NULL::jsonb;
        RETURN;
    END IF;
    IF r.device IS DISTINCT FROM p_device OR r.asker IS DISTINCT FROM p_actor_id
       OR (coalesce(r.input ->> 'sensitive', 'true') = 'true'
           AND NOT public.easyrmm_job_scope_covers(p_sens_all, p_sens_orgs, p_sens_sites, r.org, r.site)) THEN
        PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, r.org, r.site, p_device,
            'eventlog.refused', 'device', p_device::text, p_source_ip, p_user_agent,
            jsonb_build_object('rule', 'the previous page is not yours, or is for another device'));
        RETURN QUERY SELECT 'forbidden'::text, NULL::jsonb, NULL::jsonb;
        RETURN;
    END IF;
    IF r.status IN ('queued', 'sent', 'running') THEN
        RETURN QUERY SELECT 'run_open'::text, NULL::jsonb, NULL::jsonb;
        RETURN;
    END IF;
    IF r.removed IS NOT NULL OR r.stored IS NULL OR r.stored < p_at - interval '1 hour' OR r.input IS NULL OR r.last IS NULL THEN
        RETURN QUERY SELECT 'expired'::text, NULL::jsonb, NULL::jsonb;
        RETURN;
    END IF;
    RETURN QUERY SELECT 'ok'::text, r.input, r.last;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_eventlog_page(uuid, uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_eventlog_page(uuid, uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) TO easyrmm_app;

-- +goose Down
DROP FUNCTION easyrmm_eventlog_page(uuid, uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text);
DROP FUNCTION easyrmm_eventlog_input(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], timestamptz, text, uuid, text, inet, text, boolean, uuid[], uuid[]);
DROP FUNCTION easyrmm_eventlog_result(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], boolean, uuid[], uuid[], text[], jsonb, timestamptz, text, uuid, text, inet, text, boolean, uuid[], uuid[]);
DROP FUNCTION easyrmm_eventlog_refusal(uuid, timestamptz, text, uuid, text, inet, text, jsonb);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION easyrmm_job_refusal(
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_organization_id uuid, p_site_id uuid, p_device_id uuid, p_action text,
    p_target_type text, p_target_id text, p_source_ip inet, p_user_agent text, p_details jsonb
) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(63, hashtext(coalesce(p_actor_id::text, p_actor_label)));
    IF EXISTS (SELECT 1 FROM public.audit_log a
                WHERE a.actor_id = p_actor_id AND a.occurred_at > p_at - interval '10 minutes'
                  AND a.action = p_action AND a.target_id = p_target_id AND a.outcome = 'denied'
                  AND a.organization_id IS NOT DISTINCT FROM p_organization_id)
       OR (SELECT count(*) FROM public.audit_log a
            WHERE a.actor_id = p_actor_id AND a.occurred_at > p_at - interval '10 minutes'
              AND a.action IN ('job_run.output_view', 'job.arguments_view', 'job_run.result_view', 'registry.refused')
              AND a.outcome = 'denied') >= 20 THEN
        RETURN;
    END IF;
    PERFORM public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label, p_organization_id,
        p_site_id, p_device_id, p_action, p_target_type, p_target_id, 'denied', p_source_ip, p_user_agent, p_details);
END
$$;
-- +goose StatementEnd
DELETE FROM jobs WHERE kind = 'eventlog_query';
ALTER TABLE jobs DROP CONSTRAINT jobs_builtin_kind;
ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('script', 'software', 'hardening', 'winmod', 'registry_query', 'registry_change')),
    ADD CONSTRAINT jobs_builtin_kind CHECK ((executor = 'builtin') = (kind IN ('registry_query', 'registry_change')));
