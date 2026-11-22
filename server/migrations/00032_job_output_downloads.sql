-- Downloading a job's output (ADR-0064, "Downloads and results"). Output is
-- still read only through functions that check job.view_sensitive and
-- append the audit record in the same transaction (ADR-0063):
--
-- * easyrmm_job_run_output takes what is downloaded (a stream, or the run as
--   JSON), and records it with the read;
-- * easyrmm_job_output_zip records, in one transaction, a read of every
--   finished run of a job the caller may read, and names them;
-- * easyrmm_job_run_output_recorded then hands out one of those runs'
--   output, in a short transaction of its own, against the record of its
--   read: only to the caller it records, for that run, and for a day by the
--   database's clock.

-- +goose Up
DROP FUNCTION easyrmm_job_run_output(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text);

-- A run's output for a person. view is the caller's job.view scope, read
-- their job.view_sensitive scope, download what is downloaded (stdout,
-- stderr or json) or NULL for the console's page. Row-level security
-- applies inside, on the owner too, so a run outside the request's scope is
-- not found. The result is one of not_found, forbidden (recorded as denied,
-- bounded), run_open, output_removed, empty, or ok with the output,
-- recorded as job_run.output_view in this transaction.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_run_output(
    p_run uuid, p_download text,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[],
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text
) RETURNS TABLE (result text, out_text text, err_text text, out_cut boolean, err_cut boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    r record;
    s record;
    about jsonb;
BEGIN
    IF p_download IS NOT NULL AND p_download NOT IN ('stdout', 'stderr', 'json') THEN
        RAISE EXCEPTION 'easyrmm_job_run_output: unknown download %', p_download;
    END IF;
    SELECT jr.organization_id AS org, jr.site_id AS site, jr.device_id AS device, jr.job_id AS job,
           d.name AS device_name, j.script_name AS script, j.kind AS kind
      INTO r
      FROM public.job_runs jr
      JOIN public.jobs j ON j.id = jr.job_id
      JOIN public.devices d ON d.id = jr.device_id
     WHERE jr.id = p_run;
    IF NOT FOUND OR NOT public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, r.org, r.site) THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    about := jsonb_build_object('device', r.device_name, 'jobId', r.job::text, 'script', r.script, 'kind', r.kind)
        || CASE WHEN p_download IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('download', p_download) END;
    IF NOT public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, r.org, r.site) THEN
        PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, r.org, r.site,
            r.device, 'job_run.output_view', 'job_run', p_run::text, p_source_ip, p_user_agent, about);
        RETURN QUERY SELECT 'forbidden'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    -- Only a caller who may read takes the lock, which keeps a removal from
    -- emptying the output between the checks below and the read.
    SELECT jr.status AS status, jr.stdout_bytes AS out_bytes, jr.stderr_bytes AS err_bytes,
           jr.output_stored_at AS stored, jr.output_removed_at AS removed
      INTO s
      FROM public.job_runs jr
     WHERE jr.id = p_run
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    IF s.status IN ('queued', 'sent', 'running') THEN
        RETURN QUERY SELECT 'run_open'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    IF s.removed IS NOT NULL THEN
        RETURN QUERY SELECT 'output_removed'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    IF s.stored IS NULL THEN
        RETURN QUERY SELECT 'empty'::text, ''::text, ''::text, false, false;
        RETURN;
    END IF;
    PERFORM public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label, r.org, r.site, r.device,
        'job_run.output_view', 'job_run', p_run::text, 'success', p_source_ip, p_user_agent,
        about || jsonb_build_object('stdoutBytes', s.out_bytes, 'stderrBytes', s.err_bytes));
    RETURN QUERY SELECT 'ok'::text, jr.stdout, jr.stderr, jr.stdout_truncated, jr.stderr_truncated
        FROM public.job_runs jr WHERE jr.id = p_run;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_run_output(uuid, text, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_run_output(uuid, text, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) TO easyrmm_app;

-- Records a download of a whole job's output: one job_run.output_view, with
-- download zip, for each finished run the caller sees and may read whose
-- output was not removed and is not empty, under the run's organization,
-- site and device. It returns those runs with the id of their record, and
-- the finished runs they may read that printed nothing, without one: their
-- streams are empty, so nothing is read. A caller who sees runs of the job
-- and may read none of them is refused, recorded as denied once for each
-- organization of the runs they see, under the site when those runs share
-- one, within the bound easyrmm_job_refusal keeps; the function then
-- returns no rows and result forbidden. A job the caller sees no run of is
-- not_found.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_output_zip(
    p_job uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[],
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text
) RETURNS TABLE (result text, run_id uuid, record_id bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    j record;
    g record;
    r record;
    seen boolean;
    allowed boolean;
BEGIN
    SELECT jb.script_name AS script, jb.kind AS kind INTO j FROM public.jobs jb WHERE jb.id = p_job;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::uuid, NULL::bigint;
        RETURN;
    END IF;
    SELECT bool_or(public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id)),
           bool_or(public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id)
               AND public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, jr.organization_id, jr.site_id))
      INTO seen, allowed
      FROM public.job_runs jr WHERE jr.job_id = p_job;
    IF NOT coalesce(seen, false) THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::uuid, NULL::bigint;
        RETURN;
    END IF;
    IF NOT allowed THEN
        FOR g IN
            SELECT jr.organization_id AS org,
                   CASE WHEN count(DISTINCT jr.site_id) = 1 THEN min(jr.site_id::text)::uuid END AS site
              FROM public.job_runs jr
             WHERE jr.job_id = p_job
               AND public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id)
             GROUP BY jr.organization_id
             ORDER BY jr.organization_id
        LOOP
            PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, g.org, g.site, NULL,
                'job_run.output_view', 'job', p_job::text, p_source_ip, p_user_agent,
                jsonb_build_object('jobId', p_job::text, 'script', j.script, 'kind', j.kind, 'download', 'zip'));
        END LOOP;
        RETURN QUERY SELECT 'forbidden'::text, NULL::uuid, NULL::bigint;
        RETURN;
    END IF;
    -- The runs the caller sees keep their state until the transaction ends,
    -- so the server reads them as they were chosen here. They are locked in
    -- the order canceling a job locks them (by device name, then run), so
    -- a download and a cancel of the same job never wait on each other.
    PERFORM 1 FROM (
        SELECT jr.id
          FROM public.job_runs jr
          JOIN public.devices d ON d.id = jr.device_id
         WHERE jr.job_id = p_job
           AND public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id)
         ORDER BY lower(d.name), jr.id
           FOR SHARE OF jr
    ) locked;
    FOR r IN
        SELECT jr.id, jr.organization_id AS org, jr.site_id AS site, jr.device_id AS device, d.name AS device_name,
               jr.stdout_bytes AS out_bytes, jr.stderr_bytes AS err_bytes, jr.output_stored_at AS stored
          FROM public.job_runs jr
          JOIN public.devices d ON d.id = jr.device_id
         WHERE jr.job_id = p_job
           AND jr.status NOT IN ('queued', 'sent', 'running')
           AND jr.output_removed_at IS NULL
           AND public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id)
           AND public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, jr.organization_id, jr.site_id)
         ORDER BY lower(d.name), jr.id
    LOOP
        IF r.stored IS NULL THEN
            RETURN QUERY SELECT 'ok'::text, r.id, NULL::bigint;
            CONTINUE;
        END IF;
        RETURN QUERY SELECT 'ok'::text, r.id, public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label,
            r.org, r.site, r.device, 'job_run.output_view', 'job_run', r.id::text, 'success', p_source_ip, p_user_agent,
            jsonb_build_object('device', r.device_name, 'jobId', p_job::text, 'script', j.script, 'kind', j.kind,
                'download', 'zip', 'stdoutBytes', r.out_bytes, 'stderrBytes', r.err_bytes));
    END LOOP;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_output_zip(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_output_zip(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) TO easyrmm_app;

-- One run's output, read for a job's download after easyrmm_job_output_zip
-- recorded it: only against that record, which must be a successful
-- job_run.output_view of this run, with download zip, by this caller, at
-- most a day old by the database's clock (clock_timestamp(); the server
-- passes no time, so it cannot extend the day), and no more than 5 minutes
-- ahead of it, the skew allowed between the server's clock and the
-- database's. The caller must still see the run and may still read it. The
-- result is not_found, forbidden, output_removed (removed after the
-- record) or ok with the output. Nothing is recorded: the record was
-- written, and committed, before the download began.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_run_output_recorded(
    p_run uuid, p_record bigint, p_actor_id uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[]
) RETURNS TABLE (result text, out_text text, err_text text, out_cut boolean, err_cut boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    r record;
    now_db timestamptz := clock_timestamp();
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.audit_log a
                    WHERE a.id = p_record AND a.action = 'job_run.output_view' AND a.outcome = 'success'
                      AND a.target_type = 'job_run' AND a.target_id = p_run::text
                      AND a.actor_id IS NOT DISTINCT FROM p_actor_id AND a.details->>'download' = 'zip'
                      AND a.occurred_at > now_db - interval '1 day' AND a.occurred_at <= now_db + interval '5 minutes') THEN
        RETURN QUERY SELECT 'forbidden'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    SELECT jr.organization_id AS org, jr.site_id AS site, jr.output_removed_at AS removed
      INTO r
      FROM public.job_runs jr
     WHERE jr.id = p_run
       FOR SHARE;
    IF NOT FOUND OR NOT public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, r.org, r.site) THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    IF NOT public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, r.org, r.site) THEN
        RETURN QUERY SELECT 'forbidden'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    IF r.removed IS NOT NULL THEN
        RETURN QUERY SELECT 'output_removed'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    RETURN QUERY SELECT 'ok'::text, jr.stdout, jr.stderr, jr.stdout_truncated, jr.stderr_truncated
        FROM public.job_runs jr WHERE jr.id = p_run;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_run_output_recorded(uuid, bigint, uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_run_output_recorded(uuid, bigint, uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[]) TO easyrmm_app;

-- +goose Down
DROP FUNCTION easyrmm_job_run_output_recorded(uuid, bigint, uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[]);
DROP FUNCTION easyrmm_job_output_zip(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text);
DROP FUNCTION easyrmm_job_run_output(uuid, text, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text);
-- As 00028 created it.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_run_output(
    p_run uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[],
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text
) RETURNS TABLE (result text, out_text text, err_text text, out_cut boolean, err_cut boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    r record;
    s record;
    about jsonb;
BEGIN
    SELECT jr.organization_id AS org, jr.site_id AS site, jr.device_id AS device, jr.job_id AS job,
           d.name AS device_name, j.script_name AS script, j.kind AS kind
      INTO r
      FROM public.job_runs jr
      JOIN public.jobs j ON j.id = jr.job_id
      JOIN public.devices d ON d.id = jr.device_id
     WHERE jr.id = p_run;
    IF NOT FOUND OR NOT public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, r.org, r.site) THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    about := jsonb_build_object('device', r.device_name, 'jobId', r.job::text, 'script', r.script, 'kind', r.kind);
    IF NOT public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, r.org, r.site) THEN
        PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, r.org, r.site,
            r.device, 'job_run.output_view', 'job_run', p_run::text, p_source_ip, p_user_agent, about);
        RETURN QUERY SELECT 'forbidden'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    SELECT jr.status AS status, jr.stdout_bytes AS out_bytes, jr.stderr_bytes AS err_bytes,
           jr.output_stored_at AS stored, jr.output_removed_at AS removed
      INTO s
      FROM public.job_runs jr
     WHERE jr.id = p_run
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    IF s.status IN ('queued', 'sent', 'running') THEN
        RETURN QUERY SELECT 'run_open'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    IF s.removed IS NOT NULL THEN
        RETURN QUERY SELECT 'output_removed'::text, NULL::text, NULL::text, NULL::boolean, NULL::boolean;
        RETURN;
    END IF;
    IF s.stored IS NULL THEN
        RETURN QUERY SELECT 'empty'::text, ''::text, ''::text, false, false;
        RETURN;
    END IF;
    PERFORM public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label, r.org, r.site, r.device,
        'job_run.output_view', 'job_run', p_run::text, 'success', p_source_ip, p_user_agent,
        about || jsonb_build_object('stdoutBytes', s.out_bytes, 'stderrBytes', s.err_bytes));
    RETURN QUERY SELECT 'ok'::text, jr.stdout, jr.stderr, jr.stdout_truncated, jr.stderr_truncated
        FROM public.job_runs jr WHERE jr.id = p_run;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_run_output(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_run_output(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) TO easyrmm_app;
