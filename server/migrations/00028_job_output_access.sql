-- Who reads a job's output and arguments (ADR-0063). The runtime role can
-- no longer select job_runs.stdout, job_runs.stderr or jobs.args. They are
-- read only through functions that check the caller's permission and
-- append the audit record in the same transaction, and by the poll that
-- delivers a job to its device. Output is kept for a shorter time than the
-- job, counted from when it arrived, and can be removed at once.

-- +goose Up

-- Sizes and the number of arguments are kept by the database, so the
-- runtime role can read them without reading what they measure.
-- output_stored_at is when the output arrived and is set only while there
-- is output; output_removed_at is when retention or a person removed it.
-- Columns with a constant default are added without rewriting the table;
-- the triggers below keep them, and the backfill writes only the rows that
-- have something to count.
ALTER TABLE job_runs
    ADD COLUMN stdout_bytes integer NOT NULL DEFAULT 0,
    ADD COLUMN stderr_bytes integer NOT NULL DEFAULT 0,
    ADD COLUMN output_stored_at timestamptz,
    ADD COLUMN output_removed_at timestamptz;
ALTER TABLE jobs ADD COLUMN arg_count integer NOT NULL DEFAULT 0;

-- Output kept before this counts from when its run finished: each run with
-- output is written once. job_runs forces row-level security, on its owner
-- too; jobs has no policy for updates, so it is lifted for its backfill
-- inside this transaction.
SELECT set_config('easyrmm.scope_all', 'on', true);
UPDATE job_runs SET stdout_bytes = octet_length(stdout), stderr_bytes = octet_length(stderr), output_stored_at = finished_at
 WHERE stdout <> '' OR stderr <> '';
ALTER TABLE jobs NO FORCE ROW LEVEL SECURITY;
UPDATE jobs SET arg_count = cardinality(args) WHERE cardinality(args) > 0;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;

-- From here the sizes and the count follow what is written, whatever a
-- statement sets them to.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_runs_sizes() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.stdout_bytes := octet_length(NEW.stdout);
    NEW.stderr_bytes := octet_length(NEW.stderr);
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER job_runs_sizes BEFORE INSERT OR UPDATE OF stdout, stderr, stdout_bytes, stderr_bytes ON job_runs
    FOR EACH ROW EXECUTE FUNCTION easyrmm_job_runs_sizes();
-- +goose StatementBegin
CREATE FUNCTION easyrmm_jobs_arg_count() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.arg_count := cardinality(NEW.args);
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER jobs_arg_count BEFORE INSERT OR UPDATE OF args, arg_count ON jobs
    FOR EACH ROW EXECUTE FUNCTION easyrmm_jobs_arg_count();

ALTER TABLE job_runs
    ADD CONSTRAINT job_runs_output_stored CHECK ((output_stored_at IS NOT NULL) = (stdout <> '' OR stderr <> '')),
    ADD CONSTRAINT job_runs_output_removed CHECK (output_removed_at IS NULL OR output_stored_at IS NULL);
CREATE INDEX job_runs_output_stored_idx ON job_runs (output_stored_at) WHERE output_stored_at IS NOT NULL;

-- Every column but the output and the arguments. A column added to either
-- table later must be granted here too, or the server cannot read it.
REVOKE SELECT ON job_runs, jobs FROM easyrmm_app;
GRANT SELECT (id, job_id, organization_id, site_id, device_id, status, created_at, expires_at, sent_at,
    deliveries, started_at, deadline_at, finished_at, exit_code, stdout_truncated, stderr_truncated,
    error, cancel_requested_at, canceled_by, cancel_sent_at, stdout_bytes, stderr_bytes,
    output_stored_at, output_removed_at) ON job_runs TO easyrmm_app;
GRANT SELECT (id, script_id, script_name, shell, body, body_sha256, timeout_seconds, expires_at,
    created_by, created_by_label, created_at, kind, software, hardening, arg_count) ON jobs TO easyrmm_app;

-- Whether a permission's scope, as the server resolved it from the
-- caller's roles, covers a run's organization and site.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_scope_covers(p_all boolean, p_orgs uuid[], p_sites uuid[], p_org uuid, p_site uuid)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT coalesce(p_all, false) OR coalesce(p_org = ANY (p_orgs), false) OR coalesce(p_site = ANY (p_sites), false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_scope_covers(boolean, uuid[], uuid[], uuid, uuid) FROM PUBLIC;

-- Records a refused read, at most once per user, action, target and
-- organization in 10 minutes, and at most 20 times per user in 10 minutes
-- across both reads. The audit log itself is the state, so the bound holds
-- for every server process; the lock per user keeps two requests from both
-- finding nothing and both writing. It runs in the request's transaction:
-- if the record cannot be written, the request fails.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_refusal(
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_organization_id uuid, p_site_id uuid, p_device_id uuid, p_action text,
    p_target_type text, p_target_id text, p_source_ip inet, p_user_agent text, p_details jsonb
) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    -- 63: ADR-0063. The two-key form shares no keys with one-key locks.
    PERFORM pg_advisory_xact_lock(63, hashtext(coalesce(p_actor_id::text, p_actor_label)));
    IF EXISTS (SELECT 1 FROM public.audit_log a
                WHERE a.actor_id = p_actor_id AND a.occurred_at > p_at - interval '10 minutes'
                  AND a.action = p_action AND a.target_id = p_target_id AND a.outcome = 'denied'
                  AND a.organization_id IS NOT DISTINCT FROM p_organization_id)
       OR (SELECT count(*) FROM public.audit_log a
            WHERE a.actor_id = p_actor_id AND a.occurred_at > p_at - interval '10 minutes'
              AND a.action IN ('job_run.output_view', 'job.arguments_view') AND a.outcome = 'denied') >= 20 THEN
        RETURN;
    END IF;
    PERFORM public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label, p_organization_id,
        p_site_id, p_device_id, p_action, p_target_type, p_target_id, 'denied', p_source_ip, p_user_agent, p_details);
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_refusal(timestamptz, text, uuid, text, uuid, uuid, uuid, text, text, text, inet, text, jsonb) FROM PUBLIC;

-- A run's output for a person. view is the caller's job.view scope, read
-- their job.view_sensitive scope. Row-level security applies inside, on
-- the owner too, so a run outside the request's scope is not found. The
-- result is one of not_found, forbidden (recorded as denied, bounded),
-- run_open, output_removed, empty, or ok with the output, recorded as
-- job_run.output_view in this transaction.
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
REVOKE ALL ON FUNCTION easyrmm_job_run_output(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_run_output(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) TO easyrmm_app;

-- A job's arguments for a person, with the same scopes and results. The
-- arguments belong to the whole job: they are returned when the caller
-- may read them at the site of one run they can see. A read is recorded
-- once for each organization of those runs, under the site when the runs
-- there share one; a refusal under each organization of the runs the
-- caller can see.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_arguments(
    p_job uuid,
    p_view_all boolean, p_view_orgs uuid[], p_view_sites uuid[],
    p_read_all boolean, p_read_orgs uuid[], p_read_sites uuid[],
    p_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_source_ip inet, p_user_agent text
) RETURNS TABLE (result text, job_args text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    j record;
    g record;
    seen boolean;
    allowed boolean;
    about jsonb;
BEGIN
    SELECT jb.script_name AS script, jb.kind AS kind, jb.arg_count AS arg_count INTO j
      FROM public.jobs jb WHERE jb.id = p_job;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text[];
        RETURN;
    END IF;
    SELECT bool_or(public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id)),
           bool_or(public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id)
               AND public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, jr.organization_id, jr.site_id))
      INTO seen, allowed
      FROM public.job_runs jr WHERE jr.job_id = p_job;
    IF NOT coalesce(seen, false) THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text[];
        RETURN;
    END IF;
    about := jsonb_build_object('jobId', p_job::text, 'script', j.script, 'kind', j.kind, 'argCount', j.arg_count);
    FOR g IN
        SELECT jr.organization_id AS org,
               CASE WHEN count(DISTINCT jr.site_id) = 1 THEN min(jr.site_id::text)::uuid END AS site
          FROM public.job_runs jr
         WHERE jr.job_id = p_job
           AND public.easyrmm_job_scope_covers(p_view_all, p_view_orgs, p_view_sites, jr.organization_id, jr.site_id)
           AND (NOT allowed OR public.easyrmm_job_scope_covers(p_read_all, p_read_orgs, p_read_sites, jr.organization_id, jr.site_id))
         GROUP BY jr.organization_id
         ORDER BY jr.organization_id
    LOOP
        IF NOT allowed THEN
            PERFORM public.easyrmm_job_refusal(p_at, p_actor_type, p_actor_id, p_actor_label, g.org, g.site, NULL,
                'job.arguments_view', 'job', p_job::text, p_source_ip, p_user_agent, about);
        ELSIF j.arg_count > 0 THEN
            PERFORM public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label, g.org, g.site, NULL,
                'job.arguments_view', 'job', p_job::text, 'success', p_source_ip, p_user_agent, about);
        END IF;
    END LOOP;
    IF NOT allowed THEN
        RETURN QUERY SELECT 'forbidden'::text, NULL::text[];
    ELSIF j.arg_count = 0 THEN
        RETURN QUERY SELECT 'empty'::text, '{}'::text[];
    ELSE
        RETURN QUERY SELECT 'ok'::text, jb.args FROM public.jobs jb WHERE jb.id = p_job;
    END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_arguments(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_arguments(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text) TO easyrmm_app;

-- The arguments of runs the poll has just delivered to their device. It
-- answers only under the system scope the poll runs with, so a request
-- made for a person cannot use it. Delivery is not a person reading, and
-- is not recorded.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_job_delivery_args(p_device uuid, p_runs uuid[])
RETURNS TABLE (run_id uuid, run_args text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT jr.id, j.args
      FROM public.job_runs jr JOIN public.jobs j ON j.id = jr.job_id
     WHERE public.easyrmm_scope_all() AND jr.device_id = p_device AND jr.id = ANY (p_runs) AND jr.status = 'sent'
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_job_delivery_args(uuid, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_job_delivery_args(uuid, uuid[]) TO easyrmm_app;

-- +goose Down
DROP FUNCTION easyrmm_job_delivery_args(uuid, uuid[]);
DROP FUNCTION easyrmm_job_arguments(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text);
DROP FUNCTION easyrmm_job_run_output(uuid, boolean, uuid[], uuid[], boolean, uuid[], uuid[], timestamptz, text, uuid, text, inet, text);
DROP FUNCTION easyrmm_job_refusal(timestamptz, text, uuid, text, uuid, uuid, uuid, text, text, text, inet, text, jsonb);
DROP FUNCTION easyrmm_job_scope_covers(boolean, uuid[], uuid[], uuid, uuid);
-- Revoking on the table revokes the column grants too.
REVOKE SELECT ON job_runs, jobs FROM easyrmm_app;
GRANT SELECT ON job_runs, jobs TO easyrmm_app;
DROP INDEX job_runs_output_stored_idx;
DROP TRIGGER jobs_arg_count ON jobs;
DROP FUNCTION easyrmm_jobs_arg_count();
DROP TRIGGER job_runs_sizes ON job_runs;
DROP FUNCTION easyrmm_job_runs_sizes();
ALTER TABLE job_runs
    DROP CONSTRAINT job_runs_output_removed,
    DROP CONSTRAINT job_runs_output_stored,
    DROP COLUMN output_removed_at,
    DROP COLUMN output_stored_at,
    DROP COLUMN stderr_bytes,
    DROP COLUMN stdout_bytes;
ALTER TABLE jobs DROP COLUMN arg_count;
