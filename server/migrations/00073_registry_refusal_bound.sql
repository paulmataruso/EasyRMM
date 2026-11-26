-- registry.refused and denied result reads come under the refusal bound
-- (ADR-0067, Audit): the count of 20 per caller in 10 minutes includes them,
-- beside job_run.output_view and job.arguments_view. The once per caller,
-- action, target and organization in 10 minutes holds as before.

-- +goose Up
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

-- Records that the server refused a request for a refused path, as
-- registry.refused, within the bound above. The device is looked up under
-- the request's own scope, so a person can only have a refusal recorded for
-- a device they can see.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_registry_refusal(
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
        'registry.refused', 'device', p_device::text, p_source_ip, p_user_agent, p_details);
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_registry_refusal(uuid, timestamptz, text, uuid, text, inet, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION easyrmm_registry_refusal(uuid, timestamptz, text, uuid, text, inet, text, jsonb) TO easyrmm_app;

-- +goose Down
DROP FUNCTION easyrmm_registry_refusal(uuid, timestamptz, text, uuid, text, inet, text, jsonb);
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
              AND a.action IN ('job_run.output_view', 'job.arguments_view') AND a.outcome = 'denied') >= 20 THEN
        RETURN;
    END IF;
    PERFORM public.easyrmm_audit_append(p_at, p_actor_type, p_actor_id, p_actor_label, p_organization_id,
        p_site_id, p_device_id, p_action, p_target_type, p_target_id, 'denied', p_source_ip, p_user_agent, p_details);
END
$$;
-- +goose StatementEnd
