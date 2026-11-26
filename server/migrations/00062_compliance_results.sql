-- The compliance engine's per-organization tables (ADR-0078, slice C1):
-- settings, enabled packs, scans, the jobs a scan made, and the append-only
-- result history with its latest-result view. Every table carries
-- organization_id and forced row-level security; the server writes with the
-- system scope, as it does for device_hardening.

-- +goose Up
CREATE TABLE compliance_org_settings (
    organization_id  uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    enabled          boolean NOT NULL DEFAULT false,
    freshness_days   integer NOT NULL DEFAULT 30 CHECK (freshness_days BETWEEN 1 AND 365),
    scan_schedule    text CHECK (scan_schedule IN ('weekly')),
    scan_profile     text,
    retention_years  integer NOT NULL DEFAULT 6 CHECK (retention_years BETWEEN 1 AND 50),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE compliance_org_packs (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    pack_id         uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    enabled_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    enabled_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, pack_id)
);

CREATE TABLE compliance_scans (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    started_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    trigger         text NOT NULL CHECK (trigger IN ('schedule', 'manual', 'verify')),
    selection       jsonb NOT NULL,
    state           text NOT NULL CHECK (state IN ('planned', 'running', 'done', 'partial', 'failed')),
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    result_hash     text,
    UNIQUE (id, organization_id)
);
CREATE INDEX compliance_scans_org ON compliance_scans (organization_id, started_at DESC);

CREATE TABLE compliance_scan_jobs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    scan_id         uuid NOT NULL,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    job_id          uuid REFERENCES jobs (id) ON DELETE SET NULL,
    modules         text[] NOT NULL DEFAULT '{}',
    attempt         integer NOT NULL DEFAULT 1,
    ingested        boolean NOT NULL DEFAULT false,
    UNIQUE (scan_id, device_id, modules),
    FOREIGN KEY (scan_id, organization_id) REFERENCES compliance_scans (id, organization_id) ON DELETE CASCADE
);

-- One row per scan, device and control; never changed.
CREATE TABLE compliance_results_history (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL,
    scan_id         uuid NOT NULL,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    control_id      text NOT NULL,
    control_version integer NOT NULL,
    state           text NOT NULL CHECK (state IN ('in_place', 'partly', 'not_in_place', 'not_applicable',
                        'managed_elsewhere', 'not_supported', 'half_applied', 'failed', 'unknown')),
    observed        jsonb,
    expected        jsonb,
    owner           jsonb,
    param_override  jsonb,
    job_id          uuid REFERENCES jobs (id) ON DELETE SET NULL,
    checked_at      timestamptz NOT NULL,
    UNIQUE (scan_id, device_id, control_id),
    FOREIGN KEY (scan_id, organization_id) REFERENCES compliance_scans (id, organization_id) ON DELETE CASCADE
);
CREATE INDEX compliance_results_latest ON compliance_results_history (device_id, control_id, checked_at DESC, id DESC);
CREATE INDEX compliance_results_org ON compliance_results_history (organization_id);

-- History is insert-only. A delete is allowed only when it follows from deleting a parent (a
-- cascade runs one trigger level deeper) or from the retention purge, which says so.
-- +goose StatementBegin
CREATE FUNCTION compliance_results_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND (pg_trigger_depth() > 1 OR current_setting('easyrmm.compliance_purge', true) = 'on') THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'compliance_results_history rows are never changed';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER compliance_results_no_update BEFORE UPDATE ON compliance_results_history
    FOR EACH ROW EXECUTE FUNCTION compliance_results_immutable();
CREATE TRIGGER compliance_results_no_delete BEFORE DELETE ON compliance_results_history
    FOR EACH ROW EXECUTE FUNCTION compliance_results_immutable();

-- The latest result per device and control, over the history (no second copy). 'stale' is
-- computed from checked_at when read.
CREATE VIEW compliance_results WITH (security_invoker = true) AS
    SELECT DISTINCT ON (device_id, control_id) *
      FROM compliance_results_history ORDER BY device_id, control_id, checked_at DESC, id DESC;

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['compliance_org_settings', 'compliance_org_packs', 'compliance_scans',
        'compliance_scan_jobs', 'compliance_results_history'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY %I ON %I FOR SELECT USING (easyrmm_scope_all()
            OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))$p$, t || '_read', t);
        EXECUTE format('CREATE POLICY %I ON %I FOR ALL USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all())', t || '_write', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO easyrmm_app', t);
    END LOOP;
END
$$;
-- +goose StatementEnd
GRANT SELECT ON compliance_results TO easyrmm_app;

-- +goose Down
DROP VIEW compliance_results;
DROP TABLE compliance_results_history;
DROP FUNCTION compliance_results_immutable();
DROP TABLE compliance_scan_jobs;
DROP TABLE compliance_scans;
DROP TABLE compliance_org_packs;
DROP TABLE compliance_org_settings;
