-- The compliance fix queue (ADR-0078, slice C2): one item per failed control on a computer, the agreement
-- each fix and undo is made under, and the organization's approval setting. Every table carries
-- organization_id and forced row-level security, as the scan tables do: the person's permission is
-- checked in the service, the writes are the server's.

-- +goose Up
CREATE TABLE compliance_fix_settings (
    organization_id  uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    -- The tiers whose fixes wait for a second person with compliance.fix_approve (default none).
    require_approval text[] NOT NULL DEFAULT '{}' CHECK (require_approval <@ ARRAY['T1', 'T2', 'T3']),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE compliance_fix_items (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id         uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    control_id        text NOT NULL,
    control_version   integer NOT NULL,
    tier              text NOT NULL CHECK (tier IN ('T1', 'T2', 'T3')),
    -- open: waits for an agreement; awaiting_approval: agreed, waits for a second person; applying: the
    -- job runs; applied: the job succeeded and the re-scan has not answered; verified: the re-scan says
    -- the control meets; not_verified: the re-scan could not say; failed: the change did not stand;
    -- undoing, undone; declined: accepted as a risk or deferred; resolved: the control meets without
    -- a fix from here.
    state             text NOT NULL CHECK (state IN ('open', 'awaiting_approval', 'applying', 'applied', 'verified',
                          'not_verified', 'failed', 'undoing', 'undone', 'declined', 'resolved')),
    observed          jsonb,
    expected          jsonb,
    requested_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    apply_job_id      uuid REFERENCES jobs (id) ON DELETE SET NULL,
    undo_job_id       uuid REFERENCES jobs (id) ON DELETE SET NULL,
    verify_scan_id    uuid,
    -- What the job reported for the setting: before and after values, the time, the reason it failed.
    outcome           jsonb,
    fail_reason       text NOT NULL DEFAULT '' CHECK (length(fail_reason) <= 2000),
    decline_kind      text CHECK (decline_kind IN ('accepted_risk', 'deferred')),
    decline_reason    text CHECK (length(decline_reason) <= 2000),
    decline_expires   timestamptz,
    declined_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (state <> 'declined' OR (decline_kind IS NOT NULL AND decline_reason IS NOT NULL)),
    CHECK (decline_kind IS NULL OR decline_kind <> 'deferred' OR decline_expires IS NOT NULL),
    UNIQUE (id, organization_id)
);
-- One open item per computer and control (the scan re-creates, never duplicates). An item whose re-scan
-- could not say stays until the control meets or it is undone, so a second one is not made beside it.
CREATE UNIQUE INDEX compliance_fix_items_open ON compliance_fix_items (device_id, control_id)
    WHERE state IN ('open', 'awaiting_approval', 'applying', 'applied', 'not_verified', 'undoing', 'declined');
CREATE INDEX compliance_fix_items_org ON compliance_fix_items (organization_id, state);
CREATE INDEX compliance_fix_items_device ON compliance_fix_items (device_id);
CREATE INDEX compliance_fix_items_jobs ON compliance_fix_items (apply_job_id, undo_job_id);

-- An agreement is recorded per item and per act, and is never changed.
CREATE TABLE compliance_fix_agreements (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    item_id         uuid NOT NULL,
    act             text NOT NULL CHECK (act IN ('apply', 'undo', 'approve')),
    user_id         uuid REFERENCES users (id) ON DELETE SET NULL,
    agreed_at       timestamptz NOT NULL DEFAULT now(),
    warning_id      text NOT NULL,
    warning_sha256  text NOT NULL,
    control_version integer NOT NULL,
    typed_text      text,
    step_up         boolean NOT NULL DEFAULT false,
    preconditions   jsonb NOT NULL DEFAULT '[]',
    FOREIGN KEY (item_id, organization_id) REFERENCES compliance_fix_items (id, organization_id) ON DELETE CASCADE
);
CREATE INDEX compliance_fix_agreements_item ON compliance_fix_agreements (item_id, agreed_at);

-- What an apply or undo of single settings reported for each setting (the job's output itself is not
-- readable by the server's role, ADR-0063), recorded when the run reports. The fix queue reads it.
CREATE TABLE hardening_setting_results (
    job_id          uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    organization_id uuid NOT NULL,
    setting_id      text NOT NULL,
    module          text NOT NULL,
    module_outcome  text NOT NULL,
    module_reason   text NOT NULL DEFAULT '' CHECK (length(module_reason) <= 600),
    outcome         text NOT NULL DEFAULT '',
    state           text NOT NULL DEFAULT '',
    before_value    text NOT NULL DEFAULT '' CHECK (length(before_value) <= 600),
    value           text NOT NULL DEFAULT '' CHECK (length(value) <= 600),
    note            text NOT NULL DEFAULT '' CHECK (length(note) <= 600),
    changed_at      text NOT NULL DEFAULT '' CHECK (length(changed_at) <= 64),
    PRIMARY KEY (job_id, device_id, setting_id)
);
CREATE INDEX hardening_setting_results_org ON hardening_setting_results (organization_id);

-- +goose StatementBegin
CREATE FUNCTION compliance_fix_agreements_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'compliance_fix_agreements rows are never changed';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER compliance_fix_agreements_no_update BEFORE UPDATE ON compliance_fix_agreements
    FOR EACH ROW EXECUTE FUNCTION compliance_fix_agreements_immutable();
CREATE TRIGGER compliance_fix_agreements_no_delete BEFORE DELETE ON compliance_fix_agreements
    FOR EACH ROW EXECUTE FUNCTION compliance_fix_agreements_immutable();

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['compliance_fix_settings', 'compliance_fix_items', 'compliance_fix_agreements', 'hardening_setting_results'] LOOP
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

-- +goose Down
DROP TABLE hardening_setting_results;
DROP TABLE compliance_fix_agreements;
DROP FUNCTION compliance_fix_agreements_immutable();
DROP TABLE compliance_fix_items;
DROP TABLE compliance_fix_settings;
