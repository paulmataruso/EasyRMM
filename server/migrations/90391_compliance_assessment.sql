-- The compliance assessment workspace (ADR-0078, slice C5): assessments with their workflow and a
-- copy-on-write freeze, scope, implementations and objective results, attestations, evidence
-- (encrypted, never deleted), the plan of action and milestones, the system security plan's documents
-- and sections, score snapshots, and each organization's wrapped evidence data key. Every table
-- carries organization_id and forced row-level security, as the scan tables do: the person's
-- permission is checked in the service, the writes are the server's.

-- +goose Up
CREATE TABLE compliance_assessments (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    framework_key     text NOT NULL,
    framework_version text NOT NULL,
    profile_key       text,
    title             text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 200),
    assessor          text CHECK (length(assessor) <= 200),
    state             text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'in_review', 'approved', 'archived')),
    approved_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    approved_at       timestamptz,
    -- Copy-on-write: a new draft after an approval points at the record it was made from.
    supersedes        uuid REFERENCES compliance_assessments (id) ON DELETE SET NULL,
    -- The scan whose results were last applied.
    scan_id           uuid,
    created_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id),
    FOREIGN KEY (framework_key, framework_version) REFERENCES compliance_frameworks (key, version),
    CHECK ((state IN ('approved', 'archived')) = (approved_at IS NOT NULL))
);
CREATE INDEX compliance_assessments_org ON compliance_assessments (organization_id, created_at DESC);

CREATE TABLE compliance_scope_assets (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    assessment_id   uuid NOT NULL,
    device_id       uuid REFERENCES devices (id) ON DELETE CASCADE,
    group_id        uuid REFERENCES device_groups (id) ON DELETE CASCADE,
    category        text NOT NULL CHECK (category IN ('cui', 'security_protection', 'contractor_risk_managed', 'specialized', 'out_of_scope')),
    reason          text NOT NULL DEFAULT '' CHECK (length(reason) <= 2000),
    CHECK ((device_id IS NULL) <> (group_id IS NULL)),
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX compliance_scope_device ON compliance_scope_assets (assessment_id, device_id) WHERE device_id IS NOT NULL;
CREATE UNIQUE INDEX compliance_scope_group ON compliance_scope_assets (assessment_id, group_id) WHERE group_id IS NOT NULL;

CREATE TABLE compliance_implementations (
    organization_id uuid NOT NULL,
    assessment_id   uuid NOT NULL,
    req_id          text NOT NULL,
    status          text NOT NULL DEFAULT 'not_assessed' CHECK (status IN ('met', 'not_met', 'not_applicable', 'not_assessed')),
    -- Where the status came from: the scan, an attestation or a person's own call.
    origin          text NOT NULL DEFAULT 'scan' CHECK (origin IN ('scan', 'attested', 'manual')),
    -- The methodology's two partial-credit cases (3.5.3 and 3.13.11): not met, but part done.
    partial         boolean NOT NULL DEFAULT false,
    statement       text NOT NULL DEFAULT '' CHECK (length(statement) <= 20000),
    responsibility  text NOT NULL DEFAULT 'customer' CHECK (responsibility IN ('customer', 'msp', 'inherited', 'shared')),
    owner_user      uuid REFERENCES users (id) ON DELETE SET NULL,
    reviewed_at     timestamptz,
    next_review     date,
    PRIMARY KEY (assessment_id, req_id),
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE
);

CREATE TABLE compliance_attestations (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL,
    assessment_id    uuid NOT NULL,
    req_id           text NOT NULL,
    objectives       text[] NOT NULL DEFAULT '{}',
    statement        text NOT NULL CHECK (length(btrim(statement)) BETWEEN 1 AND 20000),
    statement_sha256 text NOT NULL,
    signer           uuid NOT NULL REFERENCES users (id),
    -- When the session's step-up was verified for this signature (the proof is the check, not a secret).
    stepup_proof     text NOT NULL,
    signed_at        timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    UNIQUE (id, organization_id),
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id)
);

CREATE TABLE compliance_objective_results (
    organization_id uuid NOT NULL,
    assessment_id   uuid NOT NULL,
    req_id          text NOT NULL,
    obj_id          text NOT NULL,
    determination   text NOT NULL CHECK (determination IN ('met', 'not_met', 'not_applicable', 'not_assessed')),
    method          text CHECK (method IN ('examine', 'interview', 'test')),
    source          text NOT NULL CHECK (source IN ('scan', 'attestation', 'upload', 'interview')),
    attestation_id  uuid,
    note            text NOT NULL DEFAULT '' CHECK (length(note) <= 4000),
    decided_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    decided_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (assessment_id, req_id, obj_id),
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE
);

-- A per-organization data key, wrapped by the server's sealer (secrets.Sealer); never stored in clear.
CREATE TABLE compliance_org_keys (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    key_id          text NOT NULL,
    wrapped         text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, key_id)
);

-- Evidence is never deleted, only superseded. The body is AES-256-GCM ciphertext under the
-- organization's data key; sha256 is of the plaintext and is checked on every download.
CREATE TABLE compliance_evidence (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('scan_snapshot', 'upload', 'link', 'attestation', 'screenshot')),
    title           text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 300),
    media_type      text CHECK (length(media_type) <= 200),
    file_name       text CHECK (length(file_name) <= 300),
    size_bytes      bigint CHECK (size_bytes BETWEEN 0 AND 67108864),
    body            bytea,
    nonce           bytea,
    key_id          text,
    url             text CHECK (length(url) <= 2000),
    sha256          text NOT NULL,
    collected_at    timestamptz NOT NULL DEFAULT now(),
    collector       uuid REFERENCES users (id) ON DELETE SET NULL,
    expires_at      timestamptz,
    superseded_by   uuid REFERENCES compliance_evidence (id),
    scan_id         uuid,
    UNIQUE (id, organization_id),
    CHECK ((kind = 'link') = (url IS NOT NULL)),
    CHECK (kind = 'link' OR (body IS NOT NULL AND nonce IS NOT NULL AND key_id IS NOT NULL AND size_bytes IS NOT NULL))
);
CREATE INDEX compliance_evidence_org ON compliance_evidence (organization_id, collected_at DESC);

CREATE TABLE compliance_poam_items (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id      uuid NOT NULL,
    assessment_id        uuid NOT NULL,
    req_id               text NOT NULL,
    weakness             text NOT NULL DEFAULT '' CHECK (length(weakness) <= 20000),
    point_value          integer NOT NULL CHECK (point_value >= 0),
    -- The failing computers and fix-queue items the draft was made from.
    basis                jsonb NOT NULL DEFAULT '{}',
    owner_user           uuid REFERENCES users (id) ON DELETE SET NULL,
    resources            text NOT NULL DEFAULT '' CHECK (length(resources) <= 4000),
    scheduled_completion date,
    status               text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'open', 'in_progress', 'closed', 'accepted')),
    eligible             boolean NOT NULL,
    eligibility_reason   text NOT NULL,
    opened_on            date NOT NULL DEFAULT current_date,
    closes_by            date NOT NULL,
    UNIQUE (id, organization_id),
    UNIQUE (assessment_id, req_id),
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE
);

CREATE TABLE compliance_poam_milestones (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    poam_id         uuid NOT NULL,
    title           text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 500),
    due             date,
    status          text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'done')),
    evidence_id     uuid REFERENCES compliance_evidence (id),
    FOREIGN KEY (poam_id, organization_id) REFERENCES compliance_poam_items (id, organization_id) ON DELETE CASCADE
);

CREATE TABLE compliance_evidence_links (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    evidence_id     uuid NOT NULL,
    assessment_id   uuid,
    req_id          text,
    obj_id          text,
    fix_item_id     uuid,
    poam_id         uuid,
    linked_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    linked_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (assessment_id IS NOT NULL OR fix_item_id IS NOT NULL OR poam_id IS NOT NULL),
    FOREIGN KEY (evidence_id, organization_id) REFERENCES compliance_evidence (id, organization_id) ON DELETE CASCADE,
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE,
    FOREIGN KEY (poam_id, organization_id) REFERENCES compliance_poam_items (id, organization_id) ON DELETE CASCADE,
    FOREIGN KEY (fix_item_id, organization_id) REFERENCES compliance_fix_items (id, organization_id) ON DELETE CASCADE
);
CREATE INDEX compliance_evidence_links_ev ON compliance_evidence_links (evidence_id);
CREATE INDEX compliance_evidence_links_req ON compliance_evidence_links (assessment_id, req_id);

CREATE TABLE compliance_documents (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    assessment_id   uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('ssp', 'policy', 'procedure', 'plan')),
    template_id     text NOT NULL,
    version         integer NOT NULL DEFAULT 1,
    approver        uuid REFERENCES users (id) ON DELETE SET NULL,
    approved_at     timestamptz,
    UNIQUE (id, organization_id),
    UNIQUE (assessment_id, kind, template_id),
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE
);

CREATE TABLE compliance_document_sections (
    organization_id uuid NOT NULL,
    document_id     uuid NOT NULL,
    position        integer NOT NULL,
    section_id      text NOT NULL,
    heading         text NOT NULL,
    body            text NOT NULL DEFAULT '' CHECK (length(body) <= 200000),
    generated       boolean NOT NULL,
    PRIMARY KEY (document_id, position),
    FOREIGN KEY (document_id, organization_id) REFERENCES compliance_documents (id, organization_id) ON DELETE CASCADE
);

CREATE TABLE compliance_score_snapshots (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    assessment_id   uuid NOT NULL,
    taken_at        timestamptz NOT NULL DEFAULT now(),
    sprs_low        integer NOT NULL,
    sprs_high       integer NOT NULL,
    l2_gate         jsonb NOT NULL,
    l1_count        integer,
    basis           jsonb NOT NULL,
    FOREIGN KEY (assessment_id, organization_id) REFERENCES compliance_assessments (id, organization_id) ON DELETE CASCADE
);

-- ---- the freeze ----------------------------------------------------------------------------------
-- An approved or archived assessment cannot change, nor can anything under it. A delete that follows
-- from deleting a parent (a cascade runs one trigger level deeper) or from the retention purge,
-- which says so, is allowed.
-- +goose StatementBegin
CREATE FUNCTION compliance_assessment_frozen(a uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT coalesce((SELECT state IN ('approved', 'archived') FROM compliance_assessments WHERE id = a), false)
$$;

CREATE FUNCTION compliance_assessment_children_frozen() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE a uuid;
BEGIN
    IF TG_OP = 'DELETE' AND (pg_trigger_depth() > 1 OR current_setting('easyrmm.compliance_purge', true) = 'on') THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN a := NEW.assessment_id; ELSE a := OLD.assessment_id; END IF;
    IF a IS NOT NULL AND compliance_assessment_frozen(a) THEN
        RAISE EXCEPTION 'the assessment is approved and cannot change; start a new draft' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.assessment_id IS DISTINCT FROM OLD.assessment_id THEN
        RAISE EXCEPTION 'a record cannot move to another assessment' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION compliance_milestones_frozen() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE p uuid; a uuid;
BEGIN
    IF TG_OP = 'DELETE' AND (pg_trigger_depth() > 1 OR current_setting('easyrmm.compliance_purge', true) = 'on') THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN p := NEW.poam_id; ELSE p := OLD.poam_id; END IF;
    SELECT assessment_id INTO a FROM compliance_poam_items WHERE id = p;
    IF a IS NOT NULL AND compliance_assessment_frozen(a) THEN
        RAISE EXCEPTION 'the assessment is approved and cannot change; start a new draft' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION compliance_sections_frozen() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE d uuid; a uuid;
BEGIN
    IF TG_OP = 'DELETE' AND (pg_trigger_depth() > 1 OR current_setting('easyrmm.compliance_purge', true) = 'on') THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN d := NEW.document_id; ELSE d := OLD.document_id; END IF;
    SELECT assessment_id INTO a FROM compliance_documents WHERE id = d;
    IF a IS NOT NULL AND compliance_assessment_frozen(a) THEN
        RAISE EXCEPTION 'the assessment is approved and cannot change; start a new draft' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

-- The assessment row itself: an approved one may only be archived, with nothing else changed, and is
-- never deleted by hand.
CREATE FUNCTION compliance_assessment_row_frozen() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state IN ('approved', 'archived') AND pg_trigger_depth() <= 1
                AND current_setting('easyrmm.compliance_purge', true) IS DISTINCT FROM 'on' THEN
            RAISE EXCEPTION 'an approved assessment is never deleted' USING ERRCODE = 'check_violation';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.state IN ('approved', 'archived') THEN
        IF OLD.state = 'approved' AND NEW.state = 'archived'
                AND (to_jsonb(NEW) - 'state' - 'updated_at') = (to_jsonb(OLD) - 'state' - 'updated_at') THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'the assessment is approved and cannot change; start a new draft' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

-- Evidence: a row changes only to say what superseded it, and is never deleted.
CREATE FUNCTION compliance_evidence_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF pg_trigger_depth() > 1 OR current_setting('easyrmm.compliance_purge', true) = 'on' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'evidence is never deleted, only superseded' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.superseded_by IS NULL AND NEW.superseded_by IS NOT NULL
            AND NEW.id = OLD.id AND NEW.organization_id = OLD.organization_id AND NEW.kind = OLD.kind
            AND NEW.title = OLD.title AND NEW.sha256 = OLD.sha256 AND NEW.size_bytes IS NOT DISTINCT FROM OLD.size_bytes
            AND NEW.nonce IS NOT DISTINCT FROM OLD.nonce AND NEW.key_id IS NOT DISTINCT FROM OLD.key_id
            AND NEW.url IS NOT DISTINCT FROM OLD.url AND NEW.expires_at IS NOT DISTINCT FROM OLD.expires_at
            AND NEW.collected_at = OLD.collected_at AND NEW.body IS NOT DISTINCT FROM OLD.body THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'evidence is never changed, only superseded' USING ERRCODE = 'check_violation';
END
$$;

-- An attestation is signed once and never changed.
CREATE FUNCTION compliance_attestations_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND (pg_trigger_depth() > 1 OR current_setting('easyrmm.compliance_purge', true) = 'on') THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' AND compliance_assessment_frozen(NEW.assessment_id) THEN
        RAISE EXCEPTION 'the assessment is approved and cannot change; start a new draft' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'INSERT' THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'an attestation is never changed' USING ERRCODE = 'check_violation';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER compliance_assessments_frozen BEFORE UPDATE OR DELETE ON compliance_assessments
    FOR EACH ROW EXECUTE FUNCTION compliance_assessment_row_frozen();
CREATE TRIGGER compliance_evidence_no_change BEFORE UPDATE OR DELETE ON compliance_evidence
    FOR EACH ROW EXECUTE FUNCTION compliance_evidence_immutable();
CREATE TRIGGER compliance_attestations_no_change BEFORE INSERT OR UPDATE OR DELETE ON compliance_attestations
    FOR EACH ROW EXECUTE FUNCTION compliance_attestations_immutable();
CREATE TRIGGER compliance_milestones_frozen BEFORE INSERT OR UPDATE OR DELETE ON compliance_poam_milestones
    FOR EACH ROW EXECUTE FUNCTION compliance_milestones_frozen();
CREATE TRIGGER compliance_sections_frozen BEFORE INSERT OR UPDATE OR DELETE ON compliance_document_sections
    FOR EACH ROW EXECUTE FUNCTION compliance_sections_frozen();

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['compliance_scope_assets', 'compliance_implementations', 'compliance_objective_results',
        'compliance_poam_items', 'compliance_evidence_links', 'compliance_documents', 'compliance_score_snapshots'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION compliance_assessment_children_frozen()',
            t || '_frozen', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- ---- row-level security ----------------------------------------------------------------------------
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['compliance_assessments', 'compliance_scope_assets', 'compliance_implementations',
        'compliance_attestations', 'compliance_objective_results', 'compliance_evidence', 'compliance_poam_items',
        'compliance_poam_milestones', 'compliance_evidence_links', 'compliance_documents',
        'compliance_document_sections', 'compliance_score_snapshots'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY %I ON %I FOR SELECT USING (easyrmm_scope_all()
            OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))$p$, t || '_read', t);
        EXECUTE format('CREATE POLICY %I ON %I FOR ALL USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all())', t || '_write', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO easyrmm_app', t);
    END LOOP;
    -- The wrapped keys are the server's alone: no read policy for a person's scope.
    ALTER TABLE compliance_org_keys ENABLE ROW LEVEL SECURITY;
    ALTER TABLE compliance_org_keys FORCE ROW LEVEL SECURITY;
    CREATE POLICY compliance_org_keys_system ON compliance_org_keys FOR ALL USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
    GRANT SELECT, INSERT, UPDATE ON compliance_org_keys TO easyrmm_app;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE compliance_score_snapshots;
DROP TABLE compliance_document_sections;
DROP TABLE compliance_documents;
DROP TABLE compliance_evidence_links;
DROP TABLE compliance_poam_milestones;
DROP TABLE compliance_poam_items;
DROP TABLE compliance_evidence;
DROP TABLE compliance_org_keys;
DROP TABLE compliance_objective_results;
DROP TABLE compliance_attestations;
DROP TABLE compliance_implementations;
DROP TABLE compliance_scope_assets;
DROP TABLE compliance_assessments;
DROP FUNCTION compliance_attestations_immutable();
DROP FUNCTION compliance_evidence_immutable();
DROP FUNCTION compliance_assessment_row_frozen();
DROP FUNCTION compliance_sections_frozen();
DROP FUNCTION compliance_milestones_frozen();
DROP FUNCTION compliance_assessment_children_frozen();
DROP FUNCTION compliance_assessment_frozen(uuid);
