-- The compliance engine's global tables (ADR-0078, slice C1; data model
-- appendix): licence sources, packs, the control library, frameworks,
-- requirements, mappings and profiles. They are global, so every signed-in
-- scope reads them; only the system scope (the pack loader at server start)
-- writes them, so a user's request can never change a control or a pack.

-- +goose Up
CREATE TABLE compliance_sources (
    id            text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9.-]{1,63}$'),
    title         text NOT NULL,
    publisher     text NOT NULL,
    url           text NOT NULL,
    licence_class text NOT NULL CHECK (licence_class IN ('ORIGINAL', 'PUBLIC_DOMAIN', 'OPEN_LICENSE',
                      'ATTRIBUTION_REQUIRED', 'NONCOMMERCIAL', 'COMMERCIAL_LICENSE_REQUIRED', 'RESTRICTED')),
    licence_spdx  text,
    licence_note  text NOT NULL,
    attribution   text,
    retrieved_at  date NOT NULL,
    sha256        text,
    review_state  text NOT NULL DEFAULT 'none' CHECK (review_state IN ('none', 'needed', 'cleared')),
    review_ref    text,
    CHECK (review_state <> 'cleared' OR review_ref IS NOT NULL)
);

CREATE TABLE compliance_packs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key             text NOT NULL CHECK (key ~ '^[a-z][a-z0-9.-]{1,63}$'),
    version         text NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('library', 'framework', 'profile', 'xref', 'customer')),
    title           text NOT NULL,
    origin          text NOT NULL CHECK (origin IN ('builtin', 'customer')),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    licence_class   text NOT NULL CHECK (licence_class IN ('ORIGINAL', 'PUBLIC_DOMAIN', 'OPEN_LICENSE',
                        'ATTRIBUTION_REQUIRED', 'NONCOMMERCIAL', 'COMMERCIAL_LICENSE_REQUIRED', 'RESTRICTED')),
    source_id       text REFERENCES compliance_sources (id),
    review_state    text NOT NULL DEFAULT 'none' CHECK (review_state IN ('none', 'needed', 'cleared')),
    review_ref      text,
    manifest_sha256 text NOT NULL,
    signature       bytea,
    enabled         boolean NOT NULL DEFAULT true,
    installed_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    installed_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (key, version, organization_id),
    CHECK (origin = 'builtin' OR kind = 'customer'),
    CHECK (review_state <> 'cleared' OR review_ref IS NOT NULL)
);

-- A control never changes meaning under one version: body_sha256 is the hash of its definition,
-- and the loader refuses a changed definition that keeps its version.
CREATE TABLE compliance_controls (
    id               text NOT NULL CHECK (id ~ '^[a-z][a-z0-9.-]{2,95}$'),
    version          integer NOT NULL CHECK (version >= 1),
    pack_id          uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    title            text NOT NULL,
    description      text NOT NULL,
    platforms        jsonb NOT NULL,
    scopes           text[] NOT NULL,
    severity         text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    executor         text NOT NULL CHECK (executor IN ('hardening', 'winmod', 'facts', 'server', 'attestation')),
    executor_ref     jsonb NOT NULL,
    detect           jsonb NOT NULL,
    expected         jsonb NOT NULL,
    applicability    jsonb NOT NULL DEFAULT '{}',
    remediation_text text NOT NULL,
    apply_supported  boolean NOT NULL,
    apply_ref        jsonb,
    undo_ref         jsonb,
    undo_kind        text NOT NULL CHECK (undo_kind IN ('restore_backup', 'reverse_action', 'none')),
    risk_tier        text NOT NULL CHECK (risk_tier IN ('T0', 'T1', 'T2', 'T3')),
    warning_id       text,
    needs_restart    boolean NOT NULL DEFAULT false,
    preconditions    jsonb NOT NULL DEFAULT '[]',
    author           text NOT NULL,
    provenance       jsonb NOT NULL,
    licence_class    text NOT NULL CHECK (licence_class IN ('ORIGINAL', 'PUBLIC_DOMAIN', 'OPEN_LICENSE',
                         'ATTRIBUTION_REQUIRED', 'NONCOMMERCIAL', 'COMMERCIAL_LICENSE_REQUIRED', 'RESTRICTED')),
    review_state     text NOT NULL DEFAULT 'none' CHECK (review_state IN ('none', 'needed', 'cleared')),
    body_sha256      text NOT NULL,
    PRIMARY KEY (id, version),
    CHECK (risk_tier = 'T0' OR apply_supported OR remediation_text <> ''),
    CHECK (NOT apply_supported OR warning_id IS NOT NULL),
    CHECK (risk_tier <> 'T0' OR NOT apply_supported),
    CHECK (apply_supported = (apply_ref IS NOT NULL))
);
CREATE INDEX compliance_controls_pack ON compliance_controls (pack_id);

CREATE TABLE compliance_control_refs (
    control_id text NOT NULL,
    version    integer NOT NULL,
    kind       text NOT NULL CHECK (kind IN ('stig', 'ms_baseline', 'nist', 'vendor_doc', 'rfc', 'man_page', 'cve')),
    ref        text NOT NULL,
    url        text,
    meets      text CHECK (meets IN ('meets', 'differs', 'not_set')),
    FOREIGN KEY (control_id, version) REFERENCES compliance_controls (id, version) ON DELETE CASCADE
);

CREATE TABLE compliance_profiles (
    key           text NOT NULL,
    version       text NOT NULL,
    pack_id       uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    title         text NOT NULL,
    platform      jsonb NOT NULL,
    framework_key text,
    PRIMARY KEY (key, version)
);
CREATE TABLE compliance_profile_controls (
    profile_key     text NOT NULL,
    profile_version text NOT NULL,
    control_id      text NOT NULL,
    params          jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (profile_key, profile_version, control_id),
    FOREIGN KEY (profile_key, profile_version) REFERENCES compliance_profiles (key, version) ON DELETE CASCADE
);

CREATE TABLE compliance_frameworks (
    key           text NOT NULL,
    version       text NOT NULL,
    title         text NOT NULL,
    publisher     text NOT NULL,
    source_id     text NOT NULL REFERENCES compliance_sources (id),
    licence_class text NOT NULL,
    text_policy   text NOT NULL CHECK (text_policy IN ('full', 'ids_and_own_titles', 'ids_only')),
    pack_id       uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    PRIMARY KEY (key, version)
);

CREATE TABLE compliance_requirements (
    framework_key     text NOT NULL,
    framework_version text NOT NULL,
    req_id            text NOT NULL,
    parent_id         text,
    title_own         text NOT NULL,
    text_full         text,
    class             text NOT NULL CHECK (class IN ('technical', 'partly', 'organisational')),
    weight            integer,
    flags             jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (framework_key, framework_version, req_id),
    FOREIGN KEY (framework_key, framework_version) REFERENCES compliance_frameworks (key, version) ON DELETE CASCADE
);

-- Full text is for a framework whose text policy says so (the loader checks it, and so does this).
-- +goose StatementBegin
CREATE FUNCTION compliance_requirement_text_policy() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.text_full IS NOT NULL AND NOT EXISTS (SELECT 1 FROM compliance_frameworks f
            WHERE f.key = NEW.framework_key AND f.version = NEW.framework_version AND f.text_policy = 'full') THEN
        RAISE EXCEPTION 'requirement % has full text, but its framework does not carry full text', NEW.req_id;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER compliance_requirements_text_policy BEFORE INSERT OR UPDATE ON compliance_requirements
    FOR EACH ROW EXECUTE FUNCTION compliance_requirement_text_policy();

CREATE TABLE compliance_objectives (
    framework_key     text NOT NULL,
    framework_version text NOT NULL,
    req_id            text NOT NULL,
    obj_id            text NOT NULL,
    text              text,
    methods           text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (framework_key, framework_version, req_id, obj_id),
    FOREIGN KEY (framework_key, framework_version, req_id)
        REFERENCES compliance_requirements ON DELETE CASCADE
);

CREATE TABLE compliance_mappings (
    pack_id           uuid NOT NULL REFERENCES compliance_packs (id) ON DELETE CASCADE,
    framework_key     text NOT NULL,
    framework_version text NOT NULL,
    req_id            text NOT NULL,
    obj_id            text,
    control_id        text NOT NULL,
    relation          text NOT NULL CHECK (relation IN ('satisfies_objective', 'evidence_for', 'related')),
    note              text,
    licence_class     text NOT NULL CHECK (licence_class IN ('ORIGINAL', 'PUBLIC_DOMAIN', 'OPEN_LICENSE',
                          'ATTRIBUTION_REQUIRED', 'NONCOMMERCIAL', 'COMMERCIAL_LICENSE_REQUIRED', 'RESTRICTED')),
    provenance        jsonb NOT NULL,
    FOREIGN KEY (framework_key, framework_version, req_id)
        REFERENCES compliance_requirements ON DELETE CASCADE
);
CREATE UNIQUE INDEX compliance_mappings_unique ON compliance_mappings
    (pack_id, framework_key, framework_version, req_id, coalesce(obj_id, ''), control_id);
CREATE INDEX compliance_mappings_control ON compliance_mappings (control_id);

-- Every global table: readable by every scope, written by the system scope only.
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['compliance_sources', 'compliance_packs', 'compliance_controls', 'compliance_control_refs',
        'compliance_profiles', 'compliance_profile_controls', 'compliance_frameworks', 'compliance_requirements',
        'compliance_objectives', 'compliance_mappings'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON %I FOR SELECT USING (true)', t || '_read', t);
        EXECUTE format('CREATE POLICY %I ON %I FOR ALL USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all())', t || '_write', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO easyrmm_app', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE compliance_mappings;
DROP TABLE compliance_objectives;
DROP TRIGGER compliance_requirements_text_policy ON compliance_requirements;
DROP TABLE compliance_requirements;
DROP FUNCTION compliance_requirement_text_policy();
DROP TABLE compliance_frameworks;
DROP TABLE compliance_profile_controls;
DROP TABLE compliance_profiles;
DROP TABLE compliance_control_refs;
DROP TABLE compliance_controls;
DROP TABLE compliance_packs;
DROP TABLE compliance_sources;
