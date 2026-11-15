-- EasyRMM core schema: tenancy, identity, sessions, settings, audit.
--
-- Two database roles are expected (see docs/architecture/database.md):
--   easyrmm_owner  owns every object and runs migrations.
--   easyrmm_app    is what the running server connects as. It has DML
--                  rights only, cannot alter tables, cannot disable row-level
--                  security, and cannot update or delete audit records.
--
-- Tenant isolation is enforced by row-level security (RLS) on every
-- tenant-scoped table. The server sets transaction-local settings that
-- describe what the current request may see; with nothing set, nothing is
-- visible.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Request scope helpers used by RLS policies
-- ---------------------------------------------------------------------------

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

-- +goose StatementBegin
CREATE FUNCTION easyrmm_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- Tenancy: organizations > sites > device groups
-- ---------------------------------------------------------------------------

CREATE TABLE organizations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    notes       text NOT NULL DEFAULT '' CHECK (length(notes) <= 10000),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX organizations_name_key ON organizations (lower(name));
CREATE TRIGGER organizations_touch BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

CREATE TABLE sites (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    timezone        text NOT NULL DEFAULT 'UTC' CHECK (length(timezone) BETWEEN 1 AND 64),
    address         text NOT NULL DEFAULT '' CHECK (length(address) <= 1000),
    notes           text NOT NULL DEFAULT '' CHECK (length(notes) <= 10000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- Lets child tables carry (organization_id, site_id) pairs whose
    -- consistency the database guarantees.
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX sites_org_name_key ON sites (organization_id, lower(name));
CREATE TRIGGER sites_touch BEFORE UPDATE ON sites
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

CREATE TABLE device_groups (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE,
    UNIQUE (site_id, id)
);
CREATE UNIQUE INDEX device_groups_site_name_key ON device_groups (site_id, lower(name));
CREATE INDEX device_groups_org_idx ON device_groups (organization_id);
CREATE TRIGGER device_groups_touch BEFORE UPDATE ON device_groups
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254 AND position('@' IN email) > 1),
    display_name          text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 200),
    password_hash         text,
    status                text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    totp_secret_sealed    text,
    totp_enabled_at       timestamptz,
    totp_last_step        bigint,
    failed_logins         integer NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    locked_until          timestamptz,
    password_changed_at   timestamptz,
    last_login_at         timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK (totp_enabled_at IS NULL OR totp_secret_sealed IS NOT NULL)
);
CREATE UNIQUE INDEX users_email_key ON users (email);
CREATE TRIGGER users_touch BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

CREATE TABLE user_recovery_codes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash   bytea NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_recovery_codes_user_idx ON user_recovery_codes (user_id) WHERE used_at IS NULL;

CREATE TABLE role_assignments (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role            text NOT NULL CHECK (role IN ('super_admin', 'org_admin', 'site_admin', 'technician', 'read_only')),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE,
    CHECK ((role = 'super_admin') = (organization_id IS NULL)),
    CHECK (site_id IS NULL OR role IN ('site_admin', 'technician', 'read_only')),
    CHECK (site_id IS NULL OR organization_id IS NOT NULL)
);
CREATE UNIQUE INDEX role_assignments_unique ON role_assignments (
    user_id, role,
    coalesce(organization_id, '00000000-0000-0000-0000-000000000000'),
    coalesce(site_id, '00000000-0000-0000-0000-000000000000')
);
CREATE INDEX role_assignments_org_idx ON role_assignments (organization_id);

CREATE TABLE sessions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash       bytea NOT NULL UNIQUE,
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    state            text NOT NULL CHECK (state IN ('mfa_required', 'mfa_enrollment', 'active')),
    mfa_failures     integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    idle_expires_at  timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz,
    revoked_reason   text,
    source_ip        inet,
    user_agent       text NOT NULL DEFAULT '' CHECK (length(user_agent) <= 512)
);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx ON sessions (expires_at);

CREATE TABLE password_reset_tokens (
    token_hash  bytea PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    source_ip   inet
);
CREATE INDEX password_reset_tokens_user_idx ON password_reset_tokens (user_id);

-- ---------------------------------------------------------------------------
-- Platform settings (key/value; platform-wide)
-- ---------------------------------------------------------------------------

CREATE TABLE settings (
    key         text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.]{1,99}$'),
    value       jsonb NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  uuid REFERENCES users (id) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------------
-- Audit log: append-only, hash-chained
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at      timestamptz NOT NULL,
    actor_type       text NOT NULL CHECK (actor_type IN ('user', 'agent', 'system')),
    actor_id         uuid,
    actor_label      text NOT NULL DEFAULT '',
    -- Deliberately no foreign keys: audit records must outlive the objects
    -- they describe.
    organization_id  uuid,
    site_id          uuid,
    device_id        uuid,
    action           text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$'),
    target_type      text NOT NULL DEFAULT '',
    target_id        text NOT NULL DEFAULT '',
    outcome          text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    source_ip        inet,
    user_agent       text NOT NULL DEFAULT '',
    details          jsonb NOT NULL DEFAULT '{}',
    prev_hash        bytea,
    entry_hash       bytea NOT NULL
);
CREATE INDEX audit_log_time_idx ON audit_log (occurred_at DESC);
CREATE INDEX audit_log_org_time_idx ON audit_log (organization_id, occurred_at DESC);
CREATE INDEX audit_log_actor_time_idx ON audit_log (actor_id, occurred_at DESC);
CREATE INDEX audit_log_device_time_idx ON audit_log (device_id, occurred_at DESC) WHERE device_id IS NOT NULL;

-- Records are never edited. Even the owner role gets an error.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log records are immutable';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION easyrmm_audit_immutable();

-- Canonical text of an entry, hashed into the chain. jsonb renders with a
-- deterministic key order, so the same record always hashes the same way.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_audit_canonical(
    occurred_at timestamptz, actor_type text, actor_id uuid, actor_label text,
    organization_id uuid, site_id uuid, device_id uuid, action text,
    target_type text, target_id text, outcome text, source_ip inet,
    user_agent text, details jsonb
) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT concat_ws(E'\x1f',
        to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        actor_type, coalesce(actor_id::text, ''), actor_label,
        coalesce(organization_id::text, ''), coalesce(site_id::text, ''), coalesce(device_id::text, ''),
        action, target_type, target_id, outcome,
        coalesce(host(source_ip), ''), user_agent, details::text)
$$;
-- +goose StatementEnd

-- The only way to write an audit record. It serialises writers, links each
-- record to the previous one by SHA-256, and runs as the owner so the
-- runtime role needs no INSERT privilege and cannot forge chain values.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_audit_append(
    p_occurred_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
    p_organization_id uuid, p_site_id uuid, p_device_id uuid, p_action text,
    p_target_type text, p_target_id text, p_outcome text, p_source_ip inet,
    p_user_agent text, p_details jsonb
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    prev bytea;
    entry bytea;
    new_id bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(4417355204181);
    SELECT entry_hash INTO prev FROM public.audit_log ORDER BY id DESC LIMIT 1;
    entry := sha256(coalesce(prev, ''::bytea) || convert_to(public.easyrmm_audit_canonical(
        p_occurred_at, p_actor_type, p_actor_id, p_actor_label, p_organization_id, p_site_id,
        p_device_id, p_action, p_target_type, p_target_id, p_outcome, p_source_ip,
        p_user_agent, p_details), 'UTF8'));
    INSERT INTO public.audit_log (occurred_at, actor_type, actor_id, actor_label, organization_id,
        site_id, device_id, action, target_type, target_id, outcome, source_ip, user_agent,
        details, prev_hash, entry_hash)
    VALUES (p_occurred_at, p_actor_type, p_actor_id, p_actor_label, p_organization_id,
        p_site_id, p_device_id, p_action, p_target_type, p_target_id, p_outcome, p_source_ip,
        p_user_agent, p_details, prev, entry)
    RETURNING id INTO new_id;
    RETURN new_id;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_audit_append(timestamptz, text, uuid, text, uuid, uuid, uuid, text, text, text, text, inet, text, jsonb) FROM PUBLIC;

-- Recomputes the chain from after_id onwards and returns the id of the
-- first record that does not match, or NULL when the checked range is
-- intact. The first record checked is trusted as the anchor when earlier
-- records were removed by retention.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_audit_verify(after_id bigint, max_rows integer) RETURNS TABLE (checked bigint, first_bad_id bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    r record;
    expected_prev bytea;
    have_prev boolean := false;
    n bigint := 0;
BEGIN
    IF after_id > 0 THEN
        SELECT entry_hash INTO expected_prev FROM public.audit_log WHERE id = after_id;
        have_prev := FOUND;
    END IF;
    FOR r IN SELECT * FROM public.audit_log WHERE id > after_id ORDER BY id LIMIT max_rows LOOP
        n := n + 1;
        IF have_prev AND r.prev_hash IS DISTINCT FROM expected_prev THEN
            checked := n; first_bad_id := r.id; RETURN NEXT; RETURN;
        END IF;
        IF r.entry_hash <> sha256(coalesce(r.prev_hash, ''::bytea) || convert_to(public.easyrmm_audit_canonical(
            r.occurred_at, r.actor_type, r.actor_id, r.actor_label, r.organization_id, r.site_id,
            r.device_id, r.action, r.target_type, r.target_id, r.outcome, r.source_ip,
            r.user_agent, r.details), 'UTF8')) THEN
            checked := n; first_bad_id := r.id; RETURN NEXT; RETURN;
        END IF;
        expected_prev := r.entry_hash;
        have_prev := true;
    END LOOP;
    checked := n; first_bad_id := NULL; RETURN NEXT;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_audit_verify(bigint, integer) FROM PUBLIC;

-- Retention is the only way records leave the log, and never sooner than 30
-- days. SECURITY DEFINER lets the app role call it without holding DELETE.
-- +goose StatementBegin
CREATE FUNCTION easyrmm_purge_audit(older_than interval) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    removed bigint;
BEGIN
    IF older_than < interval '30 days' THEN
        RAISE EXCEPTION 'audit retention must be at least 30 days';
    END IF;
    DELETE FROM public.audit_log WHERE occurred_at < now() - older_than;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_purge_audit(interval) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
-- Site-scoped users may read (only read) the organizations their sites belong to.
CREATE POLICY organizations_read ON organizations FOR SELECT USING (
    easyrmm_scope_all()
    OR id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR id = ANY (easyrmm_scope_ids('easyrmm.scope_read_orgs'))
);
CREATE POLICY organizations_insert ON organizations FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY organizations_update ON organizations FOR UPDATE
    USING (easyrmm_scope_all() OR id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
CREATE POLICY organizations_delete ON organizations FOR DELETE USING (easyrmm_scope_all());

ALTER TABLE sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE sites FORCE ROW LEVEL SECURITY;
CREATE POLICY sites_tenant ON sites
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );

ALTER TABLE device_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY device_groups_tenant ON device_groups
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );

-- Platform-wide audit entries (no organization) are visible only to
-- platform-wide scopes. The runtime role cannot write the table directly;
-- the SECURITY DEFINER functions above act as the owner, which FORCE RLS
-- also binds, so the owner gets its own unrestricted policy.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_log_read ON audit_log FOR SELECT TO easyrmm_app USING (
    easyrmm_scope_all()
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
);
CREATE POLICY audit_log_owner ON audit_log TO easyrmm_owner USING (true) WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- Privileges for the runtime role
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO easyrmm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    organizations, sites, device_groups, users, user_recovery_codes,
    role_assignments, sessions, password_reset_tokens, settings
    TO easyrmm_app;
GRANT SELECT ON audit_log TO easyrmm_app;
GRANT EXECUTE ON FUNCTION easyrmm_purge_audit(interval) TO easyrmm_app;
GRANT EXECUTE ON FUNCTION easyrmm_audit_append(timestamptz, text, uuid, text, uuid, uuid, uuid, text, text, text, text, inet, text, jsonb) TO easyrmm_app;
GRANT EXECUTE ON FUNCTION easyrmm_audit_verify(bigint, integer) TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS audit_log, settings, password_reset_tokens, sessions,
    role_assignments, user_recovery_codes, users, device_groups, sites, organizations CASCADE;
DROP FUNCTION IF EXISTS easyrmm_purge_audit(interval);
DROP FUNCTION IF EXISTS easyrmm_audit_verify(bigint, integer);
DROP FUNCTION IF EXISTS easyrmm_audit_append(timestamptz, text, uuid, text, uuid, uuid, uuid, text, text, text, text, inet, text, jsonb);
DROP FUNCTION IF EXISTS easyrmm_audit_canonical(timestamptz, text, uuid, text, uuid, uuid, uuid, text, text, text, text, inet, text, jsonb);
DROP FUNCTION IF EXISTS easyrmm_audit_immutable();
DROP FUNCTION IF EXISTS easyrmm_touch_updated_at();
DROP FUNCTION IF EXISTS easyrmm_scope_ids(text);
DROP FUNCTION IF EXISTS easyrmm_scope_all();
