-- Functions that run as their owner (SECURITY DEFINER) name pg_temp last in
-- their search_path. Unless it is named, a session's temporary schema is
-- searched first for tables and types, so a caller could put its own in
-- front of the ones these functions mean and have its code run as
-- easyrmm_owner. The functions added by 00028 are created this way; the
-- older ones are changed here. A test fails the build when a function that
-- runs as its owner does not name pg_temp last.
--
-- The server never creates temporary tables, so the runtime role and PUBLIC
-- also lose the right to, in this database, as a second layer. Only the
-- database's owner can take it away. Every documented install makes
-- easyrmm_owner, which runs migrations, the owner. Under any other owner,
-- or when the runtime role keeps the right through another grant, the
-- migration warns with the statement to run by hand and goes on: the
-- search_path above already blocks the attack, and a server that will not
-- start is worse.

-- +goose Up
ALTER FUNCTION easyrmm_audit_append(timestamptz, text, uuid, text, uuid, uuid, uuid, text, text, text, text, inet, text, jsonb)
    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION easyrmm_audit_verify(bigint, integer) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION easyrmm_purge_audit(interval) SET search_path = pg_catalog, public, pg_temp;

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT pg_has_role((SELECT datdba FROM pg_database WHERE datname = current_database()), 'USAGE') THEN
        RAISE WARNING 'database % is not owned by %, so TEMPORARY was not revoked from easyrmm_app and PUBLIC',
            current_database(), current_user
            USING HINT = format('As a superuser, run: REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC, easyrmm_app; '
                'ALTER DATABASE %I OWNER TO %I; (docs/architecture/database.md)', current_database(), current_database(), current_user);
        RETURN;
    END IF;
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC, easyrmm_app', current_database());
    -- A grant by another role, or one inherited through another role,
    -- survives the revoke.
    IF has_database_privilege('easyrmm_app', current_database(), 'TEMPORARY') THEN
        RAISE WARNING 'easyrmm_app can still create temporary tables in database %, through a grant by another role or a role it belongs to',
            current_database()
            USING HINT = format('As a superuser, list the grants with SELECT datacl FROM pg_database WHERE datname = %L; '
                'and the roles easyrmm_app belongs to with \du easyrmm_app in psql, then run '
                'REVOKE TEMPORARY ON DATABASE %I FROM <that role> CASCADE; for each role that grants or holds it.',
                current_database(), current_database());
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- The install scripts granted TEMPORARY to the runtime role before this.
-- +goose StatementBegin
DO $$
BEGIN
    EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO easyrmm_app', current_database());
END
$$;
-- +goose StatementEnd
ALTER FUNCTION easyrmm_purge_audit(interval) SET search_path = pg_catalog, public;
ALTER FUNCTION easyrmm_audit_verify(bigint, integer) SET search_path = pg_catalog, public;
ALTER FUNCTION easyrmm_audit_append(timestamptz, text, uuid, text, uuid, uuid, uuid, text, text, text, text, inet, text, jsonb)
    SET search_path = pg_catalog, public;
