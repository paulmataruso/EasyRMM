-- Forwarding the audit log to a syslog collector (ADR-0023): one row with
-- the destination, how far forwarding has got, and its latest outcome.

-- +goose Up

CREATE TABLE audit_forwarding (
    id                 boolean PRIMARY KEY DEFAULT true CHECK (id),
    enabled            boolean NOT NULL DEFAULT false,
    transport          text NOT NULL CHECK (transport IN ('udp', 'tcp', 'tls')),
    host               text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    port               integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    -- RFC 5424 facility: 4 auth, 10 authpriv, 13 log audit, 16-23 local0-7.
    facility           smallint NOT NULL DEFAULT 13 CHECK (facility IN (4, 10, 13, 16, 17, 18, 19, 20, 21, 22, 23)),
    ca_cert            text NOT NULL DEFAULT '' CHECK (length(ca_cert) <= 65536),
    client_cert        text NOT NULL DEFAULT '' CHECK (length(client_cert) <= 65536),
    client_key_sealed  text NOT NULL DEFAULT '',
    -- The last audit record handed to the collector. Records are appended
    -- under an advisory lock, so ids become visible in order.
    last_id            bigint NOT NULL DEFAULT 0 CHECK (last_id >= 0),
    -- Turned off, forwarding still delivers the records up to this one: the
    -- record of turning it off is the last the collector receives.
    drain_until        bigint NOT NULL DEFAULT 0 CHECK (drain_until >= 0),
    last_sent_at       timestamptz,
    last_error         text NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000),
    last_error_at      timestamptz,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         uuid REFERENCES users (id) ON DELETE SET NULL,
    CHECK ((client_cert = '') = (client_key_sealed = '')),
    CHECK (transport = 'tls' OR (ca_cert = '' AND client_cert = ''))
);

-- Platform-wide: only system-scope transactions see or change it.
ALTER TABLE audit_forwarding ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_forwarding FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_forwarding_system ON audit_forwarding TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY audit_forwarding_owner ON audit_forwarding TO easyrmm_owner USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON audit_forwarding TO easyrmm_app;

-- While forwarding is on (or delivering its last records after being turned
-- off), retention keeps records the collector has not received yet.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION easyrmm_purge_audit(older_than interval) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    removed bigint;
    keep_after bigint;
BEGIN
    IF older_than < interval '30 days' THEN
        RAISE EXCEPTION 'audit retention must be at least 30 days';
    END IF;
    SELECT last_id INTO keep_after FROM public.audit_forwarding WHERE enabled OR last_id < drain_until;
    DELETE FROM public.audit_log
    WHERE occurred_at < now() - older_than AND (keep_after IS NULL OR id <= keep_after);
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION easyrmm_purge_audit(older_than interval) RETURNS bigint
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
DROP TABLE IF EXISTS audit_forwarding;
