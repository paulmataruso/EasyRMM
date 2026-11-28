-- ADR-0055, slice 5b4: DNS-01 challenge credentials for Let's Encrypt.
--
--   tls_dns_credentials  one row per zone whose DNS-01 challenge EasyRMM
--                        solves, with the provider (rfc2136 or cloudflare),
--                        the sealed credentials, the delegation target when
--                        the zone is not reachable from the Internet, and the
--                        RFC 2136 server address resolved and pinned.
--
-- A platform table: outside row-level security, reached only through the
-- DNS credential service, which requires settings.manage and step-up
-- authentication for writes.

-- +goose Up
CREATE TABLE tls_dns_credentials (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider        text NOT NULL CHECK (provider IN ('rfc2136', 'cloudflare')),
    zone            text NOT NULL CHECK (length(zone) BETWEEN 1 AND 253),
    -- For delegation: the public zone EasyRMM writes challenges to.
    -- Empty when the zone itself answers the Internet.
    override_domain text NOT NULL DEFAULT '',
    -- Sealed with EASYRMM_SECRET_KEY, bound to the row's id.
    credentials     bytea NOT NULL,
    -- The RFC 2136 server address, resolved once and pinned (ip:53 only).
    server_addr     text NOT NULL DEFAULT '',
    tested_at       timestamptz,
    test_ok         boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX tls_dns_credentials_zone ON tls_dns_credentials (zone);

GRANT SELECT, INSERT, UPDATE, DELETE ON tls_dns_credentials TO easyrmm_app;

-- +goose Down
DROP TABLE tls_dns_credentials;
