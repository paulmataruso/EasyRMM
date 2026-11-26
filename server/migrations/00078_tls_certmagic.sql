-- Certificates through CertMagic (ADR-0055, slice 5a). Three platform tables
-- like settings, outside row-level security and reached only through the
-- certificate service (which requires settings.manage):
--
--   tls_storage       CertMagic's key/value storage: account keys, certificate
--                     keys and certificates. Every value is sealed with
--                     EASYRMM_SECRET_KEY, with its key as associated data.
--   tls_certificates  what EasyRMM knows of each name: the next attempt
--                     allowed, the failures of the last hour, the last error,
--                     the certificate's serial, validity and ARI window, and
--                     for MeshCentral's name the certificate waiting to apply.
--   tls_mesh_reads    when MeshCentral last read certUrl, per server instance.

-- +goose Up
CREATE TABLE tls_storage (
    key      text PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 1024),
    value    text NOT NULL,
    modified timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tls_certificates (
    name              text PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 253),
    -- Where the name came from: 'env' for 5a; the console's own names come with 5b.
    source            text NOT NULL DEFAULT 'env' CHECK (source IN ('env')),
    serial            text,
    issuer            text,
    not_before        timestamptz,
    not_after         timestamptz,
    ari_start         timestamptz,
    ari_end           timestamptz,
    ari_selected      timestamptz,
    ari_explanation   text,
    -- The attempts: when the next may start, the failed ones of the last hour,
    -- when the name began to fail and why.
    next_attempt_at   timestamptz NOT NULL DEFAULT now(),
    failed_at         timestamptz[] NOT NULL DEFAULT '{}',
    failing_since     timestamptz,
    last_error        text CHECK (length(last_error) <= 1000),
    last_attempt_at   timestamptz,
    last_attempt_kind text,
    failures          integer NOT NULL DEFAULT 0,
    missing_since     timestamptz NOT NULL DEFAULT now(),
    ari_moved         boolean NOT NULL DEFAULT false,
    -- Set while the server cannot resolve the name; Order anyway skips it.
    waiting_dns_since timestamptz,
    order_anyway      boolean NOT NULL DEFAULT false,
    -- The certificate was read from autocert's directory at the upgrade.
    imported          boolean NOT NULL DEFAULT false,
    -- MeshCentral's name: the certificate served, and the one waiting.
    served_serial     text,
    pending_serial    text,
    pending_ready_at  timestamptz,
    -- The alert's state, so that a restart does not open it again.
    alert_level       text NOT NULL DEFAULT 'none' CHECK (alert_level IN ('none', 'warning', 'critical')),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tls_mesh_reads (
    instance     text PRIMARY KEY CHECK (length(instance) BETWEEN 1 AND 128),
    last_read_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON tls_storage, tls_certificates, tls_mesh_reads TO easyrmm_app;

-- +goose Down
DROP TABLE tls_mesh_reads;
DROP TABLE tls_certificates;
DROP TABLE tls_storage;
