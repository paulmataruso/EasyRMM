-- Windows agent builds an operator signed with their own code signing
-- certificate and uploaded (ADR-0049). The server checked that each is its
-- own build with only an Authenticode signature added, and serves it in
-- place of the release's build of the same version. Kept here so that
-- backups keep them: for each architecture, the build of the server's
-- version and the newest older one.

-- +goose Up

CREATE TABLE signed_agent_builds (
    id             uuid PRIMARY KEY,
    arch           text NOT NULL CHECK (arch IN ('amd64', 'arm64')),
    -- The version of the release's build that was signed.
    version        text NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    -- The SHA-256 of the signed file, and of the release's build it was made
    -- from.
    sha256         text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    release_sha256 text NOT NULL CHECK (release_sha256 ~ '^[0-9a-f]{64}$'),
    content        bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 67108864),
    -- The signer's certificate, as the console shows it.
    signer_subject text NOT NULL CHECK (length(signer_subject) <= 1000),
    signer_issuer  text NOT NULL CHECK (length(signer_issuer) <= 1000),
    thumbprint     text NOT NULL CHECK (thumbprint ~ '^[0-9a-f]{40}$'),
    not_before     timestamptz NOT NULL,
    not_after      timestamptz NOT NULL,
    timestamped    boolean NOT NULL,
    uploaded_at    timestamptz NOT NULL DEFAULT now(),
    uploaded_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    UNIQUE (arch, version)
);

-- Only the server, at platform scope, reads and changes them; the service
-- lets Super Administrators (settings.manage) do so.
ALTER TABLE signed_agent_builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE signed_agent_builds FORCE ROW LEVEL SECURITY;
CREATE POLICY signed_agent_builds_platform ON signed_agent_builds
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON signed_agent_builds TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS signed_agent_builds;
