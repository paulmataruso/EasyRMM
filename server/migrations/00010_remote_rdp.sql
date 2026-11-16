-- RDP sessions (ADR-0026): a remote session kind of its own, with its own
-- grant, so the gateway admits MeshCentral's web RDP relay only for it.

-- +goose Up
ALTER TABLE remote_grants DROP CONSTRAINT remote_grants_kind_check;
ALTER TABLE remote_grants ADD CONSTRAINT remote_grants_kind_check
    CHECK (kind IN ('desktop', 'terminal', 'files', 'rdp'));

-- +goose Down
DELETE FROM remote_grants WHERE kind = 'rdp';
ALTER TABLE remote_grants DROP CONSTRAINT remote_grants_kind_check;
ALTER TABLE remote_grants ADD CONSTRAINT remote_grants_kind_check
    CHECK (kind IN ('desktop', 'terminal', 'files'));
