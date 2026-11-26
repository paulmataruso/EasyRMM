-- Per organization Quick Assist state (ADR-0080): the MeshCentral group made
-- for its sessions.

-- +goose Up
CREATE TABLE quick_assist_orgs (
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    mesh_id         text
);
ALTER TABLE quick_assist_orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE quick_assist_orgs FORCE ROW LEVEL SECURITY;
CREATE POLICY quick_assist_orgs_tenant ON quick_assist_orgs
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
GRANT SELECT, INSERT, UPDATE, DELETE ON quick_assist_orgs TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS quick_assist_orgs;
