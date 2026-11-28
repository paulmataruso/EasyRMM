-- Posture policies (ADR-0082, slice P4): an organization's own weight for a
-- posture control, over the built-in default. Weight 0 leaves the control out
-- of the score. Only the overrides are stored; a control with no row weighs what
-- the server's default says. Written with the system scope, as the compliance
-- settings are; readable by the organization's callers.

-- +goose Up
CREATE TABLE posture_policies (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    control_id      text NOT NULL CHECK (control_id ~ '^[a-z][a-z0-9-]{0,62}$'),
    weight          integer NOT NULL CHECK (weight BETWEEN 0 AND 5),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (organization_id, control_id)
);

ALTER TABLE posture_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY posture_policies_read ON posture_policies FOR SELECT
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
CREATE POLICY posture_policies_write ON posture_policies FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON posture_policies TO easyrmm_app;

-- +goose Down
DROP TABLE posture_policies;
