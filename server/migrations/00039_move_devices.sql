-- +goose Up
-- Moving a device to another site (ADR-0069): the device's MeshCentral node
-- stays in the old site's device group until the device sync moves it, and
-- the EasyRMM agent rewrites MeshAgent's settings once it has been told.
-- mesh_from_site_id is the site whose group the node is still in while the
-- move is pending; mesh_settings_pending is set until the agent reports the
-- MeshAgent settings it applied.
ALTER TABLE devices
    ADD COLUMN mesh_from_site_id uuid,
    ADD COLUMN mesh_settings_pending boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE devices
    DROP COLUMN IF EXISTS mesh_settings_pending,
    DROP COLUMN IF EXISTS mesh_from_site_id;
