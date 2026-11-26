-- ADR-0071: a removed Windows device is never sent MeshCentral's
-- uninstallagent (it also deletes a client's own MeshAgent Diagnostic Agent,
-- a name MeshAgents share); our MeshAgent is removed by our own agent only.
-- platform says which devices those are; mesh_may_remain records that the
-- agent was not there to remove ours (forced removal, or it reported a
-- failure), so the console can offer the script that removes only our
-- service, folder and keys.

-- +goose Up
ALTER TABLE retired_devices
    ADD COLUMN platform text NOT NULL DEFAULT 'other' CHECK (platform IN ('windows', 'linux', 'macos', 'other')),
    ADD COLUMN mesh_may_remain boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE retired_devices DROP COLUMN mesh_may_remain, DROP COLUMN platform;
