-- The installer recorded, devices on the server's build, Uninstalled
-- (ADR-0056 slice 2, ADR-0053).

-- +goose Up

-- installer: the package kind that installed the agent, as its heartbeat
-- reports it; NULL for an agent the command installed, or one too old to say.
-- ran_server_build_at: when the device first ran the build the server served;
-- set once, never cleared (a server upgrade or a rollback to another build
-- must not make every device new again). A device with none is new, and under
-- the "when asked" rollout is updated at its first heartbeat.
-- agent_uninstalled_installer: how an agent that said it was uninstalled
-- (POST /api/agent/v1/uninstalled) had been installed.
-- (agent_uninstalled_at exists since migration 00077.)
ALTER TABLE devices
    ADD COLUMN installer text CHECK (installer IN ('deb', 'rpm', 'msi')),
    ADD COLUMN ran_server_build_at timestamptz,
    ADD COLUMN agent_uninstalled_installer text CHECK (agent_uninstalled_installer IN ('deb', 'rpm', 'msi'));

-- Devices enrolled before this migration are not new.
UPDATE devices SET ran_server_build_at = now() WHERE agent_public_key IS NOT NULL;

-- A device whose agent was removed has its policy alerts resolved: the notice
-- "agent removed without a request" says more than an offline alert would.
ALTER TABLE alerts
    DROP CONSTRAINT alerts_resolution_check,
    ADD CONSTRAINT alerts_resolution_check CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off',
        'policy_changed', 'policy_deleted', 'subject_gone', 'module_off', 'role_removed', 'not_applicable', 'suppressed',
        'uninstalled'));

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
UPDATE alerts SET resolution = 'cleared' WHERE resolution = 'uninstalled';
ALTER TABLE alerts
    DROP CONSTRAINT alerts_resolution_check,
    ADD CONSTRAINT alerts_resolution_check CHECK (resolution IN ('cleared', 'manual', 'not_covered', 'policy_off',
        'policy_changed', 'policy_deleted', 'subject_gone', 'module_off', 'role_removed', 'not_applicable', 'suppressed'));
ALTER TABLE devices
    DROP COLUMN IF EXISTS agent_uninstalled_installer,
    DROP COLUMN IF EXISTS ran_server_build_at,
    DROP COLUMN IF EXISTS installer;
