-- Windows module snapshots (ADR-0073, slice 6): the typed result of a
-- module's read action, kept per device, action and parameters, replaced by
-- the next read. The alert evaluator and the module tabs read state from
-- here. A row follows its device (it has no organization or site of its
-- own); it is read through the device's visibility and written with the
-- system scope only.

-- +goose Up
CREATE TABLE windows_module_snapshots (
    device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    module      text NOT NULL CHECK (module IN ('defender', 'active_directory', 'certificate_authority',
                                                'dns', 'dhcp', 'file_shares', 'print', 'windows_backup')),
    action      text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
    -- SHA-256 of the canonical parameters, empty for an action without any.
    params_hash text NOT NULL DEFAULT '' CHECK (params_hash ~ '^([0-9a-f]{64})?$'),
    taken_at    timestamptz NOT NULL,
    -- A sensitive result is kept for minutes, not days (retention).
    sensitive   boolean NOT NULL DEFAULT false,
    data        jsonb NOT NULL CHECK (octet_length(data::text) <= 65536),
    PRIMARY KEY (device_id, action, params_hash)
);
CREATE INDEX windows_module_snapshots_taken_idx ON windows_module_snapshots (taken_at);
CREATE INDEX windows_module_snapshots_module_idx ON windows_module_snapshots (device_id, module);

ALTER TABLE windows_module_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_module_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY windows_module_snapshots_read ON windows_module_snapshots FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY windows_module_snapshots_write ON windows_module_snapshots FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON windows_module_snapshots TO easyrmm_app;

-- +goose Down
DROP TABLE windows_module_snapshots;
