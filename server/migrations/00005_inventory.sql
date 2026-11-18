-- Inventory and telemetry (ADR-0018).

-- +goose Up

-- The latest inventory a device's agent uploaded, without its packages.
-- hash is the SHA-256 of the upload as sent; the agent compares it with its
-- own to decide whether to upload again.
CREATE TABLE device_inventory (
    device_id        uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    hash             text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    data             jsonb NOT NULL,
    package_manager  text NOT NULL DEFAULT '' CHECK (package_manager IN ('', 'dpkg', 'rpm', 'apk', 'pacman')),
    package_count    integer NOT NULL DEFAULT 0 CHECK (package_count BETWEEN 0 AND 20000),
    received_at      timestamptz NOT NULL DEFAULT now()
);

-- Installed packages, replaced as a whole with each upload. A name can
-- appear more than once (RPM keeps several kernels).
CREATE TABLE device_software (
    device_id  uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    version    text NOT NULL DEFAULT '' CHECK (length(version) <= 200),
    arch       text NOT NULL DEFAULT '' CHECK (length(arch) <= 40)
);
CREATE INDEX device_software_device_idx ON device_software (device_id);
CREATE INDEX device_software_name_idx ON device_software (lower(name) text_pattern_ops);

-- The latest measurements per device.
CREATE TABLE device_metrics (
    device_id       uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    at              timestamptz NOT NULL,
    cpu_percent     real NOT NULL CHECK (cpu_percent BETWEEN 0 AND 100),
    memory_total    bigint NOT NULL CHECK (memory_total >= 0),
    memory_used     bigint NOT NULL CHECK (memory_used >= 0),
    swap_total      bigint NOT NULL CHECK (swap_total >= 0),
    swap_used       bigint NOT NULL CHECK (swap_used >= 0),
    load1           real NOT NULL CHECK (load1 >= 0),
    load5           real NOT NULL CHECK (load5 >= 0),
    load15          real NOT NULL CHECK (load15 >= 0),
    uptime_seconds  bigint NOT NULL CHECK (uptime_seconds >= 0),
    processes       integer NOT NULL CHECK (processes >= 0),
    filesystems     jsonb NOT NULL DEFAULT '[]'
);

-- One sample per heartbeat, for charts and alerts; removed after
-- EASYRMM_METRICS_RETENTION. disk_percent is the fullest filesystem's use.
CREATE TABLE device_metric_samples (
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    at              timestamptz NOT NULL,
    cpu_percent     real NOT NULL CHECK (cpu_percent BETWEEN 0 AND 100),
    memory_percent  real NOT NULL CHECK (memory_percent BETWEEN 0 AND 100),
    swap_percent    real NOT NULL CHECK (swap_percent BETWEEN 0 AND 100),
    disk_percent    real NOT NULL CHECK (disk_percent BETWEEN 0 AND 100),
    load1           real NOT NULL CHECK (load1 >= 0),
    PRIMARY KEY (device_id, at)
);
CREATE INDEX device_metric_samples_at_idx ON device_metric_samples USING brin (at);

-- Rows are visible through their device (whose own policy decides) and
-- written only by the agent API and maintenance, which run with the system
-- scope.
ALTER TABLE device_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_inventory FORCE ROW LEVEL SECURITY;
CREATE POLICY device_inventory_read ON device_inventory FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_inventory_insert ON device_inventory FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY device_inventory_update ON device_inventory FOR UPDATE USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY device_inventory_delete ON device_inventory FOR DELETE USING (easyrmm_scope_all());

ALTER TABLE device_software ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_software FORCE ROW LEVEL SECURITY;
CREATE POLICY device_software_read ON device_software FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_software_insert ON device_software FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY device_software_delete ON device_software FOR DELETE USING (easyrmm_scope_all());

ALTER TABLE device_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_metrics FORCE ROW LEVEL SECURITY;
CREATE POLICY device_metrics_read ON device_metrics FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_metrics_insert ON device_metrics FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY device_metrics_update ON device_metrics FOR UPDATE USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE device_metric_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_metric_samples FORCE ROW LEVEL SECURITY;
CREATE POLICY device_metric_samples_read ON device_metric_samples FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_metric_samples_insert ON device_metric_samples FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY device_metric_samples_delete ON device_metric_samples FOR DELETE USING (easyrmm_scope_all());

GRANT SELECT, INSERT, UPDATE, DELETE ON device_inventory, device_metrics TO easyrmm_app;
GRANT SELECT, INSERT, DELETE ON device_software, device_metric_samples TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS device_metric_samples, device_metrics, device_software, device_inventory;
