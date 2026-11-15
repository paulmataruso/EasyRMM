-- EasyRMM Initial Schema
-- All timestamps are UTC with timezone

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Organizations
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sites
CREATE TABLE sites (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(organization_id, slug)
);

CREATE INDEX idx_sites_org ON sites(organization_id);

-- Device Groups
CREATE TABLE device_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    mesh_group_id   TEXT,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_device_groups_site ON device_groups(site_id);

-- Devices
CREATE TABLE devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id),
    site_id             UUID NOT NULL REFERENCES sites(id),
    device_group_id     UUID REFERENCES device_groups(id) ON DELETE SET NULL,
    hostname            TEXT NOT NULL,
    display_name        TEXT,
    os_type             TEXT NOT NULL CHECK (os_type IN ('windows', 'linux')),
    os_name             TEXT,
    os_version          TEXT,
    os_build            TEXT,
    arch                TEXT,
    mesh_node_id        TEXT UNIQUE,
    mesh_group_id       TEXT,
    cpu_model           TEXT,
    cpu_cores           INTEGER,
    total_memory_mb     BIGINT,
    serial_number       TEXT,
    manufacturer        TEXT,
    model               TEXT,
    agent_id            TEXT NOT NULL UNIQUE,
    agent_version       TEXT,
    mesh_agent_version  TEXT,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'online', 'offline', 'alert')),
    last_seen_at        TIMESTAMPTZ,
    enrolled_at         TIMESTAMPTZ,
    tags                TEXT[] DEFAULT '{}',
    custom_properties   JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_org ON devices(organization_id);
CREATE INDEX idx_devices_site ON devices(site_id);
CREATE INDEX idx_devices_group ON devices(device_group_id);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_mesh_node ON devices(mesh_node_id);
CREATE INDEX idx_devices_agent ON devices(agent_id);
CREATE INDEX idx_devices_hostname ON devices(hostname);
CREATE INDEX idx_devices_tags ON devices USING GIN(tags);
CREATE INDEX idx_devices_last_seen ON devices(last_seen_at);

-- Users
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    display_name    TEXT,
    role            TEXT NOT NULL DEFAULT 'technician' CHECK (role IN ('super_admin', 'org_admin', 'site_admin', 'technician', 'read_only')),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    mfa_enabled     BOOLEAN NOT NULL DEFAULT false,
    mfa_secret      TEXT,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User-Organization Access
CREATE TABLE user_organization_access (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL DEFAULT 'technician' CHECK (role IN ('org_admin', 'site_admin', 'technician', 'read_only')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, organization_id)
);

CREATE INDEX idx_user_org_access_user ON user_organization_access(user_id);
CREATE INDEX idx_user_org_access_org ON user_organization_access(organization_id);

-- Sessions
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    ip_address      INET,
    user_agent      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- Enrollment Tokens
CREATE TABLE enrollment_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID REFERENCES sites(id) ON DELETE SET NULL,
    device_group_id UUID REFERENCES device_groups(id) ON DELETE SET NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    name            TEXT,
    max_uses        INTEGER,
    use_count       INTEGER NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,
    revoked         BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_enrollment_tokens_org ON enrollment_tokens(organization_id);

-- Scripts
CREATE TABLE scripts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    shell           TEXT NOT NULL CHECK (shell IN ('powershell', 'cmd', 'bash', 'python')),
    os_type         TEXT NOT NULL CHECK (os_type IN ('windows', 'linux', 'any')),
    content         TEXT NOT NULL,
    parameters      JSONB DEFAULT '[]',
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    category        TEXT,
    is_builtin      BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scripts_org ON scripts(organization_id);
CREATE INDEX idx_scripts_category ON scripts(category);

-- Jobs
CREATE TABLE jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name            TEXT NOT NULL,
    job_type        TEXT NOT NULL CHECK (job_type IN ('script', 'software_install', 'software_uninstall', 'command', 'patch')),
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'queued', 'dispatched', 'running', 'completed', 'failed', 'timed_out', 'cancelled')),
    target_type     TEXT NOT NULL CHECK (target_type IN ('device', 'device_group', 'site', 'organization')),
    target_id       UUID NOT NULL,
    script_id       UUID REFERENCES scripts(id),
    payload         JSONB NOT NULL DEFAULT '{}',
    scheduled_at    TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_jobs_org ON jobs(organization_id);
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_scheduled ON jobs(scheduled_at) WHERE scheduled_at IS NOT NULL;

-- Job Results (per device)
CREATE TABLE job_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    device_id       UUID NOT NULL REFERENCES devices(id),
    status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'dispatched', 'running', 'completed', 'failed', 'timed_out', 'cancelled')),
    exit_code       INTEGER,
    stdout          TEXT,
    stderr          TEXT,
    dispatched_at   TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_job_results_job ON job_results(job_id);
CREATE INDEX idx_job_results_device ON job_results(device_id);
CREATE INDEX idx_job_results_status ON job_results(status);

-- Alert Rules
CREATE TABLE alert_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    metric          TEXT NOT NULL,
    condition       JSONB NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('info', 'warning', 'critical')),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    notification_channels JSONB DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alert_rules_org ON alert_rules(organization_id);

-- Alerts
CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_rule_id   UUID REFERENCES alert_rules(id) ON DELETE SET NULL,
    device_id       UUID NOT NULL REFERENCES devices(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    severity        TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    message         TEXT NOT NULL,
    metric          TEXT NOT NULL,
    metric_value    DOUBLE PRECISION,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'acknowledged', 'resolved')),
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_device ON alerts(device_id);
CREATE INDEX idx_alerts_org ON alerts(organization_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity, status);

-- Device Telemetry
CREATE TABLE device_telemetry (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cpu_percent     DOUBLE PRECISION,
    memory_percent  DOUBLE PRECISION,
    disk_usage      JSONB,
    network         JSONB,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_telemetry_device_time ON device_telemetry(device_id, collected_at DESC);

-- Audit Logs
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    device_id       UUID REFERENCES devices(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT,
    details         JSONB DEFAULT '{}',
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_org ON audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_device ON audit_logs(device_id, created_at DESC);
CREATE INDEX idx_audit_action ON audit_logs(action, created_at DESC);

-- Notification Channels
CREATE TABLE notification_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    channel_type    TEXT NOT NULL CHECK (channel_type IN ('email', 'webhook', 'slack')),
    config          JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Server Settings
CREATE TABLE server_settings (
    key             TEXT PRIMARY KEY,
    value           JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Updated at trigger function
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at triggers
CREATE TRIGGER trg_organizations_updated BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_sites_updated BEFORE UPDATE ON sites FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_device_groups_updated BEFORE UPDATE ON device_groups FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_devices_updated BEFORE UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_scripts_updated BEFORE UPDATE ON scripts FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_alert_rules_updated BEFORE UPDATE ON alert_rules FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_notification_channels_updated BEFORE UPDATE ON notification_channels FOR EACH ROW EXECUTE FUNCTION update_updated_at();
