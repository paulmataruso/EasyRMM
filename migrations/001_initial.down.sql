-- Reverse migration: drop all tables
DROP TRIGGER IF EXISTS trg_notification_channels_updated ON notification_channels;
DROP TRIGGER IF EXISTS trg_alert_rules_updated ON alert_rules;
DROP TRIGGER IF EXISTS trg_scripts_updated ON scripts;
DROP TRIGGER IF EXISTS trg_users_updated ON users;
DROP TRIGGER IF EXISTS trg_devices_updated ON devices;
DROP TRIGGER IF EXISTS trg_device_groups_updated ON device_groups;
DROP TRIGGER IF EXISTS trg_sites_updated ON sites;
DROP TRIGGER IF EXISTS trg_organizations_updated ON organizations;
DROP FUNCTION IF EXISTS update_updated_at();

DROP TABLE IF EXISTS server_settings;
DROP TABLE IF EXISTS notification_channels;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS device_telemetry;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS alert_rules;
DROP TABLE IF EXISTS job_results;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS scripts;
DROP TABLE IF EXISTS enrollment_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS user_organization_access;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS device_groups;
DROP TABLE IF EXISTS sites;
DROP TABLE IF EXISTS organizations;
