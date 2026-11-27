-- Add ntp and laps to the module CHECK constraints (ADR-0086).

-- +goose Up

ALTER TABLE windows_module_settings DROP CONSTRAINT windows_module_settings_module_check;
ALTER TABLE windows_module_settings ADD CONSTRAINT windows_module_settings_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'bitlocker', 'group_policy', 'ntp', 'laps'));
ALTER TABLE windows_module_snapshots DROP CONSTRAINT windows_module_snapshots_module_check;
ALTER TABLE windows_module_snapshots ADD CONSTRAINT windows_module_snapshots_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'bitlocker', 'group_policy', 'ntp', 'laps'));
ALTER TABLE alert_policies DROP CONSTRAINT alert_policies_module_check;
ALTER TABLE alert_policies ADD CONSTRAINT alert_policies_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'bitlocker', 'group_policy', 'ntp', 'laps'));

-- +goose Down

DELETE FROM alert_policies WHERE module IN ('ntp', 'laps');
DELETE FROM windows_module_snapshots WHERE module IN ('ntp', 'laps');
DELETE FROM windows_module_settings WHERE module IN ('ntp', 'laps');
ALTER TABLE alert_policies DROP CONSTRAINT alert_policies_module_check;
ALTER TABLE alert_policies ADD CONSTRAINT alert_policies_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'bitlocker', 'group_policy'));
ALTER TABLE windows_module_snapshots DROP CONSTRAINT windows_module_snapshots_module_check;
ALTER TABLE windows_module_snapshots ADD CONSTRAINT windows_module_snapshots_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'bitlocker', 'group_policy'));
ALTER TABLE windows_module_settings DROP CONSTRAINT windows_module_settings_module_check;
ALTER TABLE windows_module_settings ADD CONSTRAINT windows_module_settings_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'bitlocker', 'group_policy'));
