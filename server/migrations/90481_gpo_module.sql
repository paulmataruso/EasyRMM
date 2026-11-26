-- Group Policy (ADR-0083, slice 1): the module is one more name wherever a Windows module is named.

-- +goose Up
ALTER TABLE windows_module_settings DROP CONSTRAINT windows_module_settings_module_check;
ALTER TABLE windows_module_settings ADD CONSTRAINT windows_module_settings_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'group_policy'));
ALTER TABLE windows_module_snapshots DROP CONSTRAINT windows_module_snapshots_module_check;
ALTER TABLE windows_module_snapshots ADD CONSTRAINT windows_module_snapshots_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'group_policy'));
ALTER TABLE alert_policies DROP CONSTRAINT alert_policies_module_check;
ALTER TABLE alert_policies ADD CONSTRAINT alert_policies_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup', 'group_policy'));

-- +goose Down
DELETE FROM windows_module_settings WHERE module = 'group_policy';
DELETE FROM windows_module_snapshots WHERE module = 'group_policy';
DELETE FROM alert_policies WHERE module = 'group_policy';
ALTER TABLE alert_policies DROP CONSTRAINT alert_policies_module_check;
ALTER TABLE alert_policies ADD CONSTRAINT alert_policies_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup'));
ALTER TABLE windows_module_snapshots DROP CONSTRAINT windows_module_snapshots_module_check;
ALTER TABLE windows_module_snapshots ADD CONSTRAINT windows_module_snapshots_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup'));
ALTER TABLE windows_module_settings DROP CONSTRAINT windows_module_settings_module_check;
ALTER TABLE windows_module_settings ADD CONSTRAINT windows_module_settings_module_check
    CHECK (module IN ('defender', 'active_directory', 'certificate_authority', 'dns', 'dhcp', 'file_shares', 'print', 'windows_backup'));
