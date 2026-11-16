-- Windows devices (ADR-0020): PowerShell and cmd scripts, Windows'
-- installed programs as a package source, and a program's publisher.

-- +goose Up

ALTER TABLE scripts DROP CONSTRAINT scripts_shell_check,
    ADD CONSTRAINT scripts_shell_check CHECK (shell IN ('powershell', 'cmd', 'sh', 'bash', 'python3'));
ALTER TABLE jobs DROP CONSTRAINT jobs_shell_check,
    ADD CONSTRAINT jobs_shell_check CHECK (shell IN ('powershell', 'cmd', 'sh', 'bash', 'python3'));

ALTER TABLE device_inventory DROP CONSTRAINT device_inventory_package_manager_check,
    ADD CONSTRAINT device_inventory_package_manager_check CHECK (package_manager IN ('', 'windows', 'dpkg', 'rpm', 'apk', 'pacman'));

ALTER TABLE device_software
    ADD COLUMN publisher text NOT NULL DEFAULT '' CHECK (length(publisher) <= 200);

-- +goose Down
ALTER TABLE device_software DROP COLUMN IF EXISTS publisher;
-- Windows inventories, scripts and jobs cannot be kept under the old
-- constraints.
UPDATE device_inventory SET package_manager = '' WHERE package_manager = 'windows';
ALTER TABLE device_inventory DROP CONSTRAINT device_inventory_package_manager_check,
    ADD CONSTRAINT device_inventory_package_manager_check CHECK (package_manager IN ('', 'dpkg', 'rpm', 'apk', 'pacman'));
DELETE FROM jobs WHERE shell IN ('powershell', 'cmd');
DELETE FROM scripts WHERE shell IN ('powershell', 'cmd');
ALTER TABLE jobs DROP CONSTRAINT jobs_shell_check,
    ADD CONSTRAINT jobs_shell_check CHECK (shell IN ('sh', 'bash', 'python3'));
ALTER TABLE scripts DROP CONSTRAINT scripts_shell_check,
    ADD CONSTRAINT scripts_shell_check CHECK (shell IN ('sh', 'bash', 'python3'));
