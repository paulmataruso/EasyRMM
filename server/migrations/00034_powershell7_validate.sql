-- PowerShell 7 (ADR-0064, slice 1): validates the checks 00033 added NOT
-- VALID, reading the rows that were there before it. A migration runs in a
-- transaction of its own, so 00033's exclusive locks are gone by now; each
-- VALIDATE takes SHARE UPDATE EXCLUSIVE, which lets the server read and
-- write the table while its rows are read (decided in review).
--
-- It also fills devices.powershell7 from the inventories already stored:
-- an agent sends its inventory again only when it changes. No stored
-- inventory says an install is blocked, so powershell7_blocked stays empty
-- until the next one does.

-- +goose Up
ALTER TABLE scripts VALIDATE CONSTRAINT scripts_shell_check;
ALTER TABLE scripts VALIDATE CONSTRAINT scripts_pwsh_fallback;
ALTER TABLE jobs VALIDATE CONSTRAINT jobs_shell_check;
ALTER TABLE jobs VALIDATE CONSTRAINT jobs_pwsh_fallback;
ALTER TABLE jobs VALIDATE CONSTRAINT jobs_requires_check;
ALTER TABLE job_runs VALIDATE CONSTRAINT job_runs_program_edition_check;
ALTER TABLE job_runs VALIDATE CONSTRAINT job_runs_program_version_check;
ALTER TABLE job_runs VALIDATE CONSTRAINT job_runs_program_arch_check;
ALTER TABLE job_runs VALIDATE CONSTRAINT job_runs_program_path_check;
ALTER TABLE devices VALIDATE CONSTRAINT devices_agent_accepts_check;
ALTER TABLE devices VALIDATE CONSTRAINT devices_agent_accepts_build_check;
ALTER TABLE devices VALIDATE CONSTRAINT devices_powershell7_blocked_check;

-- Row level security binds the owner too: every device is filled.
SELECT set_config('easyrmm.scope_all', 'on', true);
UPDATE devices d
SET powershell7 = jsonb_path_exists(inv.data, '$.powerShell[*] ? (@.edition == "Core" && @.usable == true)')
FROM device_inventory inv
WHERE inv.device_id = d.id AND jsonb_typeof(inv.data -> 'powerShell') = 'array';

-- +goose Down
-- A validated check stays validated; 00033's down removes the checks and
-- the columns.
