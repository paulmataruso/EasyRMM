-- PowerShell 7 (ADR-0064, slice 1): validates the checks 00033 added NOT
-- VALID, reading the rows that were there before it. A migration runs in a
-- transaction of its own, so 00033's exclusive locks are gone by now; each
-- VALIDATE takes SHARE UPDATE EXCLUSIVE, which lets the server read and
-- write the table while its rows are read (decided in review).
--
-- It also fills devices.powershell7 and powershell7_blocked from the
-- inventories already stored, as the server writes them with each
-- inventory: an agent sends its inventory again only when it changes, and
-- 00033's down drops both columns while the inventories stay. On an
-- upgrade from a release before 00033 no stored inventory lists PowerShell,
-- and nothing is written. It reads each stored inventory once, in one
-- statement; it rewrites no table, and writes, and locks, only the devices
-- whose flags change.

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

-- Row level security binds the owner too: every device is filled. A device
-- with a usable PowerShell 7 has no reason; one without has the reason of
-- the first PowerShell 7 its inventory lists as blocked, if any.
SELECT set_config('easyrmm.scope_all', 'on', true);
UPDATE devices d
SET powershell7 = f.usable, powershell7_blocked = f.blocked
FROM (
    SELECT inv.device_id, u.usable,
           CASE WHEN NOT u.usable THEN (
               SELECT coalesce(e ->> 'reason', '')
                 FROM jsonb_array_elements(inv.data -> 'powerShell') WITH ORDINALITY AS x (e, n)
                WHERE e ->> 'edition' = 'Core' AND e -> 'blocked' = 'true'::jsonb
                ORDER BY n
                LIMIT 1)
           END AS blocked
      FROM device_inventory inv
     CROSS JOIN LATERAL (SELECT jsonb_path_exists(inv.data, '$.powerShell[*] ? (@.edition == "Core" && @.usable == true)') AS usable) u
     WHERE jsonb_typeof(inv.data -> 'powerShell') = 'array'
) f
WHERE f.device_id = d.id
  AND (d.powershell7 IS DISTINCT FROM f.usable OR d.powershell7_blocked IS DISTINCT FROM f.blocked);

-- +goose Down
-- A validated check stays validated; 00033's down removes the checks and
-- the columns.
