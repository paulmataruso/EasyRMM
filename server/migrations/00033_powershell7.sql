-- PowerShell 7 and the program each run used (ADR-0064, slice 1).
--
-- * Scripts and jobs gain the pwsh shell, and pwsh_fallback: whether a pwsh
--   script may run in Windows PowerShell 5.1 where no usable PowerShell 7
--   is found. A job keeps the script's setting.
-- * A job lists the capabilities an agent's poll must accept to be sent it
--   (requires): job.pwsh for pwsh. The claim reads the poll's own list.
-- * A run keeps the program the agent started, as the agent read it.
-- * A device keeps the last list its agent's poll reported, with the build
--   that reported it: another build's list counts as not reported.
-- * A device keeps what its last inventory says of PowerShell 7, for the
--   device list: powershell7 says whether it listed a usable install, NULL
--   when it listed no PowerShell; powershell7_blocked says why a run would
--   fail where none is usable but one is blocked (its module folders or
--   configuration fail the agent's check). Kept when the inventory is
--   stored, so the list reads no inventory (decided in review).
--
-- Every check is added NOT VALID: the tables are changed under an exclusive
-- lock, briefly, without their rows being read. New and changed rows are
-- checked at once; 00034 then reads the rows already there, in a
-- transaction of its own, under a lock that lets the server read and write
-- them meanwhile (decided in review).

-- +goose Up
ALTER TABLE scripts DROP CONSTRAINT scripts_shell_check,
    ADD CONSTRAINT scripts_shell_check CHECK (shell IN ('powershell', 'pwsh', 'cmd', 'sh', 'bash', 'python3')) NOT VALID,
    ADD COLUMN pwsh_fallback boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT scripts_pwsh_fallback CHECK (NOT pwsh_fallback OR shell = 'pwsh') NOT VALID;
-- The fallback is part of the reviewed script: changing it is an edit.
DROP TRIGGER scripts_touch ON scripts;
CREATE TRIGGER scripts_touch BEFORE UPDATE OF name, description, shell, pwsh_fallback, body, timeout_seconds ON scripts
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

ALTER TABLE jobs DROP CONSTRAINT jobs_shell_check,
    ADD CONSTRAINT jobs_shell_check CHECK (shell IN ('powershell', 'pwsh', 'cmd', 'sh', 'bash', 'python3')) NOT VALID,
    ADD COLUMN pwsh_fallback boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT jobs_pwsh_fallback CHECK (NOT pwsh_fallback OR shell = 'pwsh') NOT VALID,
    ADD COLUMN requires text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT jobs_requires_check CHECK (cardinality(requires) <= 32 AND array_position(requires, NULL) IS NULL) NOT VALID;

ALTER TABLE job_runs
    ADD COLUMN program_edition text,
    ADD COLUMN program_version text,
    ADD COLUMN program_arch text,
    ADD COLUMN program_path text,
    ADD COLUMN program_fallback boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT job_runs_program_edition_check CHECK (program_edition IN ('Desktop', 'Core')) NOT VALID,
    ADD CONSTRAINT job_runs_program_version_check CHECK (length(program_version) <= 64) NOT VALID,
    ADD CONSTRAINT job_runs_program_arch_check CHECK (program_arch IN ('x64', 'arm64', 'x86')) NOT VALID,
    ADD CONSTRAINT job_runs_program_path_check CHECK (length(program_path) <= 520) NOT VALID;

ALTER TABLE devices
    ADD COLUMN agent_accepts text[],
    ADD COLUMN agent_accepts_build text,
    ADD CONSTRAINT devices_agent_accepts_check
        CHECK (cardinality(agent_accepts) <= 32 AND array_position(agent_accepts, NULL) IS NULL) NOT VALID,
    ADD CONSTRAINT devices_agent_accepts_build_check CHECK (length(agent_accepts_build) <= 64) NOT VALID,
    ADD COLUMN powershell7 boolean,
    ADD COLUMN powershell7_blocked text,
    ADD CONSTRAINT devices_powershell7_blocked_check
        CHECK (powershell7_blocked IS NULL OR (length(powershell7_blocked) <= 500 AND powershell7 IS FALSE)) NOT VALID;

-- 00028 grants the server's role every column of these tables but the
-- output and the arguments, by name: the new ones too.
GRANT SELECT (pwsh_fallback, requires) ON jobs TO easyrmm_app;
GRANT SELECT (program_edition, program_version, program_arch, program_path, program_fallback) ON job_runs TO easyrmm_app;

-- +goose Down
ALTER TABLE devices DROP COLUMN powershell7_blocked, DROP COLUMN powershell7,
    DROP COLUMN agent_accepts_build, DROP COLUMN agent_accepts;
ALTER TABLE job_runs
    DROP COLUMN program_fallback,
    DROP COLUMN program_path,
    DROP COLUMN program_arch,
    DROP COLUMN program_version,
    DROP COLUMN program_edition;
-- PowerShell 7 jobs and scripts cannot be kept without their shell. Row
-- level security binds the owner too: these rows are everyone's.
SELECT set_config('easyrmm.scope_all', 'on', true);
DELETE FROM jobs WHERE shell = 'pwsh';
DELETE FROM scripts WHERE shell = 'pwsh';
ALTER TABLE jobs DROP COLUMN requires,
    DROP CONSTRAINT jobs_pwsh_fallback,
    DROP COLUMN pwsh_fallback,
    DROP CONSTRAINT jobs_shell_check,
    ADD CONSTRAINT jobs_shell_check CHECK (shell IN ('powershell', 'cmd', 'sh', 'bash', 'python3'));
DROP TRIGGER scripts_touch ON scripts;
ALTER TABLE scripts DROP CONSTRAINT scripts_pwsh_fallback,
    DROP COLUMN pwsh_fallback,
    DROP CONSTRAINT scripts_shell_check,
    ADD CONSTRAINT scripts_shell_check CHECK (shell IN ('powershell', 'cmd', 'sh', 'bash', 'python3'));
CREATE TRIGGER scripts_touch BEFORE UPDATE OF name, description, shell, body, timeout_seconds ON scripts
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();
