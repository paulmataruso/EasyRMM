# ADR-0067: Remote Windows registry editor

* Status: Proposed (2026-11-21). Not implemented.
* Nothing here was decided by the owner. Everything marked as decided was
  decided in review, and the owner can overturn it; the
  [owner questions](#owner-questions) list what is the owner's.
* Amends: [ADR-0017](0017-scripts-and-jobs.md): two job kinds,
  `registry_query` and `registry_change`; fixed-script kinds that take a
  signed input and return a structured result (F2); settings per kind; a
  reserved lane on the agent; the size of a poll's answer and of a
  result. It gains an *Amended by ADR-0067* line when this is
  implemented. Notes made at the same time: ADR-0063's guarded columns
  gain the input and the result, and its purge gains a time per kind;
  [ADR-0054](0054-hardening-windows-computers-and-servers.md#the-job)'s
  "one change at a time on a device" gains registry changes.
* Builds on: [ADR-0007](0007-hash-chained-audit-log.md) (the audit log),
  [ADR-0009](0009-agent-protocol.md#evolving-the-protocol-amended-2026-11-21)
  (evolving the protocol), [ADR-0017](0017-scripts-and-jobs.md),
  [ADR-0020](0020-windows-agent.md) (the Windows agent),
  [ADR-0023](0023-audit-forwarding.md) (forwarding),
  [ADR-0047](0047-tokens-shown-again.md) (a read and its record in one
  transaction), the accepted
  [ADR-0064](0064-remote-powershell-management.md) (the poll's `accepts`,
  targets, the hash rule, Windows tests as LocalSystem), and these
  proposed ADRs: [ADR-0054](0054-hardening-windows-computers-and-servers.md)
  (W1's ownership reader, W2's job amendments, Constrained Language Mode,
  `AllSigned`, the script's hash published),
  [ADR-0055](0055-lets-encrypt-in-one-step.md#step-up-authentication)
  (step-up) and [ADR-0060](0060-collecting-logs.md) (arguments on the
  command line). ADR-0063 (who sees a job's output and arguments, PR #81)
  and ADR-0065 (hardware health, PR #83) are accepted on branches of their
  own and not merged, so they are cited without links. This ADR builds on
  ADR-0063's permission, guarded columns, functions, endpoints and output
  retention, and uses ADR-0065's words for states.
* Requirements: feature 7, "Remote Windows Registry Editor", of the
  [owner's requirements of 2026-11-21](../requirements/2026-11-21-msp-features.md#7-remote-windows-registry-editor).
  Every bullet is placed in [The requirements](#the-requirements). The
  [plan](../feature-plan-msp.md#7-remote-windows-registry-editor) lists
  it as feature 7, and it builds
  [F2](../feature-plan-msp.md#f2-fixed-script-job-kinds-whose-results-are-hidden-by-kind).
  This ADR differs from the plan in six places, each argued where it is
  decided:
  * **the agent changes**: a job capability, `job.structured` (a signed
    input in a file, a result in a file, a reserved lane), where the
    plan's F2 says the agent does not change;
  * **no SHA-256 of data in audit records**, where the plan records the
    old and new data's size and SHA-256 (ADR-0064's hash rule);
  * **search moves to the read-only slice**, beside export; import stays
    with writes;
  * **the script compiles a small C# helper with `Add-Type`**, which
    ADR-0054 rules out for its own script;
  * **bulk changes across devices** are a slice of their own (the
    requirements' overall expectation 4);
  * **HKCU is offered for each loaded user hive**, not each signed-in
    user.

## Context
Each claim below was checked in the code at `main` `1c21f6e` for this
ADR.

**What exists.**

* **No registry feature.** MeshCentral has a registry view, and EasyRMM
  switches it off for every user (`RightNoRegistry` in
  `rightsRestrictedSet`, `server/internal/meshcentral/rights.go:16-19`,
  applied at `:56`). A technician reaches the registry today through a
  SYSTEM terminal, remote desktop or a library script; only the session
  or the run is recorded.
* **EasyRMM's own kinds of job.** Besides library scripts (`script`)
  there are `software` and `hardening`
  (`server/internal/jobs/software.go:35-38`, `hardening.go:31`; the
  constraint `jobs_kind_check` in
  `server/migrations/00027_hardening.sql:16`). Their scripts are compiled
  into the server (`hardening.go:51`, `software.go:44-54`), at most
  512 KiB (`MaxJobBody`, `hardening.go:40-42`), and take arguments the
  server checks against fixed lists. Hardening answers with one line,
  `EASYRMM-HARDENING-RESULT-V1`, of at most 64 KiB (`hardening.go:46-49`),
  decoded strictly and checked against the job (`parseHardeningResult`,
  `:322-372`); a malformed one fails the run (`recordHardening`,
  `:408-443`).
* **Every job keeps its script and the script's SHA-256**, and each run
  is recorded once with that SHA-256 (`create`,
  `server/internal/jobs/jobs.go:254-299`; the record at `:278-290`).
* **Arguments are on the command line**: at most 32 of 1 KiB each
  (`jobs.go:144-152`), passed after `-File`
  (`agent/jobs/exec_windows.go:99`). ADR-0060's Context: process auditing
  records them, and other local processes can read them while the job
  runs. No place for a registry value someone types.
* **The payload** (`internal/agentproto/jobs.go:102-113`) is signed with
  Ed25519 over `EASYRMM-JOB-SIG-V1\n` and its JSON (`:135`, `:146-153`)
  and decoded with unknown fields refused (`:157-169`), so a new field
  must reach only agents that said they take it (ADR-0064's `accepts`).
* **The poll** asks with an empty request (`PollRequest`, `:81`); its
  answer holds at most 8 jobs (`MaxPollJobs`, `:19-20`), and the agent
  reads at most 8 MiB of it, sized for "Eight jobs with 64 KiB scripts"
  (`agent/client/client.go:290-293`). The claim takes queued runs oldest
  first (`server/internal/jobs/delivery.go:49-64`); a delivered run asks
  the server before it starts (`Start`, `:126`).
* **The result** carries the first and last 128 KiB of each output stream
  (`agentproto/jobs.go:24-30`); the server reads at most 4 MiB of it
  (`MaxResultBody`, `:21-23`; `server/internal/httpapi/agentapi/agentapi.go:208`).
  On Windows, output that is not UTF-8 is read in the OEM code page
  (`exec_windows.go:158-174`).
* **A run** gets a private folder, `run-*`, under the agent's `work`
  folder, removed when it ends (`agent/jobs/exec.go:41-45`,
  `agent/jobs/worker.go:95`). Its environment is the service's without
  `EASYRMM_` variables, with `TEMP` in that folder and the job's IDs
  (`exec_windows.go:51-65`). Windows PowerShell 5.1 runs it
  (`exec_windows.go:33-49`, `:99`). Four runs go at once
  (`worker.go:40-41`, `:73-74`), so a query can wait behind a hardening
  run of up to 30 minutes (`HardeningTimeout`, `hardening.go:37-38`) or an
  install. The journal keeps each run's result until it is reported
  (`agent/jobs/journal.go:25-36`).
* **The agent already reads the registry** in Go: both views of the
  uninstall keys, and the loaded user hives under `HKEY_USERS` whose SIDs
  start with `S-1-5-21-`, skipping `_Classes`
  (`agent/inventory/windows.go:273-291`).
* **The agents' own keys.**
  * MeshAgent keeps its node ID and options in
    `HKLM\SOFTWARE\Open Source\<service name>`
    (`agent/meshagent/registry_windows.go:7-10`). EasyRMM's MeshAgent
    service is `EasyRMMMeshAgent` (`agent/meshagent/meshagent.go:33`);
    MeshCentral's default name is "Mesh Agent" (`:261`).
  * The EasyRMM agent's service is `EasyRMMAgent`
    (`agent/host/service.go:51`). ADR-0056 plans a value `Enrolled` under
    `HKLM\SOFTWARE\EasyRMM\Agent` for its Group Policy deployment
    (`docs/architecture/adr/0056-packages-for-the-agent.md:765-766`).
  * The EasyPatch agent's installer writes `ServerUrl`, `ProxyUrl`,
    `ServerCaCertificate` and `EnrollmentToken` under
    `HKLM\SOFTWARE\EasyPatch\Agent`
    (`easypatch/agent/Installer/Package.wxs:143-166`), which the agent
    reads at start and from which it deletes the token once used
    (`easypatch/agent/EasyPatch.Agent/Platform/RegistryBootstrapConfigSource.cs:14-41`).
    Its service is `EasyPatchAgent` (`Package.wxs:108-110`).
* **Roles** (`server/internal/rbac/rbac.go:122-181`): Technicians hold
  `device.terminal`, `device.files` and `script.run` (`:142-145`);
  Read-Only holds view permissions only and "Views devices, alerts and
  reports without making changes" (`:176-180`); `audit.view` starts at
  Site Administrator (`:147-150`). Roles are a fixed catalogue.
* **The audit log** keeps at most 16 KiB of details per record
  (`server/internal/audit/audit.go:72`, `:126`).
* **The console**: a device's tabs
  (`web/src/pages/devices/DeviceDetailPage.tsx:61-70`), where Hardening
  shows for Linux only (`:66-67`); the Jobs page filters by kind
  (`web/src/pages/jobs/JobsPage.tsx:29`, `:48`, `:149`).

**On branches, not merged.**

* **ADR-0063** (PR #81, accepted and built on its branch):
  `job.view_sensitive`, held by Technicians and above and not Read-Only;
  `stdout`, `stderr` and `args` revoked from `easyrmm_app` column by
  column, read only through `SECURITY DEFINER` functions whose
  `search_path` ends with `pg_temp`, each read audited in its own
  transaction; `GET /api/v1/job-runs/{id}/output`,
  `GET /api/v1/jobs/{id}/arguments` and
  `DELETE /api/v1/job-runs/{id}/output`; refusals recorded at most 20
  times per caller in 10 minutes; output kept for
  `EASYRMM_JOB_OUTPUT_RETENTION`, 30 days by default. It names this
  feature: "Later kinds that read sensitive data on purpose, such as the
  planned registry and event log viewers, may need a stricter permission
  for their output … The output endpoint would then ask for both"; and
  retention per kind "is built with the first kind that needs it, not
  before".
* **ADR-0065** (PR #83, accepted): F1's rule of five states (healthy,
  unhealthy, unknown, unsupported, unavailable) and *reported* for what
  EasyRMM reads and does not judge. *Unavailable* is "the data exists, but
  EasyRMM cannot reach it from where the agent runs".

**What Windows offers**, from Microsoft's documentation (see
[References](#references)):

* **Names.** "Key names are not case sensitive. Key names cannot include
  the backslash character (\\), but any other printable character can be
  used. Value names and data can include the backslash character."
  (Structure of the registry.)
* **Limits.** A key name: 255 characters; a value name: 16,383
  characters; a value: "Available memory (latest format) 1 MB (standard
  format)"; a tree 512 levels deep, 32 created in one call; values over
  2,048 bytes should be kept as files (Registry element size limits).
  The page also says a key name "includes the absolute path"; whether the
  255 characters bound each name or the whole path is to be confirmed on
  the runners.
* **Types.** `REG_LINK` is "A null-terminated Unicode string that
  contains the target path of a symbolic link that was created by calling
  the RegCreateKeyEx function with REG_OPTION_CREATE_LINK". A
  `REG_MULTI_SZ` cannot hold a zero-length string. String data "might not
  have been stored with the proper terminating null characters"
  (Registry value types).
* **Links.** `RegOpenKeyExW` takes `REG_OPTION_OPEN_LINK`: "The key is a
  symbolic link. Registry symbolic links should only be used when
  absolutely necessary." Without it, Windows follows a link.
* **The kernel's name of a key.** `ZwQueryKey`, called `NtQueryKey` from
  user mode ("If the call to this function occurs in user mode, you
  should use the name NtQueryKey"), returns a `KEY_NAME_INFORMATION` for
  `KeyNameInformation`. That this is the full kernel path
  (`\REGISTRY\MACHINE\…`), and the control set's real name for a key
  reached through `CurrentControlSet`, is to be confirmed: Microsoft's
  page for the structure was not reachable for this ADR.
* **Views.** `KEY_WOW64_64KEY` (0x0100) and `KEY_WOW64_32KEY` (0x0200)
  apply to `RegCreateKeyEx`, `RegDeleteKeyEx` and `RegOpenKeyEx`;
  `RegDeleteKey` cannot take them; everything done under a key opened
  with a flag must use the same flag; on ARM64, `KEY_WOW64_32KEY` is the
  x86 view; "Wow6432Node and WowAA32Node keys are reserved" (Accessing an
  alternate registry view; Registry redirector).
* **HKCR and HKCC.** HKCR merges `HKLM\Software\Classes` with the user's
  classes; "Processes running in a security context other than that of
  the interactive user should not use the HKEY_CLASSES_ROOT key", and
  should open `HKEY_LOCAL_MACHINE\Software\Classes` explicitly
  (HKEY_CLASSES_ROOT key). HKCC "is an alias for
  HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current",
  and services should not use HKCU or HKCR (Predefined keys).
* **Loading a hive.** `RegLoadKey` loads under `HKEY_USERS` or
  `HKEY_LOCAL_MACHINE` only, and "The calling process must have the
  SE_RESTORE_NAME and SE_BACKUP_NAME privileges" (RegLoadKeyW).
* **Where secrets are.** "Local security information is stored in the
  registry under HKEY_LOCAL_MACHINE\SECURITY. Stored information includes
  policy settings, default security values, and account information, such
  as cached logon credentials. A copy of the SAM database is also stored
  here". LSA secrets on disk "might include" the computer's domain
  account password, services' and scheduled tasks' passwords, IIS
  application pools' passwords and Microsoft accounts' passwords.
  Credential Manager's credentials "are saved in special encrypted folders
  on the computer under the user's profile", not the registry
  (Credentials processes in Windows authentication).
* **Automatic logon.** Set by editing the registry, "the password is
  stored in the registry in plain text. The specific registry key that
  stores this value can be remotely read by the Authenticated Users
  group" (`Winlogon`, `DefaultPassword`); Sysinternals' Autologon keeps it
  in an LSA secret instead (Configure Windows to automate logon).
* **PowerShell's provider and .NET.** The Registry provider's drives are
  `HKLM:` and `HKCU:` only, and it takes "a backslash (\\) or a forward
  slash (/)" between levels; unsupported types come back as `Unknown`,
  "such as REG_RESOURCE_LIST values" (about_Registry_Provider;
  RegistryValueKind).
* **`reg.exe`.** `reg export` accepts the roots HKLM, HKCU, HKCR, HKU and
  HKCC; `reg import` takes `/reg:32` and `/reg:64` (reg export; reg
  import).
* **The `.reg` format** (a header of `Windows Registry Editor Version 5.00`
  or `REGEDIT4`; `dword:`, `hex:`, `hex(2):` for `REG_EXPAND_SZ`,
  `hex(7):` for `REG_MULTI_SZ`; `[-key]` and `"name"=-` to delete) is
  described in Microsoft's support article 310516, which could not be
  read for this ADR. Its details are to be confirmed, and are settled by
  the runners' tests against `reg.exe` ([Testing](#testing)).

## Decision

### In short
*Decided in review.*

* **A Registry tab** on Windows devices, built on **F2**: EasyRMM's own
  PowerShell script, signed in each job like any script, given a typed,
  signed input in a file and answering with JSON in a file, both kept off
  the command line and out of the output streams.
* **Read-only first** (slice 1): browsing, value reads, bounded search,
  and export as `.reg` or JSON. **Writes** (slice 2): create, change and
  delete keys and values, each with a backup taken in the same run, a
  check that nothing changed since it was read, undo, and protected paths
  behind step-up and the device's name typed. **Import** (slice 3) and
  **bulk changes** (slice 4) after.
* **Refusals enforced three times**: the server checks the request; the
  script checks it again, and checks the kernel's name of every key it
  opens, never letting Windows follow a link; the server checks the
  result. `SAM`, `SECURITY` and the agents' own keys are refused for
  reading and writing; `REG_LINK` is never written.
* **Two permissions**, `registry.view` and `registry.edit`, held by
  Technicians and above; Read-Only gets neither. Reading a result needs
  `job.view_sensitive` as well.
* **Audit**: one record per query and per change; no value data and no
  hash of it in the log; the data before and after kept with the change,
  read with a record.

### F2: fixed-script kinds with an input and a result
*Decided in review.* F2 as the plan defines it, made concrete. Features
9, 12 and 8's actions reuse it.

#### A kind
A kind is a Go value in `server/internal/jobs`, one per kind, in one table
the server reads. It names:

* its script, compiled in with `go:embed`, and its shell;
* the platforms it runs on;
* the agent capability it needs: `job.structured` for every F2 kind;
* its input: a Go struct per operation, decoded with unknown fields
  refused, and its checks;
* its result: a Go struct per result version, and the check of a result
  against its input;
* who reads the input and the result: a permission of the kind's own,
  beside `job.view_sensitive`, and whether only the person who asked may
  read the result;
* how long the result is kept, and how long jobs and runs are kept;
* how long a run waits for an offline device, by default and at most;
* its timeout, and whether it runs in the reserved lane;
* whether the Jobs list shows it without a filter;
* its audit record, written by `create` instead of one
  `device.script_run` per run;
* whether it takes the device's change lock (one change at a time).

The three existing kinds are entries of the same table with the values
they have today: no input, no result, output for
`EASYRMM_JOB_OUTPUT_RETENTION`, listed, one record per run. Every entry is
used: the registry's two kinds set each of them.

**Two registry kinds**: `registry_query` (list, value, search, export,
prepare) and `registry_change` (change, undo, import, bulk). Two and not
one, because retention, readers, the change lock and the record differ
between reads and writes, and one kind whose settings depend on the
operation would hide that in code.

#### Shipped, signed and versioned
* **The script** is `server/internal/jobs/registry/registry.ps1`, compiled
  into the server. It is the job's body: written to the job's row with its
  SHA-256 (as `jobs.go:264-271` does today) and signed in the payload
  with the job key. The agent runs it as it runs any PowerShell job.
* **Versions.** `$ScriptVersion` in the script, `v` in the input and in
  the result. The server writes inputs of its own version and parses
  results of its version and the one before, since a run delivered before
  an upgrade reports after it. A result of any other version fails the run
  with the reason.
* **Its SHA-256 is published** in each release's notes and in the guide,
  so that MSPs can allow it in their EDR, as ADR-0054 publishes its
  script's.
* **Not Authenticode-signed**: code signing is on hold (ADR-0054, Before
  anything changes). Where Group Policy sets `AllSigned` it does not
  start, like every PowerShell job; the server shows ADR-0054's message,
  *Group Policy allows only signed scripts*.
* **One set of rules.** The refused, protected and masked paths and names
  are one file, `server/internal/jobs/registry/rules.json`, embedded in the
  server and written into the script's rules section by `go generate`; a
  test fails when the script's copy differs.

#### The input
* **A JSON object**: `v`, `op`, and the operation's fields: hive, view,
  path, value name, limits, cursor, data to write, the state expected
  before a write.
* **Checked by the server** when the job is created: decoded strictly,
  each field against its rules ([Paths, links and
  refusals](#paths-links-and-refusals), [Types, encoding and
  limits](#types-encoding-and-limits)) and the refusals; **and again by
  the script** on the computer, against the same rules from its copy.
* **Kept** in a new column, `jobs.input` (`jsonb`), at most 1 MiB,
  written once with the job.
* **Delivered off the command line.** The payload gains `input`, signed
  with the rest. The agent writes it to `input.json` in the run's private
  folder and sets `EASYRMM_JOB_INPUT` to its path. Process auditing and
  other processes see the script's path and no data. Script block logging
  records script text, not data a script reads from a file (to be
  confirmed on the runners with script block logging on).

#### The result
* **The script writes one JSON document** to the path in
  `EASYRMM_JOB_RESULT` (`result.json` in the run's folder), UTF-8, at most
  2 MiB. It prints nothing when it succeeds, so PowerShell transcription,
  where Group Policy turns it on, records no data.
* **The agent** reads the file after the process ends, before the folder
  is removed; checks it is at most 2 MiB and valid JSON; and sends it as
  `result` (raw JSON) in the result request. A missing or malformed file
  fails the run: "the script's result is missing or malformed". The
  journal keeps it with the rest of the result.
* **The server** decodes it strictly into the kind's result for its
  version and checks it against the input: the operation, hive, view, path
  and cursor; counts within the input's limits; every path in it outside
  the refusals. It stores it in a new column, `job_runs.result` (`jsonb`).
  A result that does not match fails the run with the reason and is not
  stored; one that holds a refused path is also recorded as
  `registry.refused_on_device` ([Links](#links)).
* **Not standard output.** Output is cut to its head and tail and read in
  the OEM code page when it is not UTF-8 (Context), and is shown under
  ADR-0063's output rules for every kind. A result needs rules of its own.

#### The agent: `job.structured`
Gated as ADR-0064 gates `job.pwsh`
([Older agents and the poll](0064-remote-powershell-management.md#older-agents-and-the-poll)):

* **The agent lists `job.structured`** in its poll's `accepts`, which
  ADR-0064's slice 1 builds. It means the agent takes the payload's
  `input` and `lane`, sets the two variables, reads the result file, sends
  `result`, and keeps the reserved lane.
* **The claim delivers an F2 run** only in answer to a poll whose
  `accepts` lists `job.structured`; otherwise the run stays queued, then
  expires with the reason. Creating a registry job for a device whose list
  lacks it is refused: "PC-12's agent cannot read the registry; update the
  agent".
* **The reserved lane.** The payload's `lane: "quick"` marks a run of at
  most 60 seconds, which `VerifyJob` checks. The agent keeps 2 slots for
  quick runs beside its 4 (`worker.go:40`), so a registry read never waits
  behind an install or a hardening run; the claim takes quick runs first.
  Every registry job is quick. *Decided now*, as the plan left it to this
  ADR: without it the editor can wait half an hour on a busy computer.
* **Sizes.** A payload now carries up to 512 KiB of script and 1 MiB of
  input, base64-encoded in the answer. The claim stops adding runs when
  the answer would pass 6 MiB, and always delivers at least one, under
  the agent's 8 MiB. The server's `MaxResultBody` grows from 4 MiB to
  8 MiB, room for both streams as today and a 2 MiB result.
* **An older agent** never gets these fields; its strict decoder would
  refuse them (`agentproto/jobs.go:164`).

#### Who reads, how long, what is recorded
* **The database guards both columns**, by ADR-0063's rule that a column
  added to `jobs` or `job_runs` needs its own grant: `easyrmm_app` is not
  granted `SELECT` on `jobs.input` or `job_runs.result`. Their sizes and
  times (`input_bytes`, `result_bytes`, `result_stored_at`,
  `result_removed_at`) are granted, kept by triggers as ADR-0063 keeps
  `stdout_bytes`.
* **Reads go through `SECURITY DEFINER` functions** owned by
  `easyrmm_owner` with `search_path = pg_catalog, public, pg_temp`, as
  ADR-0063's are. A new `easyrmm_job_run_result` checks the caller's
  `job.view_sensitive` scope, the kind's permission scope and, for kinds
  read by the asker only, that the caller asked; writes the kind's record
  where it records reads; and returns the result, in the request's
  transaction. ADR-0063's `easyrmm_job_arguments` returns `input` beside
  `args`, needing the kind's permission too. The poll reads `input`
  through ADR-0063's `easyrmm_job_delivery_args`.
* **Endpoints**, answering as ADR-0063's output endpoint does (`404` for a
  run the caller cannot see, with no record; `403` recorded as denied
  within ADR-0063's bound; `409 run_open`; `409 result_removed`; `200`):
  * `GET /api/v1/job-runs/{id}/result`;
  * `DELETE /api/v1/job-runs/{id}/result`, for a finished run, by a caller
    with `job.manage`, `job.view_sensitive` and the kind's write
    permission (`registry.edit`), recorded; a change's undo goes with its
    data;
  * the input, through ADR-0063's `GET /api/v1/jobs/{id}/arguments`.
* **Retention per kind.** ADR-0063's purge gains the kind in its
  condition and a time per kind; W2's job retention per kind gains these
  two kinds. Per kind:

| | `registry_query` | `registry_change` |
|---|---|---|
| Result kept | 1 hour (the hourly purge empties it within 2) | `EASYRMM_JOB_OUTPUT_RETENTION` (30 days by default) |
| Job and runs kept | 7 days | `EASYRMM_JOB_RETENTION` (90 days by default) |
| Result read by | the person who asked, holding `registry.view` and `job.view_sensitive` at the device's site | anyone holding `registry.view` and `job.view_sensitive` at the device's site |
| Each read recorded | no: only the asker reads it, and the query's own record covers it | yes, `registry.change_view` |
| Waits for an offline device | 2 minutes | 15 minutes for one device; bulk 1 hour by default, at most 7 days |
| Timeout and lane | 60 seconds, quick | 60 seconds, quick |
| In the Jobs list | under its filter only | under its filter only |
| Change lock | no | yes |

* **The Jobs list.** The kind filter gains *Registry*; without it,
  registry jobs are left out, since each click is a job. Under `job.view`
  a registry job shows *Registry read* or *Registry change*, the device,
  who and when, and its status; no path, data or result. The device's
  Registry tab is where they are read.
* **W2's amendments.** ADR-0054's W2 adds batch IDs, job retention per
  kind, one record per organization per batch, and runs the server
  cancels. F2 extends those per kind and adds no second set (plan, F2).
  If F2 is built before W2, F2 builds job retention per kind and server
  cancels, and W2 extends them.

### The script
*Decided in review.*

* **Windows PowerShell 5.1**, with a small C# helper compiled by
  `Add-Type` for the calls .NET lacks: `RegOpenKeyExW` with
  `REG_OPTION_OPEN_LINK`; `NtQueryKey` for the kernel's name of an open
  key; `RegEnumValueW` and `RegQueryValueExW` for the raw type and bytes;
  `RegQueryInfoKeyW` for counts and the last-write time; and the write
  calls (`RegCreateKeyExW`, `RegSetValueExW`, `RegDeleteValueW`,
  `RegDeleteKeyExW`, `RegGetKeySecurity`, `RegSetKeySecurity`).
* **Why not .NET alone.** `RegistryKey.OpenSubKey` follows links and does
  not say where it landed, and reports `REG_LINK` and the resource-list
  types as `Unknown`. A link planted in a user's hive would be followed
  into whatever it names, unseen.
* **Unlike ADR-0054's script**, which rules out `Add-Type` because "it
  compiles C# at run time and is refused in Constrained Language Mode":
  * Under Constrained Language Mode, which refuses `Add-Type`, the script
    could not check links, so it does not run there: it checks the
    language mode first and answers *unavailable: Constrained Language
    Mode*, as ADR-0054's stops with *not supported*. A script without
    `Add-Type` could run there only by following links unseen, and it
    does not try to get around the computer's own control.
  * Compiling costs time, and starts `csc.exe` from PowerShell running as
    SYSTEM, which an EDR may flag. Slice 1 measures both. If the median
    from click to view passes 3 seconds on a real computer, or the EDRs
    MSPs use flag the compile, native queries in the agent (slice 5) move
    up and this ADR is amended.
* **64-bit only.** The script stops if `[Environment]::Is64BitProcess` is
  false, since a 32-bit PowerShell would swap the views.
* **`TEMP` is the run's private folder** (`exec_windows.go:64`), where
  `Add-Type` writes the helper's source and library; the folder is removed
  when the run ends.

### Paths, links and refusals
*Decided in review.* The plan's refusals, made exact.

#### How a path is written
* **The input is typed**: a hive (`HKLM`, `HKU`, `HKCR`, `HKCC`), a view
  (`64` or `32`) and the path under the hive as a list of names. HKCU is
  not a hive of the input ([Hives and users](#hives-and-users)).
* **Text paths** (the console's address bar, import files, link targets)
  are parsed into that form, accepting without regard to case `HKLM`,
  `HKEY_LOCAL_MACHINE`, `HKLM:`, `Registry::HKEY_LOCAL_MACHINE`,
  `Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE`,
  `Computer\HKEY_LOCAL_MACHINE` (as Registry Editor's address bar copies
  it) and the kernel's `\REGISTRY\MACHINE`; and likewise `HKEY_USERS`
  (`\REGISTRY\USER`), `HKEY_CLASSES_ROOT` (read as
  `HKLM\SOFTWARE\Classes`), `HKEY_CURRENT_CONFIG` (read as its alias's
  path) and `HKEY_CURRENT_USER` (which asks which user).
* **Names** are separated by `\` only. `/` is part of a name, as
  Microsoft allows, though PowerShell's provider would split on it.
  Refused: an empty name (`\\`); `.` and `..` (whether Windows treats them
  as references is to be confirmed; refusing them removes the question);
  a name over 255 characters; NUL or another control character; a path
  over 2,048 characters or 512 levels. A trailing `\` is dropped.
* **Every spelling of the 32-bit view.** A path in the 32-bit view is
  checked as the physical key it reaches (`SOFTWARE\WOW6432Node\…`), and a
  path that names `WOW6432Node` or `WowAA32Node` is checked as the key it
  names. A rule names the physical key and holds in every spelling.
* **Comparing.** The server compares names after mapping each character
  to every character Unicode's simple case mappings make it equal to, so
  `ſ`, `ı` and the Kelvin sign `K` match `S`, `I` and `K`. This may refuse
  an odd name Windows would treat as different, which costs nothing. The
  script compares with .NET's ordinal ignore-case and then compares the
  kernel's name of the key it opened, which is the name as stored.

#### Refused, for reading and writing
In both views, in every spelling, with every key under them:

| Path | Why |
|---|---|
| `HKLM\SAM` | The local accounts database, which "stores local user accounts and groups" (Microsoft), with their password hashes (widely documented; not on the Microsoft page cited, so to be confirmed) |
| `HKLM\SECURITY` | LSA secrets (`Policy\Secrets`): the computer's domain account password, services' and scheduled tasks' passwords, and DPAPI's system key; cached domain logons; and the link `SECURITY\SAM`, Microsoft's "copy of the SAM database" |
| `HKLM\SOFTWARE\EasyRMM` | The EasyRMM agent's own (ADR-0056's `Enrolled`, and whatever later ADRs keep there) |
| `HKLM\SOFTWARE\EasyPatch` | The EasyPatch agent's server address, proxy, the certificate it trusts, and its enrollment token until used |
| `HKLM\SOFTWARE\Open Source` | MeshAgent's node ID and options, under its service's name, whatever the name: any MeshAgent on the computer, EasyRMM's or another. Other software under this vendor name is refused with it |
| `HKLM\SYSTEM\<CurrentControlSet or ControlSetNNN>\Services\EasyRMMAgent`, `…\EasyRMMMeshAgent`, `…\EasyPatchAgent` | The agents' services: their programs, accounts, start and recovery |

* **Why reads too.** What the editor reads is stored on the server, in
  its database and its backups, and shown to people. Password hashes, LSA
  secrets and the agents' enrolment and trust data must not land there. The
  agents' keys are refused for reading as well, so that the editor does not
  show the server's address and trusted certificate to someone planning
  to point agents elsewhere, and so that the rule is one rule.
* **Shown as refused.** `SAM` and `SECURITY` appear in HKLM's list, marked
  *Refused by EasyRMM*, and are never opened.
* **Class names** are never read, shown or exported. LSA is said to keep
  its boot key in the class names of keys under `Control\Lsa` (to be
  confirmed); Registry Editor does not show class names either.
* **The list changes only by amending this ADR.**
* **Read, not refused**, and why:
  * `HKLM\SYSTEM\…\Control\Lsa`: settings such as `RunAsPPL`; LSA's
    secrets are under `SECURITY`.
  * BitLocker's policy (`HKLM\SOFTWARE\Policies\Microsoft\FVE`): settings,
    not keys. Recovery passwords are kept in the volume's metadata and
    wherever they are backed up, not in the registry (to be confirmed).
    Feature 8 handles them, never through the editor.
  * Credential Manager and Windows Vault: files under the user's profile
    (Microsoft), out of the editor's reach.

#### Masked values
* **Their data is not returned.** String, binary and other non-number
  values whose name holds, without regard to case, `password`, `passwd`,
  `pwd`, `secret`, `token`, `apikey`, `api_key`, `privatekey`,
  `private_key`, `credential`, `passphrase` or `connectionstring`: the
  script returns their type and size only, and the console shows
  *Masked*. Example: `Winlogon\DefaultPassword`, kept in plain text and
  readable remotely by Authenticated Users (Microsoft). DWORD and QWORD
  values are not masked: numbers named like that are settings
  (`PasswordExpiryWarning`).
* **Reveal**, from slice 2, once step-up exists: one value at a time, for
  a holder of `registry.view` who steps up; recorded as `registry.reveal`;
  the result is served to that person once and emptied in the same
  transaction.
* **Search never matches inside masked data. Export leaves masked values
  out**, with a comment line naming each.
* **Masking is a net, not a boundary.** Secrets under other names (a
  vendor's `Pass`; SNMP's community names, which are value names) are
  shown. A holder of `registry.view` also holds `script.run` and could
  read them anyway ([Permissions](#permissions)).

#### Links
* **The script never lets Windows follow a link.** It opens a path one
  name at a time from the hive's root, each with `REG_OPTION_OPEN_LINK`
  and the view's flag, and asks each key it opened whether it is a link
  (a `SymbolicLinkValue` of type `REG_LINK`).
* **The script follows a link itself** only when the target, parsed as a
  text path, passes the refusals and stays in the hive it starts in: the
  machine's hives to the machine's, or one user's `HKU\<SID>` and
  `HKU\<SID>_Classes` between themselves. Otherwise the link is listed
  with its target, *not followed*. The links Windows makes
  (`CurrentControlSet`, HKCC's alias, a user's `Software\Classes`) are
  followed and shown with both names.
* **The kernel's name of every key the script opens** is read
  (`NtQueryKey`, `KeyNameInformation`) and checked against the refusals
  before anything is read from the key. A key that resolves into a refused
  key is refused even when every name on the way looked allowed.
* **A refusal the server did not make** (the script refused a path the
  server let through, or a kernel's name was refused) is recorded as
  `registry.refused_on_device`, with the path asked for, the rule and the
  kernel's name, and shown on the device's page. Either the server's
  check missed a spelling, a bug to fix, or someone put a link there.
* **Writes never make links**: no `REG_OPTION_CREATE_LINK` and no
  `REG_LINK` value, from the editor, an import or a bulk change. Deleting a
  key whose subtree holds a link is refused.
* **Creating keys.** Each missing name is created with `RegCreateKeyExW`
  under the parent the script opened and checked, and the new key's kernel
  name is checked before any value is written. A link made in the moment
  between the check and the create, by a user in their own hive, can at
  worst create one empty key where it points; the result reports it.
* **Whether a standard user can make a link in their own hive**, and
  whether Windows follows a link from a user's hive into the machine's, is
  to be confirmed on the runners ([Testing](#testing)). This design does
  not depend on the answer.

#### Protected paths, for writes
Writing under these, in either view and in every spelling, needs step-up
and the device's name typed ([Writes](#writes)):

* `HKLM\SYSTEM\<control set>\Services` and `…\Control`: services'
  programs and accounts, LSA, Session Manager, start-up;
* `HKLM\BCD00000000`: boot configuration;
* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` and
  `…\Image File Execution Options`;
* `Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`, the
  machine's and each user's;
* every key named `Policies`, and under it: Group Policy and MDM write
  there and set edits back;
* `HKLM\SOFTWARE\Microsoft\Windows Defender`;
* deleting a key one or two levels under a hive's root (such as
  `HKLM\SOFTWARE` or `HKLM\SOFTWARE\Microsoft`).

This is not every place that can start code as SYSTEM, of which there are
hundreds; it holds the common ones, and grows by amending this ADR.

### Hives and users
*Decided in review.*

* **HKLM**: its keys, with `SAM` and `SECURITY` refused.
* **HKU**: every loaded hive: `.DEFAULT`, `S-1-5-18`, `S-1-5-19`,
  `S-1-5-20`, and each user's SID with its `_Classes`. Named from the
  profile list (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>`)
  and the SID's translation, for local and domain accounts (`S-1-5-21-…`)
  and Microsoft Entra ID accounts (`S-1-12-1-…`, to be confirmed). The
  inventory reads only `S-1-5-21-` (Context); the editor lists every
  loaded hive.
* **HKCU.** The script runs as SYSTEM, whose HKCU is `HKU\S-1-5-18`, and
  Microsoft says services should not use HKCU. So *HKEY_CURRENT_USER*
  opens a choice of the loaded user hives ("Ana Silva, loaded") and shows
  `HKU\<SID>` as *HKEY_CURRENT_USER of Ana Silva*. "Loaded", not "signed
  in": a hive is loaded for a service account or a scheduled task too, and
  may stay loaded after sign-out (to be confirmed).
* **Users not signed in: deferred.** Loading a user's `NTUSER.DAT` needs
  `RegLoadKey` with the backup and restore privileges; a hive EasyRMM
  loaded may collide with the profile service when the user signs in (to
  be confirmed); a run stopped by its timeout would leave the hive loaded;
  roaming profiles and FSLogix keep it elsewhere. An MSP that needs a
  setting for every user uses a script or Group Policy today
  ([Owner questions](#owner-questions)).
* **HKCR** opens as two roots, as Microsoft tells services to: the
  computer's classes (`HKLM\SOFTWARE\Classes`, labelled *HKEY_CLASSES_ROOT,
  the computer's part*) and each loaded user's classes
  (`HKU\<SID>_Classes`). The merged view a given user sees is not
  computed. Writes go to the key shown, never through HKCR's merge rules.
* **HKCC** opens as `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current`,
  labelled *HKEY_CURRENT_CONFIG*.
* **Not offered**: `HKEY_PERFORMANCE_DATA`, hive files that are not
  loaded, other computers' registries.

### Views
* **Both views**, 64-bit (`KEY_WOW64_64KEY`) and 32-bit
  (`KEY_WOW64_32KEY`, the x86 view on ARM64), chosen per tab and named in
  the header: *64-bit view* or *32-bit view*, and the physical key from
  the kernel's name (`HKLM\SOFTWARE\WOW6432Node\Vendor`). A key the two
  views share says so: both kernel names are the same.
* **Every open, create and delete** under a key uses the view's flag, as
  Microsoft requires. Deletes use `RegDeleteKeyExW`, since `RegDeleteKey`
  cannot take the flag.
* `WowAA32Node` (ARM32 programs) is shown as a key, not as a view.
* **Data is written as given.** WOW64 rewrites `%ProgramFiles%` in
  `REG_SZ` data written by 32-bit programs; the script runs 64-bit and
  relies on no rewriting.

### Types, encoding and limits
* **Read raw**: the type's number and the bytes, from `RegEnumValueW`;
  never expanded, never converted by .NET.

| Type | In the result | Editable |
|---|---|---|
| `REG_SZ`, `REG_EXPAND_SZ` | `text`: the UTF-16LE bytes as text, one terminating NUL dropped; never expanded | Yes |
| `REG_MULTI_SZ` | `items`: an array of strings | Yes; an empty item or a NUL in one is refused |
| `REG_DWORD` | `number`, 0 to 4,294,967,295; the console shows hex too | Yes |
| `REG_QWORD` | `decimal`, a string, since JavaScript's numbers lose precision past 2^53; hex too | Yes |
| `REG_BINARY` | `base64`; the console shows hex | Yes |
| `REG_NONE`, `REG_DWORD_BIG_ENDIAN`, `REG_LINK`, the resource lists, any other number | `base64` with the type's name or number | No |

* **Data that is not well formed**: a string with no terminator, an odd
  length, a NUL inside or a lone surrogate; a DWORD that is not 4 bytes;
  a `REG_MULTI_SZ` with an empty item. The result gives `raw` in base64
  beside what can be shown, with a flag, and the value is read-only, so
  that no one saves bytes they did not see. A name with a NUL or a lone
  surrogate is shown escaped and is read-only.
* **The default value** has the name `""` and is shown as *(Default)*.
* **Limits**:
  * a page: at most 1,000 subkeys, 500 values or 1 MiB of result,
    whichever comes first, with a cursor (the last name, in ordinal
    ignore-case order) for the next;
  * a value's data in a page: up to 4 KiB; a larger value shows its type
    and size and is read alone, up to 1 MiB, then cut and marked as cut;
  * a value written: at most 512 KiB of data;
  * a value name: at most 16,383 characters (Microsoft's limit); the
    audit record keeps its first 1,024.

### Browsing
*Slice 1.*

* **Opening a key** runs a `registry_query` `list`. It returns the
  subkeys (name; number of subkeys and values; last-write time; *link to
  …*, *access denied* or *refused*), the values (name, type, size, data
  up to 4 KiB, or *masked*), the key's kernel name, the view, and when it
  was read. Each listed subkey is opened, with `REG_OPTION_OPEN_LINK`, to
  mark links and access denied, within the run's time (to be measured on
  a key of 1,000 subkeys).
* **Refresh** runs it again. The header shows *Read at 14:02:11*.
* **A new read for the same tab cancels the one before** if it has not
  started. A person has at most 2 reads open per device; a third is
  refused, *wait for the last read*.

### Search
*Slice 1.* From a chosen key, in one view:

* **matches**, as a substring with ordinal ignore-case: key names, value
  names, and string data (`REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`); not
  binary data, not masked data;
* **never enters a refused key and never follows a link**; it lists links
  as *not followed*;
* **bounds**: depth (10 by default, at most 32), 500 matches, 100,000
  keys visited, and 45 seconds of the 60-second run. The result says which
  bound stopped it and the first key it did not visit;
* **a term of 1 to 256 characters**; no patterns or regular expressions;
* **its record holds the term's length, not the term**, which may be a
  password someone is looking for. The term is in the job's input, read
  with ADR-0063's record.

### Export
*Slice 1.*

* **One `registry_query` `export`** of a key and its subtree in one view,
  at most 5,000 keys and 2 MiB of result; a larger one is refused,
  *export a smaller key*. One run, not pieces put together, so the file is
  one reading.
* **JSON**: the result as it is, with the device, the view, the time and
  the script's version.
* **`.reg`**, built by the server: `Windows Registry Editor Version 5.00`,
  UTF-16LE with a byte order mark, CRLF line ends; each type in Registry
  Editor's notation (`dword:`, `hex:`, `hex(2):`, `hex(7):`, `hex(b):`,
  `hex(0):`), to be confirmed against `reg.exe`. Comment lines (`;`) name
  what was left out: masked values, refused keys, links not followed,
  keys denied. A link's `SymbolicLinkValue` is never written, so
  importing an export never makes a link. Keys of the 32-bit view are
  written under their physical names (`WOW6432Node`).
* **Downloaded** by the person who asked, within the hour, and recorded as
  `registry.export` with the format, the counts and the size.
* **"Export a key before modifying it"**: the write dialog offers *Export
  this key first*, and every change keeps its own backup ([Backup and
  undo](#backup-and-undo)).

### States
ADR-0065's words, as the registry needs them. EasyRMM does not judge
registry values, so there is no healthy or unhealthy.

* **Reported**: read this time, with *Read at*.
* **Unavailable**: Windows denied SYSTEM access (*access denied*);
  Constrained Language Mode; `AllSigned` from Group Policy; the agent
  cannot take registry jobs (*update the agent*).
* **Unknown**: the device did not answer within the wait, the run timed
  out, the agent stopped while it ran, or the result was malformed; with
  the reason.
* **Unsupported**: a Linux device; no Registry tab, and the API answers
  so.
* **Refused by EasyRMM**: EasyRMM's rule, not a state of the computer,
  and named as such.
* **Not found**: the key or value is gone since it was listed.

### Writes
*Slice 2. Decided in review.*

* **Operations**: create a key; create, change or delete a value (a
  change may change its type); delete a key and its subtree. Renaming,
  copying and permissions are not offered: not asked for.
* **Prepare first.** Opening the edit dialog runs a `registry_query`
  `prepare`: the value or subtree as it is; the key's last-write time; the
  owner from ADR-0054's ownership reader (`internal/winpolicy`, W1, which
  answers an owner and its policy, none, or cannot tell; see
  [Managed elsewhere](0054-hardening-windows-computers-and-servers.md#managed-elsewhere));
  whether Windows hardening's manifest lists the value (W2); and whether
  the path is protected.
* **The dialog names the device** (name, organization, site, last seen),
  the view and the physical key, the value before and after, and the
  warnings: *set by Group Policy (policy …); it will set this back*; *the
  owner cannot be told*; *Windows hardening set this; changing it leaves
  hardening's undo for this value*. A protected path needs step-up and the
  device's name typed.
* **Checked before writing.** The change carries what the prepare saw:
  for a value shown, its type and its data's SHA-256; for a masked value
  or a key, the key's last-write time. The script refuses, *changed since
  you looked*, when that differs, and the console reads again. The
  SHA-256 is in the job's input, under the input's rules, never in a
  record.
* **One run**: the script checks, takes the backup, writes, reads back
  and reports before and after. No backup, no write.
* **Windows' permissions are respected.** Keys are opened with the access
  needed and no more (`KEY_READ` to read; `KEY_SET_VALUE`,
  `KEY_CREATE_SUB_KEY` or `DELETE` to write). The backup and restore
  privileges are never enabled, ownership is never taken, and a key's
  permissions are never changed, except that undo gives a deleted key its
  permissions back. *Access denied* is shown, and nothing is forced.
* **One change at a time.** `registry_change` takes ADR-0054's device
  lock: no registry change runs beside a hardening apply or undo, or
  beside another registry change, on the same device; reads never wait
  for it.
* **No approvals.** *Decided in review*: a stolen session reaches one
  device per request, as with the terminal (ADR-0064's reason for putting
  step-up on one-off commands), and step-up covers the paths where one
  write starts code as SYSTEM. Bulk changes need step-up for every job.
  [Owner question](#owner-questions) 3.

### Backup and undo
*Slice 2.*

* **What is kept.** A value: its type and data before, or *absent*. A
  created key: *absent*. A deleted key: its subtree's keys and values and
  each key's permissions (its DACL as SDDL), at most 1,000 keys and
  512 KiB of data. A larger subtree, one with a key the script cannot
  read, or one holding a link, is not deleted (*too large to back up*,
  *cannot be read whole*, *holds a registry link*). Owners and class names
  are not kept and not restored.
* **Where.** In the change's result, for `EASYRMM_JOB_OUTPUT_RETENTION`,
  and downloadable as `.reg`.
* **Undo** is a change built from the backup. It expects the state the
  change left and refuses, *changed since*, unless the person confirms
  *undo anyway*. A deleted key is created again with its values, and its
  permissions are set last, deepest key first. A created key is deleted
  only while it is still empty. Undoing a masked value needs step-up; its
  data goes back without being shown. Undo is a `registry_change` with the
  same checks, and is recorded.

### Import
*Slice 3.*

* **A `.reg` file** of at most 256 KiB: `Windows Registry Editor Version
  5.00` in UTF-16LE with a byte order mark, or in UTF-8; `REGEDIT4` only
  when it is ASCII. Parsed on the server into at most 2,000 operations:
  keys, values, `[-key]` and `"name"=-` deletes. Each path goes through
  the same parser and refusals. Data types: the six editable ones and
  `hex(0)` (`REG_NONE`, which Windows' file associations use, to be
  confirmed). `hex(6)` (`REG_LINK`) and every other type are refused,
  naming the line.
* **Preview**: a `prepare` for every key and value the file touches,
  shown as differences (added, changed, deleted, unchanged), with Writes'
  warnings and protected paths; step-up if any is protected.
* **Apply**: one `registry_change` with every operation, in order, each
  backed up first. On a failure the run puts back what it already changed,
  from its backups, in reverse, and reports each item. One record,
  `registry.import`, with the counts and the first 20 paths; one change row
  per item.

### Bulk changes
*Slice 4.*

* **One change or one import across devices**, chosen as ADR-0064's
  [targets](0064-remote-powershell-management.md#targets) are
  (organization, site, group or a selection; at most 500), with
  `registry.edit` checked at each device's site. Devices that are not
  Windows, and agents without `job.structured`, are left out and counted.
* **Step-up for every bulk job.** The confirmation names the scale (*Set
  `…\Foo` to 1 on 312 devices in 3 sites?*); for a protected path the
  count is typed.
* **No check before writing** (there is no prepare per device): each run
  takes its backup and reports before and after. *Undo on all* creates an
  undo per device, each with its own check.
* **Recorded** as one `registry.change` per organization with the device
  count (W2's rule), and one change row per device.

### Permissions
*Decided in review.*

* **`registry.view`**: browse, read values, search, export, read changes.
  **`registry.edit`**: create, change, delete, import, undo, bulk. Each is
  checked at the device's site. Reading a result needs
  `job.view_sensitive` as well; ADR-0063 foresaw a stricter permission for
  this kind of output, and that "the output endpoint would then ask for
  both".
* **Technicians and above hold both; Read-Only holds neither.**
* **Least privilege, and why Technicians.** A Technician already holds
  `device.terminal` and `script.run` at the same sites (`rbac.go:142-145`):
  a SYSTEM shell on any online computer there. The editor puts nothing new
  within their reach; it adds structure, refusals, backups and a record
  per change. Withholding it would push the same work to the terminal,
  which records only the session. Read-Only is for viewing "without making
  changes" and may be given to people who are not technicians; registry
  values can be secrets, and the plan's F2 says registry values must not
  reach Read-Only.
* **Two permissions, not one**, because reads and writes are checked
  apart, at different endpoints; the roles may split them later. Today
  both start at Technician ([Owner questions](#owner-questions)).
* **Step-up** ([ADR-0055](0055-lets-encrypt-in-one-step.md#step-up-authentication),
  plan [F5](../feature-plan-msp.md#f5-approvals-and-step-up-authentication))
  for protected paths, reveals, undoing a masked value, and every bulk
  job. An account without a second factor cannot do these.
* **MeshCentral's registry view stays off** (`RightNoRegistry`), so the
  only registry view is the one that is recorded.

### Audit
*Decided in review.*

| Action | When | Details |
|---|---|---|
| `registry.read` | a query is created | device, hive, view, path (its first 2,048 characters), operation (`list`, `value`, `search`, `export`, `prepare`), the search term's length, the limits asked |
| `registry.export` | an export file is downloaded | format, keys, values, size |
| `registry.reveal` | a masked value is revealed | path, value name, type, size, when the session stepped up |
| `registry.change` | a change, an undo or a bulk change is created | device (for bulk, the device count, one record per organization), hive, view, path, value name (its first 1,024 characters), operation, type and size before and after, whether protected, when the session stepped up, the warnings shown, the change it undoes |
| `registry.import` | an import is created | counts by operation, the first 20 paths, the file's size |
| `registry.change_view` | a change's data is read | the change, the sizes |
| `registry.data_remove` | a change's data is removed | the change |
| `registry.refused` | the server refuses a request for a refused path | the path and the rule; at most once per caller, target and rule in 10 minutes and 20 times per caller in 10 minutes, as ADR-0063 bounds refusals |
| `registry.refused_on_device` | a result shows the script refused what the server allowed, or holds a refused path | the path asked for, the rule, the kernel's name; the system as actor, and the person who asked in the details |

* **Every read and every write is recorded**; the data is not. The audit
  log outlives results, is forwarded (ADR-0023) and is read by every
  holder of `audit.view`, and values can be secrets. A SHA-256 does not
  help: it confirms a guess, and a DWORD has only 2^32 values (ADR-0064's
  rule for one-off commands). So the plan's "old and new data's size and
  SHA-256" becomes type and size; the data before and after is kept with
  the change and read with `registry.change_view`.
* **Changes have a table of their own**, `registry_changes`: one row per
  item (device, run, hive, view, path, value name, operation, outcome,
  types and sizes, the change it undoes), written when the result
  arrives, written once, under row-level security, with no data. The
  device's *Changes* list and the audit records point to it.
* **The count a query returned is on its run**, not in its record, which
  is written when the query is created, as `device.script_run` is.

### Offline devices, timeouts and huge keys
* **Offline.** The tab says when the device was last seen and sends no
  reads while it is offline. A read sent to a device that then stops
  answering is *Unknown* after 2 minutes. A single change waits 15
  minutes, then expires with the reason, and nothing changes. A bulk
  change waits 1 hour by default, at most 7 days; there is no check before
  writing, and the backup still holds.
* **A change that ran while the console was away** is reported by the
  agent's journal when it reconnects (`journal.go:34-36`); the change shows
  as made from then, and the agent never runs it twice.
* **Timeouts.** Each run has 60 seconds. The script stops itself at 45
  seconds for search and export and at 30 for the rest, and reports what
  it has, rather than being stopped with nothing.
* **Huge keys** page by name ([Browsing](#browsing)); HKCR's and
  `Installer`'s thousands of subkeys page like any other. Slice 1 measures
  a key with 100,000 subkeys.

### The console
* **A Registry tab** on a Windows device's page, for holders of
  `registry.view` at its site, beside Hardening
  (`DeviceDetailPage.tsx:61-70`); none on Linux devices.
* **A header that stays in view**: the device's name, organization and
  site, whether it is online, the view, the physical key, *Read at* and
  Refresh. Every dialog names the device again.
* **A tree of keys and a list of values**; an address bar that takes every
  spelling above, and HKCU's choice of user; a filter on names within the
  page shown.
* **Changes**: the device's list of changes, with their data under
  `registry.change_view`, and Undo.

### Linux
No registry, and no tab; the API answers *unsupported*. Linux's nearest
equivalents are out of scope: `sysctl` values are Linux hardening's
([ADR-0051](0051-hardening-linux-computers.md)), and files under `/etc`
and `dconf` are reached through the terminal and scripts. The requirement
names Windows only.

### Not chosen
* **.NET's `RegistryKey` alone**: follows links unseen; types come back
  `Unknown`.
* **PowerShell's Registry provider**: splits names on `/`, which a name
  may hold; reads wildcards in paths unless given `-LiteralPath`; has
  drives for HKLM and HKCU only; follows links.
* **`reg.exe` and WMI's `StdRegProv`**: text to parse, links followed, no
  kernel names.
* **Native queries in the agent now**: faster, and free of Constrained
  Language Mode, `Add-Type` and EDR alerts; but every new operation would
  ship in the agent rather than the server. Slice 5, when measured.
* **A compiled helper library carried in the job** and loaded from bytes:
  what malware does, and worse with EDRs than `Add-Type`.
* **Arguments on the command line, or the result in standard output**:
  see Context.
* **A hash of data in audit records**: ADR-0064's rule.
* **Loading the hives of users who are not signed in**: deferred.
* **Comparing two devices, or against a baseline**: not asked for
  ([Owner questions](#owner-questions)).
* **Approvals**: F5's approvals exist from the keystore's slice (step 19
  of the plan's order) and could gate bulk changes later.

### What this does not fix
* **A Technician still has the terminal and scripts** as SYSTEM, and can
  read `SAM` or change anything that way. The editor's refusals bind the
  editor.
* **Masking catches names**, not every secret.
* **Results and backups stay in database backups** made while they were
  kept, as ADR-0063 says of output.
* **Group Policy and MDM set back** what they own; the editor warns.
* **An EDR may stop the script** until it is allowed by its hash.
* **Constrained Language Mode and `AllSigned`** leave the editor
  unavailable on those computers until slice 5, or until code signing.

## The requirements
Feature 7 of the owner's requirements, bullet by bullet.

| Requirement | Where | Status after this ADR |
|---|---|---|
| Browse registry keys and subkeys | Browsing (slice 1) | New: pages of up to 1,000, links and refusals marked |
| View registry values | Browsing; Types (slice 1) | New: data by type; masked values' type and size |
| View registry value types | Types (slice 1) | New: every type, the editable ones and the rest |
| Create registry keys | Writes (slice 2) | New, with backup and undo |
| Create registry values | Writes (slice 2) | New, with backup and undo |
| Modify existing registry values | Writes (slice 2) | New, checked against what was read |
| Delete registry values | Writes (slice 2) | New, with backup and undo |
| Delete registry keys | Writes; Backup and undo (slice 2) | New: subtrees up to 1,000 keys and 512 KiB, none holding a link |
| Search registry keys and values | Search (slice 1) | New, bounded by depth, matches, keys and time |
| Export registry keys | Export (slice 1) | New: `.reg` and JSON, up to 5,000 keys |
| Import registry data | Import (slice 3) | New: `.reg` with a preview; `REG_LINK` refused |
| Refresh registry information | Browsing (slice 1) | New: Refresh and *Read at* |
| REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_EXPAND_SZ | Types | Read in slice 1, written in slice 2 |
| HKEY_LOCAL_MACHINE | Hives and users (slice 1) | New, without `SAM` and `SECURITY` |
| HKEY_CURRENT_USER | Hives and users (slice 1) | Each loaded user's hive; users not signed in deferred (Owner questions) |
| HKEY_USERS | Hives and users (slice 1) | Every loaded hive, named |
| HKEY_CLASSES_ROOT | Hives and users (slice 1) | The computer's classes and each loaded user's; the merged view not computed |
| HKEY_CURRENT_CONFIG | Hives and users (slice 1) | Through its alias |
| Support 32-bit and 64-bit registry views | Views (slice 1) | Both; the x86 view on ARM64 |
| Clearly identify which registry view is being accessed | Views; The console | The view and the physical key on every page |
| Respect Windows registry permissions | Writes | As SYSTEM, with no privilege enabled, no ownership taken, no permissions changed |
| Handle inaccessible keys and access-denied errors | States | *Unavailable: access denied*, per key and value |
| Safeguards before deleting or modifying important keys | Paths, links and refusals; Writes | Refused paths; protected paths behind step-up and the device's name typed; owners' warnings; checked before writing; backups |
| Allow exporting a key before modifying it | Export; Backup and undo | *Export this key first*, and a backup in every change |
| Record registry modifications in the audit history | Audit | `registry.change`, `registry.import` and change rows; the data kept with the change, not in the record |
| Clearly identify the target device before executing changes | The console; Writes; Bulk changes | On every view and dialog; the name typed for protected paths; the count for bulk |

The requirements' overall expectations, where they bear on this feature:

| Expectation | Where | Status after this ADR |
|---|---|---|
| 1. Multi-tenant permission boundaries | Permissions | Checked at each device's site, under row-level security |
| 2. Execution history and results | Changes; the Jobs filter | A device's changes with data; reads kept 1 hour |
| 3. Success, failure and meaningful errors | States; each item's outcome | New |
| 4. Organization, site, group and device targeting | Bulk changes (slice 4) | On ADR-0064's targets |
| 5. Reporting and notifications | — | None planned: EasyRMM judges no value; `registry.refused_on_device` may become an alert kind under ADR-0053 later |
| 6. Permissions and audit records for sensitive operations | Permissions; Audit | New |
| 7. Healthy, unhealthy, unknown, unsupported and unavailable | States | Unknown, unsupported and unavailable, with *reported* and *Refused by EasyRMM*; healthy and unhealthy do not apply, since EasyRMM judges no value |
| 8. Offline and reconnecting endpoints | Offline devices | Waits per kind; the journal |
| 9. Supported and unsupported environments | States; Linux | Windows; Linux unsupported; Constrained Language Mode and `AllSigned` unavailable |

## Slices
Each merges and is verified on its own, at every level it touches. In the
plan's [order](../feature-plan-msp.md#order), slice 1 is step 15, after
ADR-0063 (step 5), ADR-0064's slice 1 and its `accepts` (step 6), and W2's
job amendments (step 8). The later slices are among step 28's.

1. **Read-only: F2, browsing, search and export.** The smallest that is
   worth shipping: technicians read a computer's registry with a record of
   each read. Three pull requests:
   * **F2**: the table of kinds, `jobs.input` and `job_runs.result` with
     their functions, endpoints and purge per kind; `job.structured` in
     the agent (input, result, the quick lane), the claim's order and size,
     and `MaxResultBody`;
   * **browsing**: the script with its rules, the two permissions,
     `registry.read`, `registry.refused`, `registry.refused_on_device`, and
     the Registry tab;
   * **search and export**, with `registry.export`.

   *Verified*: integration tests; agent tests; the Windows runners, x64
   and ARM64, as LocalSystem; the time from click to view, and whether
   the compile is flagged, on a real Windows computer of the owner's test
   instance before the guide calls it verified; the end-to-end test; an
   agent of the previous release running every job it ran before.
2. **Writes, backup and undo.** After ADR-0054's W1 (its ownership reader,
   step 7), W2 (its manifest, step 8) and step-up (ADR-0055's slice 5b2,
   step 17). Create, change and delete; prepare; protected paths; reveal;
   `registry.change`, `registry.reveal`, `registry.change_view` and
   `registry.data_remove`; the Changes list.
3. **Import**, with its preview and `registry.import`.
4. **Bulk changes**, after ADR-0064's targets (its slice 4).
5. **Native queries in the agent**, only if slice 1's measurements call for
   them (median click to view over 3 seconds on a real computer, EDRs
   flagging the compile, or many computers under Constrained Language
   Mode): the same input and result, through the signed poll; the agent
   lists another capability, and the script stays for agents without it.
   An amendment to this ADR.

## Consequences
* Technicians can read a Windows computer's registry from the console,
  with every read recorded, and, from slice 2, change it with a backup,
  undo and a record per change.
* EasyRMM gains F2, which features 9, 12 and 8 reuse: kinds with a signed
  input and a structured result, guarded like output, kept per kind.
* The agent gains `job.structured`: an input file, a result file and two
  reserved slots. An agent of the release before keeps running everything
  it ran, gets no registry job, and the console says to update it.
* The jobs' kinds gain `registry_query` and `registry_change`; `jobs` gains
  `input`, `job_runs` gains `result` and its sizes and times; a table
  `registry_changes`; the poll's answer is bounded by size as well as
  count; results may be 8 MiB.
* Permissions gain `registry.view` and `registry.edit`; the audit log
  gains the nine actions above.
* ADR-0054's one change at a time covers registry changes, and this ADR's
  script uses `Add-Type`, which ADR-0054's does not.
* Computers under Constrained Language Mode or `AllSigned` show the editor
  as unavailable.
* Windows paths that the runners cannot show stay marked unverified until
  ADR-0054's Windows machines, or real computers, show them: a domain's
  Group Policy setting a value back, `AllSigned`, Constrained Language
  Mode, roaming profiles.

## Testing
* **Integration tests** in Go against real PostgreSQL through `testdb`
  (`make test-db`), without mocks:
  * **F2**: `jobs.input` and `job_runs.result` refused to `easyrmm_app`
    (`42501`), read only through the functions; ADR-0063's catalogue test
    finds the new functions with `pg_temp` last; a query's result read by
    the person who asked and refused (`403`, recorded within the bound) to
    another Technician of the site; a change's result read with
    `registry.change_view`; every role on each endpoint; the purge emptying
    a query's result after an hour and a change's after the output
    retention, and not before; a result of the wrong operation, path,
    version or size failing the run and not stored; one holding a refused
    path recorded as `registry.refused_on_device`; the claim delivering an
    F2 run only to a poll listing `job.structured`, quick runs first, and
    stopping before 6 MiB while always delivering one.
  * **Paths**: a table of spellings refused by the server (every row of
    the refused table as `HKLM\`, `HKEY_LOCAL_MACHINE\`, `\Registry\Machine\`,
    `Registry::`, `Computer\`, lower case, `SECURITY\SAM`, the 32-bit view
    and `WOW6432Node`, `ControlSet001` and `CurrentControlSet`, and names
    with `ſ`, `ı` and `K`); refusals recorded within the bound; `/` kept as
    part of a name; `.`, `..`, empty names and long paths refused.
  * **Records**: one `registry.read` per query; no record holding data or
    any hash of data (a random marker written as a value appears in no
    record, list or job answer); the search term's length, not the term;
    one `registry.change` per organization for bulk.
  * **Writes, import, bulk** (slices 2 to 4): step-up required for
    protected paths, reveals and bulk, stale step-up refused; the change
    lock against a hardening apply; `.reg` files parsed, `hex(6)` and the
    other types refused naming the line; targets as ADR-0064's tests.
* **Agent tests** in Go on every platform: the payload's `input` and
  `lane` refused by the release before's strict decoder and accepted now;
  `job.structured` listed only while the last heartbeat answer was of
  level 2 or higher; the input file written in the run's folder and gone
  after; the two variables set and no others leaked; the result file read,
  over 2 MiB or not JSON failing the run; the journal keeping `result`
  across a restart; quick runs taking the reserved slots while four long
  runs hold the others.
* **The script on CI's Windows runners, as LocalSystem**, through a
  scheduled task, as ADR-0054's and ADR-0064's tests run, on
  `windows-latest` (x64) and `windows-11-arm` (ARM64). Test keys live
  under a random name below `HKLM\SOFTWARE`, made and removed by the test:
  * the script's rules section equal to `rules.json`;
  * every spelling above refused by the script with the server's check
    skipped (a test entry point that runs the script directly);
  * links made by the test's own helper (test code, never shipped): a link
    to `\REGISTRY\MACHINE\SAM` refused by the kernel's name and recorded; a
    link to an allowed key listed and followed only within its hive; a
    link from a standard user's hive into HKLM, made by a process running
    as a local standard user the test creates, recording whether Windows
    lets the user make it and whether it would follow it, and the script
    not following it;
  * every type, including `REG_NONE`, `REG_DWORD_BIG_ENDIAN`,
    `REG_RESOURCE_LIST` and an unknown number written raw; strings with no
    terminator, odd lengths, NULs and lone surrogates; names with NUL;
    the default value;
  * both views, a shared key, the x86 view on ARM64; the 255-character
    limit per name or per path;
  * a key with 100,000 subkeys paged; a 1 MiB value; search stopping at
    each bound;
  * `.reg` export imported by `reg import` into another test key and read
    back equal, and `reg export`'s file of the same key compared with
    EasyRMM's;
  * writes: compare refusals, backups, undo, a key deleted and restored
    with its DACL, a key that denies SYSTEM writing shown as access
    denied and left alone;
  * a run started in Constrained Language Mode (the test's runspace)
    answering *unavailable*; with script block logging on, no input data
    in the PowerShell log;
  * the time from the agent starting PowerShell to the result file,
    printed, and whether `csc.exe` ran.
* **Machine tests**: with ADR-0054's Windows machines under KVM, Group
  Policy setting a value the editor changes, a domain account's hive, and
  `AllSigned`.
* **Page tests** (`web/src/pages/devices/`): the tab only for Windows and
  `registry.view`; the header's device, view and physical key; each state;
  masked values; refused keys greyed; links; the write dialog's warnings,
  step-up and typed name.
* **The browser end-to-end test** (`make e2e`), with the simulated agent
  (`web/e2e/agent.ts`) taught `job.structured` and answering with results
  the real script produced on a runner: a technician opens the Registry
  tab, reads a key and exports it; a Read-Only user sees no tab; the audit
  log shows the records. The simulated agent is a stand-in, as in
  ADR-0064's end-to-end test: it does not run the script, which is tested
  on the runners and on a real computer.
* **Real computers**: browsing, a change and its undo on a real Windows
  computer of the owner's test instance, before the guide calls them
  verified.
* The coverage floors in `scripts/ci/check-coverage.sh` hold for the
  packages touched.

## Owner questions
1. **Users who are not signed in.** Editing their registry means loading
   their hive, with the risks under [Hives and users](#hives-and-users).
   Is it wanted, as a slice of its own?
2. **Comparing.** Comparing a key between two devices, or against a saved
   baseline, is not in the requirement. Is it wanted?
3. **Who writes, and approvals.** Decided in review: Technicians write,
   with step-up for protected paths and bulk changes, and no second
   person's approval. Should writes start at Site Administrator instead,
   or bulk changes need an approval once F5's approvals exist?

## References
* Structure of the registry:
  https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry
* Registry element size limits:
  https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
* Registry value types:
  https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
* RegOpenKeyExW:
  https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
* RegLoadKeyW:
  https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw
* ZwQueryKey:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwquerykey
* KEY_INFORMATION_CLASS:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_information_class
* Accessing an alternate registry view:
  https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view
* Registry redirector:
  https://learn.microsoft.com/en-us/windows/win32/winprog64/registry-redirector
* HKEY_CLASSES_ROOT key:
  https://learn.microsoft.com/en-us/windows/win32/sysinfo/hkey-classes-root-key
* Predefined keys:
  https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys
* Credentials processes in Windows authentication:
  https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication
* Configure Windows to automate logon:
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
* about_Registry_Provider (5.1):
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_registry_provider?view=powershell-5.1
* RegistryValueKind:
  https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvaluekind
* reg export:
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-export
* reg import:
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-import
* How to add, modify, or delete registry subkeys and values by using a
  .reg file (support article 310516; not read for this ADR):
  https://support.microsoft.com/help/310516
