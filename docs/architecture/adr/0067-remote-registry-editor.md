# ADR-0067: Remote Windows registry editor

* Status: Accepted (2026-11-21, after an independent review). Not
  implemented.
* Nothing here was decided by the owner. Everything marked as decided was
  decided in review, and the owner can overturn it; the
  [owner questions](#owner-questions) list what is the owner's.
* Revised after an independent review (2026-11-21): the registry work
  runs natively in the agent instead of a PowerShell script; inputs live
  and go with their results, and masked values stay masked everywhere;
  changes survive a crash; writes never cross a link; numbers and
  protected strings are recorded; payload and result sizes are bounded on
  the real bytes. Each is in its section.
* Amends, each gaining an *Amended by ADR-0067* line when this is
  implemented:
  * [ADR-0017](0017-scripts-and-jobs.md): two job kinds,
    `registry_query` and `registry_change`; kinds whose work is a script
    or code built into the agent, given an input and returning a result
    (F2); settings per kind; a reserved lane on the agent; how the claim
    fills and orders a poll's answer; the size of a result.
  * [ADR-0063](0063-who-sees-job-output-and-arguments.md): its guarded
    data gains inputs and results, kept and removed per kind; its
    arguments endpoint answers an input under the kind's rules; its
    refusal bound counts `registry.refused`.
  * [ADR-0054](0054-hardening-windows-computers-and-servers.md#the-job):
    "one change at a time on a device" covers registry changes.
* Builds on: [ADR-0007](0007-hash-chained-audit-log.md) (the audit log),
  [ADR-0009](0009-agent-protocol.md#evolving-the-protocol-amended-2026-11-21)
  (evolving the protocol), [ADR-0020](0020-windows-agent.md) (the Windows
  agent), [ADR-0023](0023-audit-forwarding.md) (forwarding),
  [ADR-0027](0027-agent-updates.md) (agent updates),
  [ADR-0047](0047-tokens-shown-again.md) (a read and its record in one
  transaction), [ADR-0063](0063-who-sees-job-output-and-arguments.md), the
  accepted [ADR-0064](0064-remote-powershell-management.md) (the poll's
  `accepts`, targets, the hash rule, Windows tests as LocalSystem), and
  these proposed ADRs:
  [ADR-0054](0054-hardening-windows-computers-and-servers.md) (accepted
  since, on 2026-11-22; W1's ownership reader, W2's job amendments),
  [ADR-0055](0055-lets-encrypt-in-one-step.md#step-up-authentication)
  (step-up) and [ADR-0060](0060-collecting-logs.md) (arguments on the
  command line; the PowerShell logs it collects), and
  [ADR-0065](0065-hardware-health.md) (hardware health), whose words for
  states this ADR uses.
* Requirements: feature 7, "Remote Windows Registry Editor", of the
  [owner's requirements of 2026-11-21](../requirements/2026-11-21-msp-features.md#7-remote-windows-registry-editor).
  Every bullet is placed in [The requirements](#the-requirements). The
  [plan](../feature-plan-msp.md#7-remote-windows-registry-editor) lists
  it as feature 7, and it builds
  [F2](../feature-plan-msp.md#f2-fixed-script-job-kinds-whose-results-are-hidden-by-kind).
* **Where this differs from the plan**, each argued where it is decided:
  1. **The registry work is code in the agent**, run as a child process
     of the agent's own program. The plan's F2 says "The agent does not
     change" and its slice 1 uses a PowerShell script, keeping native
     queries for a slice 5 "only if measured latency calls for them".
     There is one implementation, native, and no slice 5.
  2. **F2 gains executors**: a kind's work is either a script from the
     server or code built into the agent, and each needs a capability the
     agent lists.
  3. **No SHA-256 of data in audit records**, where the plan records the
     old and new data's size and SHA-256 (ADR-0064's hash rule). Records
     carry numbers before and after, and string data on protected paths,
     instead.
  4. **A typed confirmation only for protected paths and bulk changes**,
     where the plan's slice 3 has one for every write. Every write still
     shows a confirmation naming the device, the key and the value before
     and after; typing the device's name for every edit would train people
     to type it without reading, so it is kept for where a mistake costs
     most.
  5. **Results of up to 2 MiB and result bodies of up to 8 MiB**, where
     the plan's F2 has a structured result of 64 KiB. A page of 1,000 key
     names, and a key delete's backup of up to 512 KiB, do not fit in
     64 KiB; reads still page.
  6. **A query's count is on its run, not in its audit record**, where
     the plan's F2 has "one row per query (the path or filter and the
     count)": the record is written when the query is created, before the
     count exists.
  7. **Search moves to the read-only slice**, beside export; import stays
     with writes.
  8. **Bulk changes across devices** are a slice of their own (the
     requirements' overall expectation 4).
  9. **HKCU is offered for each loaded user hive**, not each signed-in
     user.

## Context
Each claim below was checked in the code at `main` `987618b` for this
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
  constraint `jobs_kind_check`, `server/migrations/00027_hardening.sql:16`).
  Their scripts are compiled into the server (`hardening.go:51`,
  `software.go:44-54`), at most 512 KiB (`MaxJobBody`,
  `hardening.go:40-42`), and take arguments the server checks against
  fixed lists. Hardening answers with one line,
  `EASYRMM-HARDENING-RESULT-V1`, of at most 64 KiB (`hardening.go:46-49`),
  decoded strictly and checked against the job (`parseHardeningResult`,
  `:322-376`); a malformed one fails the run (`recordHardening`,
  `:410-466`).
* **A job is written once.** It keeps its script and the script's
  SHA-256, and each run is recorded once with that SHA-256 (`create`,
  `server/internal/jobs/jobs.go:281-337`; the SHA-256 at `:291-293`, the
  record at `:311`). "It is written once, with its runs, in the caller's
  transaction; `easyrmm_app` cannot update it"
  (`docs/architecture/database.md:89`).
* **Arguments are on the command line**: at most 32 of 1 KiB each
  (`jobs.go:171-176`), passed after `-File`
  (`agent/jobs/exec_windows.go:99`). ADR-0060's Context: process auditing
  records them, and other local processes can read them while the job
  runs.
* **The payload** (`internal/agentproto/jobs.go:102-113`) is signed with
  Ed25519 over `EASYRMM-JOB-SIG-V1\n` and its JSON (`:135`, `:146-153`)
  and decoded with unknown fields refused (`:157-169`), so a new field
  must reach only agents that said they take it (ADR-0064's `accepts`).
  `VerifyJob` requires a known shell and a script (`:183`).
* **The poll** asks with an empty request (`PollRequest`, `:81`); its
  answer holds at most 8 jobs (`MaxPollJobs`, `:19-20`), and the agent
  reads at most 8 MiB of it, sized for "Eight jobs with 64 KiB scripts"
  (`agent/client/client.go:290-293`).
* **The claim** (`server/internal/jobs/delivery.go:49-124`) takes queued
  runs and runs delivered over `RedeliverAfter` (2 minutes,
  `server/internal/jobs/service.go:49`) ago without starting, together,
  oldest first (`delivery.go:53-64`), counts deliveries, and never gives
  up on a run before it expires. So a run whose answer the agent cannot
  take is sent again in the next answers, oldest first, with whatever
  runs share them. A delivered run asks the server before it starts
  (`Start`, `:164`).
* **The result** carries the first and last 128 KiB of each output stream
  (`agentproto/jobs.go:24-30`); the server reads at most 4 MiB of it
  (`MaxResultBody`, `:21-23`; `server/internal/httpapi/agentapi/agentapi.go:208`).
  On Windows, output that is not UTF-8 is read in the OEM code page
  (`exec_windows.go:158-174`).
* **A run** gets a private folder, `run-*`, under the agent's `work`
  folder, removed when it ends (`agent/jobs/exec.go:41-45`,
  `agent/jobs/worker.go:95`). Its environment is the service's without
  `EASYRMM_` variables, with `TEMP` and `TMP` set to that folder and the
  job's IDs added (`exec_windows.go:51-65`). It runs in a job object,
  assigned just after the process starts (`exec_windows.go:115-137`).
  Four runs go at once (`worker.go:40-41`, `:73-74`), so a query can wait
  behind a hardening run of up to 30 minutes (`HardeningTimeout`,
  `hardening.go:37-38`) or an install.
* **The journal** keeps each run's result until it is reported
  (`agent/jobs/journal.go:25-36`), and reads its files with plain
  `json.Unmarshal` (`:114`): a build that does not know a field of a
  saved result drops it.
* **The agent already reads the registry** in Go, through
  `golang.org/x/sys/windows/registry`: both views of the uninstall keys,
  and the loaded user hives under `HKEY_USERS` whose SIDs start with
  `S-1-5-21-`, skipping `_Classes` (`agent/inventory/windows.go:273-291`).
  It already calls Windows functions that `x/sys` does not wrap, through
  lazily loaded DLLs (`exec_windows.go:22-25`). `x/sys/windows` v0.50.0
  exports `RegOpenKeyEx` with its options, `RegEnumKeyEx`,
  `RegQueryInfoKey` and `RegQueryValueEx`.
* **The agent is built for Windows on x64 and ARM64** (`Makefile:124-130`);
  CI runs the agent's Windows tests on `windows-latest`
  (`.github/workflows/backend-tests.yml:65`).
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
* **Roles** (`server/internal/rbac/rbac.go`): Technicians hold
  `device.terminal`, `device.files`, `script.run` and
  `job.view_sensitive` (`:145-148`); Read-Only holds view permissions only
  (`:125-128`) and "Views devices, alerts and reports without making
  changes" (`:179-183`); `audit.view` starts at Site Administrator
  (`:150-153`). Roles are a fixed catalogue.
* **The audit log** keeps at most 16 KiB of details per record
  (`server/internal/audit/audit.go:72`, `:126`).
* **The console**: a device's tabs
  (`web/src/pages/devices/DeviceDetailPage.tsx:61-70`), where Hardening
  shows for Linux only (`:66-67`); the Jobs page filters by kind
  (`web/src/pages/jobs/JobsPage.tsx:29`, `:48`, `:149`).

**ADR-0063, merged and built.**

* `job.view_sensitive` (`rbac.go:42`), held by Technicians and above, not
  Read-Only ([The permission](0063-who-sees-job-output-and-arguments.md#the-permission)).
* `stdout`, `stderr` and `args` are not granted to `easyrmm_app`; a column
  added to `jobs` or `job_runs` later needs its own grant
  (`server/migrations/00028_job_output_access.sql:64-72`).
* Reads go through `SECURITY DEFINER` functions whose `search_path` ends
  with `pg_temp`: `easyrmm_job_run_output` (`00028:123`),
  `easyrmm_job_arguments` (`:196`) and, for the poll,
  `easyrmm_job_delivery_args` (`:263-271`), each read recorded in its
  transaction (`server/internal/jobs/output.go:87`, `:107`); a test fails
  for any definer function without `pg_temp` last
  (`server/internal/database/definer_integration_test.go:39`).
* Endpoints `GET /api/v1/job-runs/{id}/output`,
  `GET /api/v1/jobs/{id}/arguments` and
  `DELETE /api/v1/job-runs/{id}/output`
  (`server/internal/httpapi/jobsapi/jobsapi.go:36`, `:40-41`).
* Refusals are recorded through `easyrmm_job_refusal` (`00028:84-114`):
  once per caller, action, target and organization in 10 minutes, and at
  most 20 per caller in 10 minutes counted over
  `job_run.output_view` and `job.arguments_view` only (`:104-106`).
* Output is emptied after `EASYRMM_JOB_OUTPUT_RETENTION`, 30 days by
  default, by the purge (`service.go:182`), one time for every kind. The
  ADR names this feature: later kinds such as "the planned registry and
  event log viewers, may need a stricter permission for their output …
  The output endpoint would then ask for both", and retention per kind
  "is built with the first kind that needs it, not before"
  ([Retention](0063-who-sees-job-output-and-arguments.md#retention)).

**[ADR-0065](0065-hardware-health.md)** (accepted): F1's rule of five states
(healthy, unhealthy, unknown, unsupported, unavailable) and *reported* for
what EasyRMM reads and does not judge. *Unavailable* is "the data exists,
but EasyRMM cannot reach it from where the agent runs".

**What Windows offers**, from Microsoft's documentation unless said
otherwise (see [References](#references)):

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
  everything done under a key opened with a flag must use the same flag;
  on ARM64, `KEY_WOW64_32KEY` is the x86 view; "Wow6432Node and
  WowAA32Node keys are reserved" (Accessing an alternate registry view;
  Registry redirector).
* **HKCR and HKCC.** HKCR merges `HKLM\Software\Classes` with the user's
  classes; "Processes running in a security context other than that of
  the interactive user should not use the HKEY_CLASSES_ROOT key", and
  should open `HKEY_LOCAL_MACHINE\Software\Classes` explicitly
  (HKEY_CLASSES_ROOT key). HKCC "is an alias for
  HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current",
  and services should not use HKCU or HKCR (Predefined keys).
* **Loading a hive.** `RegLoadKey` loads under `HKEY_USERS` or
  `HKEY_LOCAL_MACHINE` only, and "The calling process must have the
  SE_RESTORE_NAME and SE_BACKUP_NAME privileges" (RegLoadKeyW). Each
  loaded hive and its file are listed under
  `HKLM\SYSTEM\CurrentControlSet\Control\hivelist` (widely documented, not
  on a Microsoft page cited here: to be confirmed).
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
* **PowerShell.** The Registry provider's drives are `HKLM:` and `HKCU:`
  only, and it takes "a backslash (\\) or a forward slash (/)" between
  levels; unsupported types come back as `Unknown`, "such as
  REG_RESOURCE_LIST values" (about_Registry_Provider; RegistryValueKind).
  Windows PowerShell "automatically logs script blocks when they have
  content often used by malicious scripts", even with script block
  logging off (PowerShell ♥ the Blue Team). That `Add-Type` and
  `DllImport` are among that content, logged as warnings in event 4104,
  is the independent review's finding, to be confirmed. ADR-0060 collects
  4104 (its `windows.powershell` source).
* **Compiling on the computer.** MITRE ATT&CK's T1027.004, *Compile After
  Delivery*, names `csc.exe`, and its detection flags compiling outside
  development environments.
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

* **A Registry tab** on Windows devices, built on **F2**: the registry
  work is Go code in the agent, run as a child process of the agent's own
  program inside the run's job object, given a typed, signed input in a
  file and writing its result to a file, both kept off the command line
  and out of the output streams. No PowerShell.
* **Read-only first** (slice 1): browsing, value reads, bounded search,
  and export as `.reg` or JSON. **Writes** (slice 2): create, change and
  delete keys and values, each item's backup written down before it
  changes, a check that nothing changed since it was read, undo, and
  protected paths behind step-up and the device's name typed. **Import**
  (slice 3) and **bulk changes** (slice 4) after.
* **Refusals enforced three times**: the server checks the request; the
  agent checks it again, and checks the kernel's name of every key it
  opens, never letting Windows follow a link; the server checks the
  result. `SAM`, `SECURITY`, copies of them, and the agents' own keys are
  refused for reading and writing; `REG_LINK` is never written; writes
  never cross a link.
* **Inputs go with their results, and masked values stay masked**: in
  results, backups, inputs, downloads and change views; only a reveal,
  with step-up, shows one.
* **Two permissions**, `registry.view` and `registry.edit`, held by
  Technicians and above; Read-Only gets neither. Reading a result needs
  `job.view_sensitive` as well.
* **Audit**: one record per query and per change; numbers before and
  after, and string data on protected paths, but no other data and no
  hash of any.

### F2: kinds with an input and a result
*Decided in review.* F2 as the plan defines it, made concrete. Features
9, 12 and 8's actions reuse it.

#### A kind
A kind is a Go value in `server/internal/jobs`, one per kind, in one table
the server reads. It names:

* its **executor**: a `script` the server sends, or a `builtin` in the
  agent ([Executors](#executors));
* the platforms it runs on;
* the capabilities the agent must list in `accepts`;
* its input: a Go struct per operation and input version, decoded with
  unknown fields refused, and its checks;
* its result: a Go struct per result version, and the check of a result
  against its input;
* who reads the input and the result: a permission of the kind's own,
  beside `job.view_sensitive`, and whether only the person who asked may
  read them;
* how long the input and result are kept, and how long jobs and runs are
  kept;
* how long a run waits for an offline device, by default and at most;
* its timeout, and whether it runs in the reserved lane;
* whether the Jobs list shows it without a filter;
* its audit record, written by `create` instead of one
  `device.script_run` per run;
* whether it takes the device's change lock (one change at a time).

The three existing kinds are entries of the same table with the values
they have today: a script, no input, no result, output for
`EASYRMM_JOB_OUTPUT_RETENTION`, listed, one record per run. Every entry is
used: the registry's two kinds set each of them.

**Two registry kinds**: `registry_query` (list, value, search, export,
prepare) and `registry_change` (change, undo, import, bulk). Two and not
one, because retention, readers, the change lock and the record differ
between reads and writes, and one kind whose settings depend on the
operation would hide that in code.

#### Executors
*Decided in review.*

* **`script`**: EasyRMM's own script, compiled into the server with
  `go:embed`, is the job's body, kept with its SHA-256 and signed in the
  payload, as `software` and `hardening` are today; its SHA-256 is
  published for EDRs, as ADR-0054 publishes its script's. The script reads
  its input from the file named by `EASYRMM_JOB_INPUT` and writes its
  result to the file named by `EASYRMM_JOB_RESULT`. It suits work that is
  naturally a script (`Get-WinEvent`, `dcdiag`), where PowerShell's own
  logs, `AllSigned` and Constrained Language Mode are acceptable.
* **`builtin`**: Go code in the agent's program, run as a child process of
  that program: `easyrmm-agent.exe builtin registry` on Windows. It suits
  work that needs Windows calls PowerShell reaches only through
  `Add-Type`, or that must run where App Control puts scripts in
  Constrained Language Mode.
  * **The child** gets the run's environment, as a script does: `TEMP`
    and `TMP` in the run's private folder, `EASYRMM_JOB_INPUT`,
    `EASYRMM_JOB_RESULT`, and the job's IDs. Its command line names the
    builtin and nothing else. It runs in the run's job object (assigned
    before it starts once ADR-0060's slice 0 is built), with the run's
    timeout and cancel, and a job-object memory limit of 512 MiB. Its
    standard output and error are captured as any run's, and hold
    diagnostics only.
  * **Why a child and not the agent's own process**: a hang, a crash or a
    runaway allocation in registry code (a key with millions of values, a
    driver's registry filter that blocks) ends the child, not the agent;
    the job object stops it like any run; and the agent's own memory never
    holds registry data.
  * **Its job row** has an empty body and SHA-256, and the builtin's name
    in a new column `jobs.builtin`; a constraint ties each kind to its
    executor. Each run records the agent's version that ran it (the
    result's `agentVersion`) and the build's SHA-256 the device reported
    when the run was delivered (`devices.agent_sha256`).
  * **What signs it**: the payload is signed with the job key as any job;
    the code is the agent's own, signed and updated as the agent is
    (ADR-0027).
* **Features 9, 12 and 8 choose** their executor in their ADRs. This ADR
  builds `builtin` and what both share; `script` is built by the first
  kind that chooses it, not before.

#### Capabilities, versions and older agents
Gated as ADR-0064 gates `job.pwsh`
([Older agents and the poll](0064-remote-powershell-management.md#older-agents-and-the-poll)):

* **`job.structured`**: the agent takes the payload's `input`, `lane`,
  `executor` and `builtin`, sets the two variables, reads the result file,
  sends `result`, and keeps the reserved lane. Every F2 kind needs it.
* **`builtin.<name>.v<N>`**, one per input version a build reads, such as
  `builtin.registry.v1`. A builtin kind needs `job.structured` and one of
  its versions. The server writes the highest input version that both it
  and the device's build know, and parses every result version it knows.
* **The claim** delivers an F2 run only in answer to a poll whose
  `accepts` lists what the kind needs; otherwise the run stays queued, then
  expires with the reason. Creating a registry job for a device whose list
  lacks it is refused: "PC-12's agent cannot open the registry editor;
  update the agent".
* **No fallback.** An agent without `builtin.registry` does not get the
  editor; nothing else does the work for it.
* **Builds differ.** An agent may be older or newer than its server
  (ADR-0009). Each side applies the rules it was built with
  ([One set of rules](#one-set-of-rules)); the server's checks of requests
  and results hold for every agent.
* **An older agent's strict decoder** would refuse the new payload fields
  (`agentproto/jobs.go:164`), which is why they reach only agents that
  list them.

#### The input
* **A JSON object**: `v`, `op`, and the operation's fields: hive, view,
  path, value name, limits, cursor, data to write, the state expected
  before a write, whether a protected path was confirmed, the backup an
  undo restores.
* **Checked by the server** when the job is created: decoded strictly,
  each field against its rules ([Paths, links and
  refusals](#paths-links-and-refusals), [Types, encoding and
  limits](#types-encoding-and-limits)) and the refusals; **and again by
  the agent**, against the rules it was built with.
* **Kept in a table of its own, `job_inputs`**, one row per job: the input
  (`jsonb`), its size, when it was stored and when it was removed. Not in
  `jobs`, which is written once and which `easyrmm_app` cannot update
  (`database.md:89`): an input must be emptied with its results (below).
* **Masked data is not in it.** Data a person types for a masked value is
  kept apart ([Masked values](#masked-values)); the input holds a
  reference.
* **An undo carries no data**: its input names the backup on the server,
  by change and item. The claim builds the agent's input from the backup
  when it signs the payload.
* **Delivered off the command line.** The payload gains `input`: the
  input's exact bytes, base64-encoded, signed with the rest. The agent
  writes them to `input.json` in the run's private folder and sets
  `EASYRMM_JOB_INPUT` to its path. Process auditing and other processes
  see the agent's program and the word `registry`, and no data.

#### The result
* **A file of JSON lines**, at the path in `EASYRMM_JOB_RESULT`: each line
  one JSON object, UTF-8, the file at most 2 MiB. The first line names the
  version and the operation; the last, `end`, says the work finished.
  Between them, for a change, each item's **backup line is written and
  flushed to disk before that item is changed**, and its outcome line
  after.
* **The agent sends what is there, however the child ended**: on exit,
  timeout, cancel or crash, it reads the complete lines (a cut last line
  is dropped) and sends them as `result`, base64-encoded, in the result
  request. A result without `end` is partial, and says so.
* **The server** decodes it strictly into the kind's result for its
  version and checks it against the input: the operation, hive, view, path
  and cursor; counts within the input's limits; every path in it outside
  the refusals; no masked data where none may be. It stores it in a new
  column, `job_runs.result` (`jsonb`), after moving any backup of a masked
  value into the masked store. A result that does not match fails the run
  with the reason and is not stored; one that holds a refused path is also
  recorded as `registry.refused_on_device` ([Links](#links)).
* **A change with no result, or a partial one, is never shown as
  failed.** Items with an outcome line show it; items with a backup line
  and no outcome, and a change whose result never came, show *unknown: may
  have been applied*, with the backup where there is one, so that undo is
  still possible. A query without a result is *Unknown*.
* **Not standard output.** Output is cut to its head and tail and read in
  the OEM code page when it is not UTF-8 (Context), and is shown under
  ADR-0063's output rules for every kind. A result needs rules of its own.

#### Older builds and the result
* **An older agent build reading the journal** (after an update rolled
  back, ADR-0027) decodes it with plain `json.Unmarshal`
  (`journal.go:114`) and drops `result`, then reports the run without it.
  The server treats an F2 run reported without `result` like one whose
  result never came: *unknown: may have been applied* for a change,
  *Unknown* for a query.
* **An older server** ignores `result`, as ADR-0009's level 2 ignores
  request fields it does not know. It never created the run unless it was
  this server before a rollback, and the host updater's rollback restores
  the database as it was (ADR-0052).

#### Sizes, and why one run cannot block a device
* **The input is at most 1 MiB**, as JSON; an undo's input is measured
  with the backup the claim will put in it, which fits, since a backup is
  at most 512 KiB ([Backup and undo](#backup-and-undo)).
* **The signed job is bounded on its real bytes when the job is
  created**, for every kind. The server builds the payload as the claim
  will, with the run's fields at their longest, marshals it with
  `json.Marshal` (which escapes `<`, `>` and `&` in strings, so one
  character can become six) and base64-encodes it as `SignJob` does
  (`agentproto/jobs.go:146-153`), and refuses the job if the signed job
  passes 2 MiB. The size is kept on the job. An input of 1 MiB, base64 in
  the payload and base64 again around it, is about 1.8 MiB. Today's kinds
  stay far below it: library scripts are at most 64 KiB
  (`MaxBody`, `server/internal/jobs/service.go:27`), EasyRMM's own at most
  512 KiB.
* **The claim fills an answer by size and order** (it changes
  `delivery.go:53-64`):
  * quick runs first, then queued runs, oldest first, up to 8 runs and
    6 MiB of signed jobs; at least one run, which always fits;
  * **a run being sent again** (delivered over `RedeliverAfter` ago and
    not started) goes in an answer of its own, never with others, so a run
    whose answer the agent could not take never holds others back with it;
  * **a run delivered 5 times without starting fails**: "the agent did not
    take it after 5 deliveries".
* **So no answer can pass the agent's 8 MiB**: each signed job is at most
  2 MiB, an answer at most 6 MiB of them plus their framing; a run that
  fails for any other reason fails alone, at most 5 times.
* **The result body.** The server's `MaxResultBody` grows from 4 MiB to
  8 MiB: both streams as today, and a 2 MiB result base64-encoded. The
  agent builds the whole result request and checks it against
  `MaxResultBody` before sending; if it would pass, it drops result lines
  from the end, never the first or a backup, and marks the result cut, so
  the items whose outcome was dropped show *unknown: may have been
  applied*.
* **The reserved lane.** The payload's `lane: "quick"` marks a run of at
  most 60 seconds, which `VerifyJob` checks. The agent keeps 2 slots for
  quick runs beside its 4 (`worker.go:40`), so a registry read never waits
  behind an install or a hardening run. Every registry job is quick.
  Decided in review, as the plan left it to this ADR: without it the
  editor can wait half an hour on a busy computer.

#### Who reads, how long, what is recorded
* **The database guards the data**, by ADR-0063's rule: `easyrmm_app` is
  not granted `SELECT` on `job_inputs.input`, `job_runs.result`, or the
  masked store's data. Sizes and times (`input_bytes`, `result_bytes`,
  `result_stored_at`, `result_removed_at`) are granted, kept by triggers
  as ADR-0063 keeps `stdout_bytes`.
* **Reads go through `SECURITY DEFINER` functions** owned by
  `easyrmm_owner` with `search_path = pg_catalog, public, pg_temp`, which
  ADR-0063's test checks for every such function. A new
  `easyrmm_job_run_result` checks the caller's `job.view_sensitive` scope,
  the kind's permission scope and, for kinds read by the asker only, that
  the caller asked; writes the kind's record where it records reads; and
  returns the result, in the request's transaction. ADR-0063's
  `easyrmm_job_arguments` returns the input beside `args` under the same
  checks, the asker rule included. The poll reads inputs through
  `easyrmm_job_delivery_args`, which gains the input and, for a write or
  an undo, the masked data and backups it needs.
* **Endpoints**, answering as ADR-0063's output endpoint does (`404` for a
  run the caller cannot see, with no record; `403` recorded as denied
  within the bound; `409 run_open`; `409 result_removed`; `200`):
  * `GET /api/v1/job-runs/{id}/result`;
  * the input, through ADR-0063's `GET /api/v1/jobs/{id}/arguments`;
  * removal, per kind: for registry changes, `registry.data_remove`
    ([Backup and undo](#backup-and-undo)).
* **Inputs are kept and removed with their results.** The purge empties
  a job's input at the same time as its runs' results, after the kind's
  time, counted from when its last run ended; a removal empties both. No
  input outlives its results, and none is read more widely than they are.
* **Per kind.** ADR-0063's purge gains the kind in its condition and a
  time per kind; W2's job retention per kind gains these two kinds:

| | `registry_query` | `registry_change` |
|---|---|---|
| Executor | `builtin` (`registry`) | `builtin` (`registry`) |
| Input and result kept | 1 hour (the hourly purge empties them within 2) | `EASYRMM_JOB_OUTPUT_RETENTION` (30 days by default) |
| Job and runs kept | 7 days | `EASYRMM_JOB_RETENTION` (90 days by default) |
| Input and result read by | the person who asked, holding `registry.view` and `job.view_sensitive` at the device's site | anyone holding `registry.view` and `job.view_sensitive` at the device's site |
| Each read recorded | no: only the asker reads them, and the query's own record covers it | yes, `registry.change_view` |
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

### The registry builtin
*Decided in review.*

* **Go, in the agent**: a package `agent/registry`, built for Windows on
  x64 and ARM64, run as `easyrmm-agent.exe builtin registry`.
* **Calls**: `RegOpenKeyEx` with `REG_OPTION_OPEN_LINK`, `RegEnumKeyEx`,
  `RegQueryInfoKey` and `RegQueryValueEx` from `x/sys/windows`;
  `RegEnumValueW`, `RegCreateKeyExW`, `RegSetValueExW`, `RegDeleteValueW`,
  `RegGetKeySecurity` and `RegSetKeySecurity` from `advapi32.dll`, and
  `NtQueryKey` and `NtDeleteKey` from `ntdll.dll`, loaded lazily as the
  agent already loads `kernel32.dll` (`exec_windows.go:22-25`). The
  inventory's `registry` package is not used here: it opens keys without
  `REG_OPTION_OPEN_LINK`.
* **Native only.** The child checks with `IsWow64Process2` that it runs as
  the machine's own architecture, and stops otherwise, since an emulated
  or 32-bit process would see other views.
* **No PowerShell**: so no script block (4104) or module (4103) records,
  no `csc.exe`, and nothing for `AllSigned` or Constrained Language Mode
  to stop. What an EDR sees is the agent's own program reading the
  registry as SYSTEM, which MSPs already allow.
* **No privileges enabled**: the backup and restore privileges stay off,
  so Windows' permissions hold ([Writes](#writes)).

#### One set of rules
The path parser, the refused, protected and masked rules, and the
comparison are one Go package, `internal/registryrules`, beside
`internal/agentproto`, compiled into both the server and the agent. One
implementation, so the two checks cannot read a path differently. A
server and an agent of different releases may carry different rules: the
server applies its own to every request and result, the agent its own on
the computer, and the result names the rules' version it used. A rule
added in a release therefore holds on the server at once, and on the
computer once the agent updates.

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
* **Comparing.** Names are compared after mapping each character to every
  character Unicode's simple case mappings make it equal to, so `ſ`, `ı`
  and the Kelvin sign `K` match `S`, `I` and `K`. This may refuse an odd
  name Windows would treat as different, which costs nothing. On the
  computer the agent then compares the kernel's name of the key it opened,
  which is the name as stored.

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

* **Copies loaded under other names.** At the start of every run the agent
  reads `hivelist`. A hive whose file is named `SAM` or `SECURITY`, with
  any extension or none, in any folder (`sam.save`, `SECURITY.hiv`), is
  refused wherever it is mounted. And before reading any key of a hive
  that is not one of Windows' own, the agent looks at the hive's root: one
  holding `SAM\Domains` or `Policy\Secrets` is refused, so a copy renamed
  to anything is refused too.
* **Why reads too.** What the editor reads is stored on the server, in
  its database and its backups, and shown to people. Password hashes, LSA
  secrets and the agents' enrolment and trust data must not land there.
  The agents' keys are refused for reading as well, so that the editor
  does not show the server's address and trusted certificate to someone
  planning to point agents elsewhere, and so that the rule is one rule.
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
* **Which.** String, binary and other non-number values whose name holds,
  without regard to case, `pass`, `pwd`, `secret`, `token`, `auth`,
  `cred`, `psk`, `cookie`, `apikey`, `api_key`, `accesskey`,
  `privatekey`, `private_key` or `connectionstring`, and every value named
  `DigitalProductId` (a product key, encoded). Example:
  `Winlogon\DefaultPassword`, kept in plain text and readable remotely by
  Authenticated Users (Microsoft). DWORD and QWORD values are not masked:
  numbers named like that are settings (`PasswordExpiryWarning`). The list
  masks some harmless strings (`Author`, `Bypass`); a reveal shows them.
* **Masked everywhere.** A masked value's data is in no list, value read,
  search match, export or prepare: the agent returns its type and size
  only, and the console shows *Masked*. Where the data must reach the
  server, it is kept apart, in a store of its own (`registry_masked_values`:
  the value's device, job, run, path and name, its type, its data and
  when it was stored and removed), which `easyrmm_app` cannot read:
  * the data a person types for a masked value: the change's input holds a
    reference;
  * a masked value's backup: the agent marks it, and the server moves it
    into the store before it stores the result, which then holds a
    reference.

  So inputs, results, backups, change views and `.reg` downloads all show
  *Masked*. If the server's rules mask a name that an older agent's do
  not, the server drops that data from a read's result, and moves it from
  a backup, on receipt.
* **Reveal**, from slice 2, once step-up exists: one value at a time, for
  a holder of `registry.view` whose session stepped up (ADR-0055), through
  a definer function that reads the store and records `registry.reveal` in
  the same transaction; for a value on the computer, through a `value` read
  marked as a reveal. Nothing else shows masked data.
* **Search never matches inside masked data.**
* **Masking is a net, not a boundary.** Secrets under other names (SNMP's
  community names, which are value names) are shown. A holder of
  `registry.view` also holds `script.run` and could read them anyway
  ([Permissions](#permissions)).

#### Links
* **The agent never lets Windows follow a link.** It opens a path one name
  at a time from the hive's root, each with `REG_OPTION_OPEN_LINK` and the
  view's flag, and asks each key it opened whether it is a link (a
  `SymbolicLinkValue` of type `REG_LINK`).
* **For reads, the agent follows a link itself** only when the target,
  parsed as a text path, passes the refusals and stays in the hive it
  starts in: the machine's hives to the machine's, or one user's
  `HKU\<SID>` and `HKU\<SID>_Classes` between themselves. Otherwise the
  link is listed with its target, *not followed*.
* **Writes never cross a link**, but for Windows' own, followed only after
  the agent reads each one's target and the kernel's name it reaches and
  finds them as Windows makes them: `CurrentControlSet` to a
  `ControlSetNNN` under `SYSTEM`; HKCC's alias to `Hardware
  Profiles\NNNN` under that control set; a user's `Software\Classes` to
  that user's `HKU\<SID>_Classes`. A write whose path crosses any other
  link is refused, naming it.
* **The kernel's name of every key the agent opens** is read (`NtQueryKey`,
  `KeyNameInformation`) and checked against the refusals, and for a write
  against the protected paths, before anything is read from it or written
  to it. A key that resolves into a refused key is refused even when every
  name on the way looked allowed.
* **A refusal the server did not make** (the agent refused a path the
  server let through, or a kernel's name was refused, or a write reached a
  protected key by another name) is recorded as
  `registry.refused_on_device`, with the path asked for, the rule and the
  kernel's name, and shown on the device's page. Either the server's check
  missed a spelling, a bug to fix, or someone put a link there.
* **Writes never make links**: no `REG_OPTION_CREATE_LINK` and no
  `REG_LINK` value, from the editor, an import or a bulk change.
* **Creating keys.** Each missing name is created with `RegCreateKeyExW`
  under the parent the agent opened and checked, and the new key's kernel
  name is checked before any value is written. A link made in the moment
  between the check and the create, by a user in their own hive, can at
  worst create one empty key where it points; the result reports it.
* **Deleting keys goes through handles.** The agent opens each key to
  delete with `REG_OPTION_OPEN_LINK`, `DELETE` and the view's flag; checks
  it is not a link and its kernel name is the one in the backup; and
  deletes it through that handle (`NtDeleteKey`), deepest first.
  Microsoft documents it for drivers, as `ZwDeleteKey`; its behaviour
  from user mode on a handle opened this way is to be confirmed on the
  runners ([Testing](#testing)). A link
  swapped in after the backup was taken is caught by the check, and the
  delete stops. Deleting by name (`RegDeleteKeyEx`) would open the name
  again, following whatever is there now, so it is not used. A key whose
  subtree holds a link is not deleted.
* **Whether a standard user can make a link** in their own hive, or under
  a key of the machine whose permissions let users create subkeys, and
  whether Windows follows a link from a user's hive into the machine's,
  is to be confirmed on the runners ([Testing](#testing)). This design
  does not depend on the answer.

#### Protected paths, for writes
Writing under these, in either view, in every spelling, and wherever the
kernel's name shows a write has landed, needs step-up and the device's
name typed ([Writes](#writes)):

* `HKLM\SYSTEM\<control set>\Services` and `…\Control`: services'
  programs and accounts, LSA, Session Manager, start-up;
* `HKLM\BCD00000000`: boot configuration;
* under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`: `Winlogon`,
  `Image File Execution Options`, `SilentProcessExit`, and `Windows`
  (`AppInit_DLLs`);
* `Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` and
  `RunOnceEx`, the machine's and each user's;
* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`;
* `Classes\CLSID`, the machine's (`HKLM\SOFTWARE\Classes\CLSID`) and each
  user's (`HKU\<SID>_Classes\CLSID`);
* `HKLM\SOFTWARE\Microsoft\AMSI\Providers`;
* `HKLM\SOFTWARE\Microsoft\Netsh`;
* `HKLM\SOFTWARE\Microsoft\Cryptography\OID`;
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels`;
* `HKLM\SOFTWARE\Microsoft\Windows Defender` and
  `HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection`;
* every key named `Policies`, and under it: Group Policy and MDM write
  there and set edits back;
* deleting a key one or two levels under a hive's root (such as
  `HKLM\SOFTWARE` or `HKLM\SOFTWARE\Microsoft`).

**Checked on the computer too.** The server decides from the path asked
for whether it is protected, and only then puts `protectedConfirmed` in
the signed input, after the step-up and the typed name. The agent checks
the kernel's name of every key it writes against the same rules, and
refuses a write that lands on a protected key without that flag.

This is not every place that can start code or blind a defence, of which
there are hundreds; it holds the common ones, and grows by amending this
ADR.

### Hives and users
*Decided in review.*

* **HKLM**: its keys, with `SAM` and `SECURITY` refused, and any other
  hive mounted there checked as above.
* **HKU**: every loaded hive: `.DEFAULT`, `S-1-5-18`, `S-1-5-19`,
  `S-1-5-20`, and each user's SID with its `_Classes`. Named from the
  profile list (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>`)
  and the SID's translation, for local and domain accounts (`S-1-5-21-…`)
  and Microsoft Entra ID accounts (`S-1-12-1-…`, to be confirmed). The
  inventory reads only `S-1-5-21-` (Context); the editor lists every
  loaded hive.
* **HKCU.** The agent runs as SYSTEM, whose HKCU is `HKU\S-1-5-18`, and
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
*Decided in review.*

* **Both views**, 64-bit (`KEY_WOW64_64KEY`) and 32-bit
  (`KEY_WOW64_32KEY`, the x86 view on ARM64), chosen per tab and named in
  the header: *64-bit view* or *32-bit view*, and the physical key from
  the kernel's name (`HKLM\SOFTWARE\WOW6432Node\Vendor`). A key the two
  views share says so: both kernel names are the same.
* **Every open and create** under a key uses the view's flag, as Microsoft
  requires; deletes go through handles opened with it ([Links](#links)).
* `WowAA32Node` (ARM32 programs) is shown as a key, not as a view.
* **Data is written as given.** WOW64 rewrites `%ProgramFiles%` in
  `REG_SZ` data written by 32-bit programs; the agent runs natively and
  relies on no rewriting.

### Types, encoding and limits
*Decided in review.*

* **Read raw**: the type's number and the bytes, from `RegEnumValueW`;
  never expanded, never converted.

| Type | In the result | Editable |
|---|---|---|
| `REG_SZ`, `REG_EXPAND_SZ` | `text`: the UTF-16LE bytes as text, one terminating NUL dropped; never expanded | Yes |
| `REG_MULTI_SZ` | `items`: an array of strings | Yes; an empty item or a NUL in one is refused |
| `REG_DWORD` | `number`, 0 to 4,294,967,295; the console shows hex too | Yes |
| `REG_QWORD` | `decimal`, a string, since JavaScript's numbers lose precision past 2^53; hex too | Yes |
| `REG_BINARY` | `base64`; the console shows hex | Yes |
| `REG_NONE`, `REG_DWORD_BIG_ENDIAN`, `REG_LINK`, the resource lists, any other number | `base64` with the type's name or number | No |

* **No NUL and no lone surrogate ever goes into JSON.** PostgreSQL's
  `jsonb` refuses `\u0000` and does not accept a lone surrogate, and Go's
  JSON encoder replaces invalid text. So a name or a string holding a NUL
  or a lone surrogate, data with no terminator or an odd length, a DWORD
  that is not 4 bytes, and a `REG_MULTI_SZ` with an empty item, are sent
  as `raw` (base64 of the bytes) with a `display` text in which each such
  character is written as a visible escape, and a flag. They are
  read-only, so that no one saves bytes they did not see. The server's
  decoder refuses a result with a `\u0000` or a lone surrogate escape
  anywhere.
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
*Slice 1. Decided in review.*

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
*Slice 1. Decided in review.* From a chosen key, in one view:

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
  password someone is looking for. The term is in the query's input,
  which only the person who asked reads, and which goes after an hour.

### Export
*Slice 1. Decided in review.*

* **One `registry_query` `export`** of a key and its subtree in one view,
  at most 5,000 keys and 2 MiB of result; a larger one is refused,
  *export a smaller key*. One run, not pieces put together, so the file is
  one reading.
* **JSON**: the result as it is, with the device, the view, the time and
  the agent's version.
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
*Decided in review.* ADR-0065's words, as the registry needs them.
EasyRMM does not judge registry values, so there is no healthy or
unhealthy.

* **Reported**: read this time, with *Read at*.
* **Unavailable**: Windows denied SYSTEM access (*access denied*); the
  agent cannot open the editor (*update the agent*).
* **Unknown**: the device did not answer within the wait, the run timed
  out, the agent stopped while it ran, or the result was malformed or
  missing; with the reason. For a change: *unknown: may have been
  applied*.
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
  `prepare`: the value or subtree as it is, masked values masked; the
  key's last-write time; whether Windows hardening's manifest lists the
  value (W2); whether the path is protected; and the owner, from ADR-0054's
  ownership reader (`internal/winpolicy`, W1: an owner and its policy,
  none, or cannot tell; see
  [Managed elsewhere](0054-hardening-windows-computers-and-servers.md#managed-elsewhere)).
  W1's reader is a PowerShell script the agent carries for *Configure
  logging*; the builtin starts it as a child of its own with the values'
  paths in a file, and where PowerShell cannot run it, the owner is *cannot
  tell*, shown as a warning.
* **The dialog names the device** (name, organization, site, last seen),
  the view and the physical key, the value before and after, and the
  warnings: *set by Group Policy (policy …); it will set this back*; *the
  owner cannot be told*; *Windows hardening set this; changing it leaves
  hardening's undo for this value*. A protected path needs step-up and the
  device's name typed; every other write is confirmed with a button in
  that dialog.
* **Checked before writing.** The change carries what the prepare saw:
  for a value shown, its type and its data's SHA-256; for a masked value
  or a key, the key's last-write time. The agent refuses, *changed since
  you looked*, when that differs, and the console reads again. The
  SHA-256 is in the change's input, under the input's rules, never in a
  record.
* **One run**: the agent checks, writes each item's backup line, changes
  the item, reads it back, and writes its outcome line. No backup, no
  write.
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
* **Step-up is a safeguard against mistakes.** On protected paths and bulk
  changes it makes the person confirm, with a second factor, a change
  whose damage is large or wide, and it covers a session left open on a
  shared screen. It is not a boundary against a Technician, who holds the
  terminal.
* **No approvals.** A second person's approval (F5) is not asked for.
  ADR-0064 puts step-up on one-off commands because one request reaches
  500 computers; a single-device registry write reaches one, as the
  terminal does. Bulk changes need step-up for every job.
  [Owner question](#owner-questions) 3.

### Backup and undo
*Slice 2. Decided in review.*

* **What is kept.** A value: its type and data before, or *absent*. A
  created key: *absent*. A deleted key: its subtree's keys and values and
  each key's permissions (its DACL as SDDL) and kernel name, at most 1,000
  keys and 512 KiB of backup as JSON, so that its undo always fits in one
  input. A larger subtree, one with a key the agent
  cannot read, or one holding a link, is not deleted (*too large to back
  up*, *cannot be read whole*, *holds a registry link*). Owners and class
  names are not kept and not restored.
* **Written down before the change.** Each item's backup line is written
  and flushed to the result file before the item changes
  ([The result](#the-result)), so a crash, a timeout or a kill leaves the
  backup of every item that may have changed, and the server keeps it.
* **Where.** In the change's result, masked values in the masked store,
  for `EASYRMM_JOB_OUTPUT_RETENTION`; downloadable as `.reg`, with masked
  values left out and named in comments.
* **Undo** is a change whose input names the backup on the server, by
  change and item, and carries no data; the claim puts the backup's data
  into the signed payload. It expects the state the change left and
  refuses, *changed since*, unless the person confirms *undo anyway*. A
  deleted key is created again with its values, and its permissions are
  set last, deepest key first. A created key is deleted only while it is
  still empty. Undoing a masked value needs step-up; its data goes back
  without being shown. Undo is a `registry_change` with the same checks,
  and is recorded.
* **Undo is offered only while the change's result is kept**: 30 days by
  default. After that the change's row stays, with what changed and who
  changed it, and no data.
* **Removing a change's data** (`registry.data_remove`): the input, every
  run's result and the masked values, at once; undo goes with them. By a
  holder of `registry.edit`, `job.manage` and `job.view_sensitive` at
  every run's site, **who is not the change's author**: whoever made a
  change cannot erase what it did, and another holder can, for a secret
  written by mistake.

### Import
*Slice 3. Decided in review.*

* **A `.reg` file** of at most 256 KiB: `Windows Registry Editor Version
  5.00` in UTF-16LE with a byte order mark, or in UTF-8; `REGEDIT4` only
  when it is ASCII. Parsed on the server into at most 2,000 operations:
  keys, values, `[-key]` and `"name"=-` deletes. Each path goes through
  the same parser and refusals. Data types: the six editable ones and
  `hex(0)` (`REG_NONE`, which Windows' file associations use, to be
  confirmed). `hex(6)` (`REG_LINK`) and every other type are refused,
  naming the line. Data for masked names goes into the masked store.
* **Preview**: a `prepare` for every key and value the file touches,
  shown as differences (added, changed, deleted, unchanged), with Writes'
  warnings and protected paths; step-up if any is protected.
* **Apply**: one `registry_change` with every operation, in order, each
  backed up first. On a failure the run puts back what it already changed,
  from its backups, in reverse, and reports each item. One record,
  `registry.import`, with the counts and the first 20 paths; one change row
  per item.

### Bulk changes
*Slice 4. Decided in review.*

* **One change or one import across devices**, chosen as ADR-0064's
  [targets](0064-remote-powershell-management.md#targets) are
  (organization, site, group or a selection; at most 500), with
  `registry.edit` checked at each device's site. Devices that are not
  Windows, and agents without the capabilities, are left out and counted.
* **Step-up for every bulk job.** The confirmation names the scale (*Set
  `…\Foo` to 1 on 312 devices in 3 sites?*), and the count is typed.
* **No check before writing** (there is no prepare per device): each run
  writes its backups first and reports before and after. *Undo on all*
  creates an undo per device, each with its own check.
* **Recorded** as one `registry.change` per organization with the device
  count (W2's rule), and one change row per device.

### Permissions
*Decided in review.*

* **`registry.view`**: browse, read values, search, export, read changes.
  **`registry.edit`**: create, change, delete, import, undo, bulk. Each is
  checked at the device's site. Reading an input or a result needs
  `job.view_sensitive` as well; ADR-0063 foresaw a stricter permission for
  this kind of output, and that "the output endpoint would then ask for
  both".
* **Technicians and above hold both; Read-Only holds neither.**
* **Least privilege, and why Technicians.** A Technician already holds
  `device.terminal` and `script.run` at the same sites (`rbac.go:145-148`):
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
| `registry.change` | a change, an undo or a bulk change is created | device (for bulk, the device count, one record per organization), hive, view, path, value name (its first 1,024 characters), operation, type and size before and after; for `REG_DWORD` and `REG_QWORD`, the number before and after; on a protected path, string data before and after, each cut to 1,024 characters, never for a masked name; whether protected, when the session stepped up, the warnings shown, the change it undoes |
| `registry.import` | an import is created | counts by operation, the first 20 paths, the file's size |
| `registry.change_view` | a change's data is read | the change, the sizes |
| `registry.data_remove` | a change's data is removed | the change, the sizes removed |
| `registry.refused` | the server refuses a request for a refused path | the path and the rule, within ADR-0063's bound (below) |
| `registry.refused_on_device` | a result shows the agent refused what the server allowed, or holds a refused path | the path asked for, the rule, the kernel's name; the system as actor, and the person who asked in the details |

* **Every read and every write is recorded.** Data mostly is not: the
  audit log outlives results, is forwarded (ADR-0023) and is read by every
  holder of `audit.view`, and values can be secrets. A SHA-256 does not
  help: it confirms a guess, and a DWORD has only 2^32 values (ADR-0064's
  rule for one-off commands). So the plan's "old and new data's size and
  SHA-256" becomes type and size, with two exceptions that make changes
  traceable:
  * **numbers** (`REG_DWORD`, `REG_QWORD`), before and after: they are
    settings, which is why masking leaves them alone;
  * **string data on protected paths**, before and after, cut to 1,024
    characters each and never for a masked name: a service's program, a
    `Run` entry or a debugger set under Image File Execution Options is
    what an investigation looks for first.

  Other data before and after is kept with the change and read with
  `registry.change_view`, while the change's result is kept.
* **Refusals are bounded.** A new migration in slice 1 replaces
  `easyrmm_job_refusal` (`00028:84-114`) so that its count of 20 per caller
  in 10 minutes (`:104-106`) includes `registry.refused`, beside
  `job_run.output_view` and `job.arguments_view`; the once per caller,
  action, target and organization in 10 minutes holds as it does.
* **Changes have a table of their own**, `registry_changes`: one row per
  item (device, run, hive, view, path, value name, operation, outcome,
  types and sizes, the change it undoes), written when the result arrives,
  written once, under row-level security, with no data. The device's
  *Changes* list and the audit records point to it.
* **The count a query returned is on its run**, not in its record, which
  is written when the query is created, as `device.script_run` is.

### Offline devices, timeouts and huge keys
*Decided in review.*

* **Offline.** The tab says when the device was last seen and sends no
  reads while it is offline. A read sent to a device that then stops
  answering is *Unknown* after 2 minutes. A single change waits 15
  minutes, then expires with the reason, and nothing changes. A bulk
  change waits 1 hour by default, at most 7 days; there is no check before
  writing, and the backups still hold.
* **A change that ran while the console was away** is reported by the
  agent's journal when it reconnects (`journal.go:34-36`); the change
  shows as made from then, and the agent never runs it twice.
* **Timeouts.** Each run has 60 seconds. The builtin stops itself at 45
  seconds for search and export and at 30 for the rest, and writes what it
  has, rather than being stopped with nothing; if it is stopped anyway,
  the lines it wrote are sent ([The result](#the-result)).
* **Huge keys** page by name ([Browsing](#browsing)); HKCR's and
  `Installer`'s thousands of subkeys page like any other. Slice 1 measures
  a key with 100,000 subkeys.

### The console
*Decided in review.*

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
  `registry.change_view`, masked values masked, and Undo while it is
  offered.

### Linux
*Decided in review.* No registry, and no tab; the API answers
*unsupported*. Linux's nearest equivalents are out of scope: `sysctl`
values are Linux hardening's ([ADR-0051](0051-hardening-linux-computers.md)),
and files under `/etc` and `dconf` are reached through the terminal and
scripts. The requirement names Windows only.

### Not chosen
* **A Windows PowerShell 5.1 script with an `Add-Type` C# helper**, the
  first draft of this ADR:
  * Windows PowerShell logs script blocks with content "often used by
    malicious scripts" even with script block logging off, and ADR-0060
    collects 4104; the review found `Add-Type` and `DllImport` among them,
    as warnings (to be confirmed);
  * `powershell.exe` running as SYSTEM and starting `csc.exe` is what
    detections for *Compile After Delivery* (MITRE T1027.004) look for;
  * App Control and AppLocker put scripts in `ProgramData` in Constrained
    Language Mode, which refuses `Add-Type`: the editor would be missing on
    the best-managed fleets;
  * it compiles again on every click;
  * module logging (4103), where turned on, records cmdlets' parameters,
    so data passed through cmdlets could reach the logs.
* **.NET's `RegistryKey`, from PowerShell or not**: follows links unseen,
  and reports `REG_LINK` and the resource lists as `Unknown`.
* **PowerShell calling Windows through `Reflection.Emit`** (defining
  P/Invoke methods at run time): no `csc.exe`, but a pattern AMSI and EDRs
  watch for, and still refused in Constrained Language Mode.
* **PowerShell's Registry provider**: splits names on `/`, which a name
  may hold; reads wildcards in paths unless given `-LiteralPath`; has
  drives for HKLM and HKCU only; follows links.
* **`reg.exe` and WMI's `StdRegProv`**: text to parse, links followed, no
  kernel names.
* **A compiled helper library carried in the job** and loaded from bytes:
  what malware does.
* **Running the registry code in the agent's own process**: no job object
  around it, so a hang or a crash in it would stop the agent.
* **A script for older agents, beside the builtin**: two implementations
  of the same refusals, one of them with every problem above. Older agents
  do not get the editor.
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
* **Inputs, results and backups stay in database backups** made while they
  were kept, as ADR-0063 says of output.
* **Group Policy and MDM set back** what they own; the editor warns.
* **Rules reach the computer with the agent's update**: a refusal added in
  a release holds on the server at once, and in the agent's own check once
  it updates.
* **The owner warning depends on PowerShell**: where W1's reader cannot
  run, it says *cannot tell*.

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
| Delete registry keys | Writes; Backup and undo (slice 2) | New: subtrees up to 1,000 keys and 512 KiB, none holding a link, deleted through checked handles |
| Search registry keys and values | Search (slice 1) | New, bounded by depth, matches, keys and time |
| Export registry keys | Export (slice 1) | New: `.reg` and JSON, up to 5,000 keys |
| Import registry data | Import (slice 3) | New: `.reg` with a preview; `REG_LINK` refused |
| Refresh registry information | Browsing (slice 1) | New: Refresh and *Read at* |
| REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_EXPAND_SZ | Types | Read in slice 1, written in slice 2 |
| HKEY_LOCAL_MACHINE | Hives and users (slice 1) | New, without `SAM`, `SECURITY` or copies of them |
| HKEY_CURRENT_USER | Hives and users (slice 1) | Each loaded user's hive; users not signed in deferred (Owner questions) |
| HKEY_USERS | Hives and users (slice 1) | Every loaded hive, named |
| HKEY_CLASSES_ROOT | Hives and users (slice 1) | The computer's classes and each loaded user's; the merged view not computed |
| HKEY_CURRENT_CONFIG | Hives and users (slice 1) | Through its alias |
| Support 32-bit and 64-bit registry views | Views (slice 1) | Both; the x86 view on ARM64 |
| Clearly identify which registry view is being accessed | Views; The console | The view and the physical key on every page |
| Respect Windows registry permissions | Writes | As SYSTEM, with no privilege enabled, no ownership taken, no permissions changed |
| Handle inaccessible keys and access-denied errors | States | *Unavailable: access denied*, per key and value |
| Safeguards before deleting or modifying important keys | Paths, links and refusals; Writes | Refused paths; protected paths behind step-up and the device's name typed, checked on the computer too; owners' warnings; checked before writing; backups written first |
| Allow exporting a key before modifying it | Export; Backup and undo | *Export this key first*, and a backup in every change |
| Record registry modifications in the audit history | Audit | `registry.change`, `registry.import` and change rows; numbers and protected strings in the record, other data kept with the change |
| Clearly identify the target device before executing changes | The console; Writes; Bulk changes | On every view and dialog; the name typed for protected paths; the count typed for bulk |

The requirements' overall expectations, where they bear on this feature:

| Expectation | Where | Status after this ADR |
|---|---|---|
| 1. Multi-tenant permission boundaries | Permissions | Checked at each device's site, under row-level security |
| 2. Execution history and results | Changes; the Jobs filter | A device's changes with their data while kept; reads kept 1 hour |
| 3. Success, failure and meaningful errors | States; each item's outcome | New; a change without its result is *unknown: may have been applied*, never failed |
| 4. Organization, site, group and device targeting | Bulk changes (slice 4) | On ADR-0064's targets |
| 5. Reporting and notifications | — | None planned: EasyRMM judges no value; `registry.refused_on_device` may become an alert kind under ADR-0053 later |
| 6. Permissions and audit records for sensitive operations | Permissions; Audit | New |
| 7. Healthy, unhealthy, unknown, unsupported and unavailable | States | Unknown, unsupported and unavailable, with *reported* and *Refused by EasyRMM*; healthy and unhealthy do not apply, since EasyRMM judges no value |
| 8. Offline and reconnecting endpoints | Offline devices | Waits per kind; the journal; partial results kept |
| 9. Supported and unsupported environments | States; Linux | Windows on x64 and ARM64 with an agent that lists the editor; Linux unsupported |
| 10. Suitable for real-world MSP operations, not demonstrations | Testing; slices | Verified on CI's Windows runners as LocalSystem and on a real Windows computer of the owner's test instance before the guide calls it verified; native code, so App Control, `AllSigned` and EDRs that stop scripts do not take the editor away |

## Slices
*Decided in review.* Each merges and is verified on its own, at every
level it touches. In the plan's [order](../feature-plan-msp.md#order),
slice 1 is step 15, after ADR-0063 (merged), ADR-0064's slice 1 and its
`accepts` (step 6), and W2's job amendments (step 8). The later slices are
among step 28's.

1. **Read-only: F2, browsing, search and export.** The smallest that is
   worth shipping: technicians read a computer's registry with a record of
   each read. Three pull requests:
   * **F2**: the table of kinds; `job_inputs`, `job_runs.result` and the
     masked store, with their grants, functions, endpoints and purge per
     kind; the builtin executor (the child process, `job.structured`,
     `builtin.registry.v1`, the input and result files, the quick lane);
     the claim's size, order and delivery limit; `MaxResultBody`; the
     migration that brings `registry.refused` under the refusal bound;
   * **browsing**: `internal/registryrules`, the builtin's reads, the two
     permissions, `registry.read`, `registry.refused`,
     `registry.refused_on_device`, and the Registry tab;
   * **search and export**, with `registry.export`.

   *Verified*: integration tests; agent tests; the Windows runners, x64
   and ARM64, as LocalSystem; on a real Windows computer of the owner's
   test instance, the time from click to view, before the guide calls it
   verified; the end-to-end test; an agent of the previous release
   running every job it ran before and refused the editor.
2. **Writes, backup and undo.** After ADR-0054's W1 (its ownership reader,
   step 7), W2 (its manifest, step 8) and step-up (ADR-0055's slice 5b2,
   step 17). Create, change and delete; prepare; protected paths; reveal;
   `registry.change`, `registry.reveal`, `registry.change_view` and
   `registry.data_remove`; the Changes list.
3. **Import**, with its preview and `registry.import`.
4. **Bulk changes**, after ADR-0064's targets (its slice 4).

### Slice 1 as built
*Amended 2026-11-26 (decided in review).* The slice follows the Decision
above; where the code showed a better shape, this is what was built.

* **Data functions.** `easyrmm_job_run_result` reads a result under four
  scopes (`job.view`, `job.view_sensitive`, the kind's `registry.view`, and
  the person who asked for the kinds that say so) and records the read where
  the kind says it is recorded. A **separate** `easyrmm_job_input` returns
  the input, and `GET /api/v1/jobs/{id}/arguments` calls it for these
  kinds (an `input` field beside `args`), rather than the arguments function
  being rebuilt to return both: the arguments function and its catalogue
  test stay as ADR-0063 left them.
  `easyrmm_job_delivery_inputs` and `easyrmm_job_run_input_system` are the
  system-scope readers the poll and the result path use. A refused result
  or input read is recorded as `job_run.result_view` or
  `job.arguments_view`; the refusal bound counts `job_run.result_view` and
  `registry.refused` with the two it counted before (migration 00073).
  `registry.refused` is written by `easyrmm_registry_refusal`, a definer
  function that looks the device up under the caller's own scope.
* **The result's lines.** One JSON object per line with a `t`: `begin`
  (operation, hive, view, path, the rules' version, the build and its
  architecture), `key`, `subkey`, `value`, `match`, `xkey` (an export's
  key with its values), `refused`, `error` and `end`. The server decodes
  every line strictly (`agentproto.ParseRegistryLines`), refuses a result
  with a NUL or a lone surrogate in any escape, and stores the lines as a
  `jsonb` array after masking, from what it decoded, not as received. A
  result for another operation, hive, view or path, over its limits, with
  a key outside the key asked for, or with a path the server's rules refuse
  fails the run and is not stored.
* **Not built, because they need slice 2**: `prepare`, the change lock in
  the claim, `registry_changes`, the reveal, the protected paths' checks
  and `registry.change_view` reads (the kind's table entry carries them).
  `registry_masked_values` exists, with its grants and its purge, and holds
  nothing in slice 1: a read never stores masked data.
* **The claim.** A run delivered five times without starting fails
  (`agentproto.MaxDeliveries`) for every kind, not only F2's. The answer is
  chosen in Go from the candidates: quick runs first, then oldest first;
  a quick run that is sent again goes first and alone; otherwise runs sent
  again wait for an answer of their own. The signed size is bounded at
  creation for every kind (`jobs.signed_bytes`).
* **Links in a list** are marked `link` with their target, and a click
  opens one: the agent follows it only where ADR-0067's rule allows.
  Search lists a link as a match of kind `link` and never enters it.
* **Counts of -1.** A listed subkey whose counts the agent did not read, for
  want of time (the key's 30-second budget), has `subkeys` and `values` of
  -1, and the console shows no count for it.
* **Mounted copies.** A hive found in `hivelist` with a file named SAM or
  SECURITY, or one under another name whose root holds `SAM\Domains` or
  `Policy\Secrets`, is refused under `HKLM` and `HKU`.
* **The child's folder** is `TEMP` and `TMP` on Windows, as a script's is,
  and `HOME` elsewhere (only tests run a builtin off Windows).
* **Not measured here.** The time to list a key of 1,000 subkeys and the
  100,000-subkey page are printed by the Windows runners' tests
  (`TestRegistryBigKeyAndValueAsSystem`); the owner's test instance's real
  computer has not been used, so the guide must not call the editor
  verified until it has been.

## Consequences
* Technicians can read a Windows computer's registry from the console,
  with every read recorded, and, from slice 2, change it with backups
  written first, undo for 30 days, and a record per change.
* EasyRMM gains F2, which features 9, 12 and 8 reuse: kinds with a signed
  input and a structured result, run as a script or as code in the agent,
  guarded like output, kept and removed per kind, inputs with their
  results.
* The agent gains `job.structured` and `builtin.registry.v1`: an input
  file, a result file of lines sent however the run ends, two reserved
  slots, and a child process of its own program. An agent of the release
  before keeps running everything it ran, gets no registry job, and the
  console says to update it.
* The jobs' kinds gain `registry_query` and `registry_change`; `jobs`
  gains `builtin` and the signed job's size; new tables `job_inputs`,
  `registry_masked_values` and `registry_changes`; `job_runs` gains
  `result` and its sizes and times; the claim orders and bounds an answer
  by size and gives up on a run after 5 deliveries; results may be 8 MiB.
* Permissions gain `registry.view` and `registry.edit`; the audit log
  gains the nine actions above; the refusal bound counts
  `registry.refused`.
* ADR-0054's one change at a time covers registry changes.
* No PowerShell runs for the editor, but the owner check of slice 2.
* Windows paths that the runners cannot show stay marked unverified until
  ADR-0054's Windows machines, or real computers, show them: a domain's
  Group Policy setting a value back, App Control, roaming profiles.

## Testing
* **Integration tests** in Go against real PostgreSQL through `testdb`
  (`make test-db`), without mocks:
  * **F2's data**: `job_inputs.input`, `job_runs.result` and the masked
    store's data refused to `easyrmm_app` (`42501`), read only through the
    functions, which ADR-0063's catalogue test finds with `pg_temp` last; a
    query's input and result read by the person who asked and refused
    (`403`, recorded within the bound) to another Technician of the site,
    through `/result` and through `/arguments`; a change's read with
    `registry.change_view`; every role on each endpoint; the purge
    emptying a query's input and result after an hour and a change's after
    the output retention, together and not before; `registry.data_remove`
    emptying input, results and masked values, refused to the change's
    author; undo refused once the result is gone.
  * **Masking**: a value named `DbPassword` written by a change, then read
    back through every endpoint, list, download and record: the data
    appears only through a reveal, after step-up, with its record; a
    backup of it moved into the masked store on receipt; a result from an
    agent whose rules missed the name has the data dropped.
  * **Results**: a result of the wrong operation, path, version or size
    failing the run and not stored; one holding a refused path recorded as
    `registry.refused_on_device`; a change's result with backup lines and
    no outcome, a change reported without `result`, and one never
    reported, each shown as *unknown: may have been applied* with undo
    offered where a backup came; names and data with `\u0000` and lone
    surrogates stored through `raw` and read back equal, and a result with
    a `\u0000` escape refused before it reaches `jsonb`.
  * **Delivery**: the claim delivering an F2 run only to a poll whose
    `accepts` lists what the kind needs; quick runs first; an answer never
    over 6 MiB and never empty while runs are due; a run being sent again
    alone in its answer; a run failed after 5 deliveries; a job whose
    signed size, with `<`, `>` and `&` in its data, passes 2 MiB refused at
    creation.
  * **Paths**: a table of spellings refused by the server (every row of
    the refused table as `HKLM\`, `HKEY_LOCAL_MACHINE\`, `\Registry\Machine\`,
    `Registry::`, `Computer\`, lower case, `SECURITY\SAM`, the 32-bit view
    and `WOW6432Node`, `ControlSet001` and `CurrentControlSet`, and names
    with `ſ`, `ı` and `K`); refusals recorded within the bound, counted with
    ADR-0063's; `/` kept as part of a name; `.`, `..`, empty names and long
    paths refused; the same table run against `internal/registryrules` in
    the agent's tests.
  * **Records**: one `registry.read` per query; no record holding data but
    numbers and protected strings (a random marker written as a string
    value outside protected paths appears in no record, list or job
    answer); the search term's length, not the term; one `registry.change`
    per organization for bulk.
  * **Writes, import, bulk** (slices 2 to 4): step-up required for
    protected paths, reveals and bulk, stale step-up refused; the change
    lock against a hardening apply; `.reg` files parsed, `hex(6)` and the
    other types refused naming the line; targets as ADR-0064's tests.
* **Agent tests** in Go on every platform: the payload's new fields
  refused by the release before's strict decoder and accepted now; the
  capabilities listed only while the last heartbeat answer was of level 2
  or higher; the input file written in the run's folder and gone after;
  the variables set, `TEMP` and `TMP` in the run's folder, and nothing
  else leaked; a result of lines read whole with a cut last line dropped,
  after exit, timeout, cancel and a kill; a result request over
  `MaxResultBody` cut from the end and marked; the journal keeping
  `result` across a restart, and the previous release's journal code
  dropping it; quick runs taking the reserved slots while four long runs
  hold the others.
* **The builtin on CI's Windows runners, as LocalSystem.** A job of its
  own, in a matrix over `windows-latest` (x64) and `windows-11-arm`
  (ARM64), builds the agent's Windows test binary and runs it as
  LocalSystem through a scheduled task, as ADR-0054's and ADR-0064's
  tests do, and fails with the task's exit code and output. Go tests of
  `agent/registry`, against keys under a random name below `HKLM\SOFTWARE`
  that the test makes and removes:
  * every spelling above refused by the agent with the server's check
    skipped (the builtin's entry point called directly);
  * links made by the test's own helper (test code, never shipped): a link
    to `\REGISTRY\MACHINE\SAM` refused by its kernel name and recorded; a
    link to an allowed key listed for reads and followed only within its
    hive, and refused for writes; `CurrentControlSet` and HKCC's alias
    followed for writes; a link swapped in between a key delete's backup
    and its delete, caught and the delete stopped;
  * **links made by a standard user**, through a process running as a
    local standard user the test creates: one in that user's own hive
    pointing into HKLM, and one under a key of HKLM whose permissions let
    users create subkeys; recording whether Windows lets the user make
    each and would follow it, and the builtin following neither for a
    write;
  * a copy of a hive saved with `reg save` and loaded under another name
    (`HKLM\EasyRMMTest-<random>`): refused by its file's name when saved as
    `sam.save`, and by its root when saved under any name; the saved copy
    is of a test hive built with a `SAM\Domains` key, never the real SAM;
  * a write landing on a protected key through a path the server did not
    see as protected, refused without `protectedConfirmed`;
  * every type, including `REG_NONE`, `REG_DWORD_BIG_ENDIAN`,
    `REG_RESOURCE_LIST` and an unknown number written raw; strings with no
    terminator, odd lengths, NULs and lone surrogates; names with NUL; the
    default value;
  * both views, a shared key, the x86 view on ARM64, the child refusing to
    run emulated; the 255-character limit per name or per path;
  * a key with 100,000 subkeys paged; a 1 MiB value; search stopping at
    each bound;
  * a `.reg` export imported by `reg import` into another test key and
    read back equal, and `reg export`'s file of the same key compared with
    EasyRMM's;
  * writes: compare refusals, backup lines on disk before each change,
    undo, a key deleted and restored with its DACL, a key that denies
    SYSTEM writing shown as access denied and left alone; the child
    killed in the middle of an import, and the lines left naming every
    item that may have changed;
  * no PowerShell process started by a read; the time of each operation
    printed.
* **Machine tests**: with ADR-0054's Windows machines under KVM, Group
  Policy setting a value the editor changes, a domain account's hive, App
  Control putting scripts in Constrained Language Mode (the editor still
  working; the owner check saying *cannot tell*).
* **Page tests** (`web/src/pages/devices/`): the tab only for Windows and
  `registry.view`; the header's device, view and physical key; each state,
  *unknown: may have been applied* included; masked values everywhere;
  refused keys greyed; links; the write dialog's warnings, step-up and
  typed name.
* **The browser end-to-end test** (`make e2e`), with the simulated agent
  (`web/e2e/agent.ts`) taught `job.structured` and `builtin.registry.v1`
  and answering with results the real builtin produced on a runner: a
  technician opens the Registry tab, reads a key and exports it; a
  Read-Only user sees no tab; the audit log shows the records. The
  simulated agent is a stand-in, as in ADR-0064's end-to-end test: it does
  not run the builtin, which is tested on the runners and on a real
  computer.
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
* about_Logging (5.1):
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
* PowerShell ♥ the Blue Team (Microsoft's PowerShell team):
  https://devblogs.microsoft.com/powershell/powershell-the-blue-team/
* RegistryValueKind:
  https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvaluekind
* reg export:
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-export
* reg import:
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-import
* How to add, modify, or delete registry subkeys and values by using a
  .reg file (support article 310516; not read for this ADR):
  https://support.microsoft.com/help/310516
* MITRE ATT&CK T1027.004, Compile After Delivery:
  https://attack.mitre.org/techniques/T1027/004/
