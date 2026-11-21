# ADR-0060: Collecting logs

* Status: Proposed (2026-11-21). Not implemented.
* Builds on: [ADR-0002](0002-postgresql-rls-tenant-isolation.md)
  (row-level security), [ADR-0017](0017-scripts-and-jobs.md) (jobs),
  [ADR-0019](0019-monitoring-and-alerts.md) (alerts),
  [ADR-0023](0023-audit-forwarding.md) (audit forwarding),
  [ADR-0027](0027-agent-updates.md) (agent updates),
  [ADR-0050](0050-removing-a-device.md) (removing a device),
  [ADR-0051](0051-hardening-linux-computers.md) (hardening Linux), and three
  ADRs proposed beside this one and not merged yet, so cited without
  links: ADR-0058 (signed settings, the plan's F1), ADR-0053 (one
  notification sender, F2) and ADR-0054 (hardening Windows).
* Amends: [ADR-0023](0023-audit-forwarding.md) (one list of syslog
  destinations), [ADR-0052](0052-the-host-updater.md) (the updater's copy
  leaves the log store out) and [ADR-0051](0051-hardening-linux-computers.md)
  (who removes auditd).
* Part of [the feature plan](../feature-plan.md): feature 3.

## Context
The owner asked on 2026-11-20 for EasyRMM to cover an MSP's security
visibility without other tools: the agent collects the security and
antivirus logs of Windows and Linux computers (Windows' Security, System,
Application, Defender, PowerShell and Sysmon logs; Linux's authentication
log, journal and auditd), EasyRMM stores them and forwards them, for
example to a SIEM, and logging is configured when the agent is installed
(audit policy, log sizes, PowerShell script block logging, auditd rules),
so that the operator does nothing.

What exists, and what it means here:

* **Nothing reads a computer's logs.** The agent (`agent/`) has no event
  log, journal or audit code. The only log it handles is its own: a file
  under `Paths.Logs()` on Windows, the journal on Linux
  (`agent/host/host.go`).
* **The audit log already leaves over syslog** (ADR-0023,
  `server/internal/auditfwd`). One row, `audit_forwarding`, holds one
  collector and the ID of the last record sent. Every two seconds, under an
  advisory lock so that one server forwards, up to 500 records go as RFC
  5424 messages whose text is the record in JSON, over TLS (1.2 or later,
  a pasted CA as the only trust anchor, an optional client certificate
  with its key sealed), TCP or UDP (`service.go`, `transport.go`,
  `message.go`). It dials through `server/internal/netguard`, which
  refuses link-local addresses and two cloud metadata addresses and
  allows loopback and private ones. Audit retention waits for the
  collector.
* **Agent requests are signed over their body.** The signature covers the
  body's SHA-256 (`internal/agentproto/agentproto.go`). The server checks
  the header before reading the body, reads at most 1 MiB (4 MiB for
  inventory and job results) within two minutes, and allows each device
  one signed request a second with bursts of 120
  (`server/internal/httpapi/agentapi/agentapi.go`).
* **The agent has no resource limits.** Its systemd unit sets none
  (`UnitContent`, `agent/host/service.go`); the Windows service runs as
  LocalSystem (`agent/host/system_windows.go`). On Linux the agent updates
  itself by executing the new build in its own process
  (`agent/cmd/easyrmm-agent/restart_other.go`), not by restarting its unit.
* **How jobs run.** Each run gets a directory with a random name,
  `run-*`, under the jobs directory (`agent/jobs/exec.go`); on Windows it
  runs in a job object, PowerShell with `-File script.ps1` and the job's
  arguments on the command line (`agent/jobs/exec_windows.go`). Argument
  values stay out of the audit log (ADR-0017).
* **Secrets reach the logs this feature reads.** The console's Windows
  install command runs `install.ps1` as a script block with
  `-Token '<token>'` (`windowsInstallCommand`,
  `web/src/pages/devices/AddDevicesPage.tsx`), which script block logging
  records; `install.sh` takes `--token` as well as `EASYRMM_TOKEN`
  (`server/internal/httpapi/agentapi/install.sh.tmpl`). Deployment and
  approval tokens are `ert_` and 43 base64url characters (`newTokenSecret`,
  `server/internal/agents/tokens.go`), usable until they expire or are used
  up.
* **One PostgreSQL holds every database.** The deployment's PostgreSQL
  (`deploy/docker-compose.yml`: host networking, loopback port 15432,
  `max_connections=200`, `shared_buffers=256MB`) holds EasyRMM's database,
  the engine's (made by `easypatch-db-init`,
  `docker/postgres/easypatch-db-init.sh`) and Authentik's. Tenant tables
  force row-level security on the `easyrmm.scope_*` settings
  ([database.md](../database.md)). Deleting an organization, site or
  device fires `BEFORE DELETE` triggers that record what the engine must
  undo (migration 00020).
* **Backups copy files.** A backup has six parts
  ([backup-restore.md](../../operations/backup-restore.md)). The updater
  ([ADR-0052](0052-the-host-updater.md#an-upgrade), not built yet) copies
  the whole data root before each upgrade, and a rollback restores that
  copy. The feature plan wants the logs left out of that copy. A database
  inside the shared PostgreSQL cannot be: the transaction log and the
  record of which transactions committed belong to the whole cluster, so a
  restored cluster with one database's newer files is corrupt.
* **Hardening writes audit rules** ([ADR-0051](0051-hardening-linux-computers.md)):
  `/etc/audit/rules.d/60-easyrmm-hardening.rules`, "Log collection will
  keep its rules in another file", and its undo keeps auditd while another
  EasyRMM rules file is there. Its script, in progress on the hardening
  branches, keys its rules `easyrmm-accounts` to `easyrmm-privileged` and
  checks that they loaded by looking for `key=easyrmm-` in `auditctl -l`.
  ADR-0054 (proposed) may set Windows audit policy.
* **Test harnesses.** CI's Windows runner runs the agent's Windows tests
  for real (`.github/workflows/backend-tests.yml`, "Agent tests on
  Windows"); the bundle test runs the deployment and a Debian machine with
  systemd on host networking (`scripts/e2e/bundle.sh`); `tools/agentsim`
  simulates thousands of agents; `server/internal/auditfwd/collector_test.go`
  has a syslog receiver on loopback. The machine test harness
  (`internal/vmtest`: distributions' cloud images under QEMU with user
  networking) is on the hardening branch, not yet on `main`.

### How much
The volume decides the store. These are assumptions, after the default
filters below, until slice 1 measures real computers (the store's sizing
is redone then):

| Kind | Devices | Events a day each | Raw a day each | Raw a day, all |
|---|--:|--:|--:|--:|
| Windows workstation | 1,700 | 10,000 | 9 MB | 15.3 GB |
| Windows member server | 200 | 50,000 | 45 MB | 9.0 GB |
| Domain controller | 50 | 200,000 | 180 MB | 9.0 GB |
| Linux server | 50 | 20,000 | 14 MB | 0.7 GB |
| **An MSP with 2,000 devices** | | **38 million** (440 a second, peaks of several times that) | | **34 GB** |

A raw event is about 900 bytes on Windows (its fields as JSON, without
the rendered message) and 700 on Linux. Thirty days are about 1 TB of
raw events.

* **A row per event in PostgreSQL** costs about 1.1 KB with its tuple
  header and two indexes (rows under 2 KB are not compressed): about
  1.25 TB for 30 days, 1.1 billion rows, written twice (heap and
  transaction log).
* **Compressed blocks** of events with indexed facts about each block
  cost the compressed events (6 to 8 times smaller is assumed: 130 to
  170 GB for 30 days) and about 400 bytes of facts and indexes per block
  (1.8 million blocks a day at the upload pace below: 22 GB). About 150
  to 200 GB.

## Decision

### In short
* The agent runs a **collector**, its own process with CPU, memory,
  bandwidth and disk limits, that reads Windows' event logs and Linux's
  journal and auditd log from its own bookmarks, filters, redacts
  EasyRMM's tokens, and uploads signed, compressed batches that the server
  stores exactly once.
* **Configure logging** (on by default) sets audit policy, log sizes and
  PowerShell script block logging on Windows, and auditd rules and a
  persistent journal on Linux, leaving what Group Policy sets alone, and
  undoes its changes on uninstall.
* The logs live in a **PostgreSQL instance of their own**, as compressed
  blocks with indexed facts, partitioned by retention and day, under
  row-level security; quotas, a size cap and a free-disk floor stop
  ingest before the store can fill its disk, and the updater's copy leaves
  it out.
* The console searches them (**Logs**, and a device's **Logs** tab);
  command lines and script text need a permission of their own.
* **One list of syslog destinations** carries the audit log and device
  logs; built-in **detections** raise alerts that the rules of ADR-0053
  (proposed) send.

### Two switches
As the plan has them:

* **Configure logging** (`logs.configure`) changes the computer's own
  logging (below). Nothing leaves the computer for it. On by default.
* **Collect into EasyRMM** (`logs.collect`) uploads the logs. A
  platform-wide switch that super administrators can also set per
  organization (a customer that declines collection).
* **New installs**: `setup.sh` turns both on unless given
  `--no-collect-logs` or `--no-configure-logging`. It writes the choice to
  `.env` (`EASYRMM_LOGS_INITIAL`), which the server applies once, when the
  platform's settings were never set; from then on the console owns them.
  **Upgrades** have no initial value: the first-run checklist asks a super
  administrator once, and until then nothing is configured or collected.
* **Agents already enrolled** act when the setting reaches them (F1), so
  enrolment and upgrades need no other step.
* **While collection is off**, the collector still counts events per
  source under the filters (counts only, sent with its status), so that
  Settings → Logs can show the volume per kind of computer before anyone
  turns collection on.
* **Turning collection off** for a device deletes its spool and bookmarks;
  turning it on again starts from that moment. The first start ever reads
  the previous 24 hours too, so that what led up to an install is there.

### What is collected
Each source has a default filter for its security-relevant part, which
organization administrators can change (`logs.sources`): sources on or
off, codes included or excluded, a minimum level. They can add up to ten
sources of their own (a Windows channel, or journal matches by unit or
identifier), each with a filter.

**Windows** (each channel read only where it exists):

| Source | Channel | Default filter |
|---|---|---|
| `windows.security` | Security | 1102; 4608, 4616 (start, time changed); 4624, 4625, 4647, 4648, 4672, 4778, 4779, 4800, 4801, 4964 (sign-ins and sessions), without the sign-ins of SYSTEM, LOCAL SERVICE, NETWORK SERVICE and the window manager's and font driver's accounts; 4688 (processes, with command lines); 4697, 4698 to 4702 (services, scheduled tasks); 4719, 4739, 4906 (policy); 4720 to 4767, 4781, 4794 (accounts and groups); 4741 to 4743 (computer accounts); failures of 4768, 4769, 4771, 4776 (Kerberos, NTLM); 4946 to 4948 (firewall rules); 6416 (a new external device). Not 4634 (every sign-out), 5156 (every connection), 4663 (every file access) |
| `windows.system` | System | Critical and error from any provider; 104 (log cleared), 1074 (restart and by whom), 6005, 6006, 6008 (starts, unexpected stops), 7040, 7045 (service changed, installed) |
| `windows.application` | Application | Critical and error; 1033, 1034, 11707, 11724 (programs installed and removed) |
| `windows.defender` | Microsoft-Windows-Windows Defender/Operational | Detections and actions (1006 to 1009, 1015, 1116 to 1119), scans failed (1005, 2001, 3002), protection changed or off (5001, 5004, 5007, 5008, 5010, 5012, 5013) |
| `windows.powershell` | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational | 4104 (script blocks) |
| `windows.sysmon` | Microsoft-Windows-Sysmon/Operational, when Sysmon is installed | Every event but 3, 7, 10 and 22 (network connections, image loads, process access, DNS queries), the four a broad Sysmon configuration makes largest |
| `windows.rdp` | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational, -RemoteConnectionManager/Operational | 21, 23, 24, 25, 39, 40; 1149 |
| `windows.wmi` | Microsoft-Windows-WMI-Activity/Operational | 5861 (a permanent WMI subscription, a common way to persist) |

**Linux:**

| Source | Where | Default filter |
|---|---|---|
| `linux.auth` | The journal: facilities auth and authpriv (sshd, sudo, su, login, PAM, polkit, the account tools) and systemd-logind | Everything |
| `linux.audit` | auditd's log (`log_file` in `auditd.conf`) | Records carrying an EasyRMM key (`easyrmm-*`, this feature's and hardening's), and sign-ins, authentication, sudo, account and group changes, audit configuration changes, auditd starting and stopping, SELinux denials and anomalies (`LOGIN`, `USER_LOGIN`, `USER_AUTH`, `USER_CMD`, `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`, `USER_MGMT`, `GRP_MGMT`, `USER_CHAUTHTOK`, `CONFIG_CHANGE`, `DAEMON_*`, `AVC`, `USER_AVC`, `ANOM_*`) |
| `linux.system` | The journal | Priority error and above, any unit |
| `linux.av` | The journal of Defender for Endpoint and ClamAV units, when installed (`mdatp.service`, `clamav-daemon.service`, `clamd@*.service`, `clamav-freshclam.service`) | Everything |
| `linux.file` | `/var/log/auth.log` or `/var/log/secure` | Only on a computer without a journal (an agent run without systemd). Elsewhere the journal holds the same messages, which rsyslog writes to those files from it: reading both would store each twice |

**Codes.** Every event gets a code that filters, detections and the
console use: a Windows event's ID; on Linux, a name the server's parser
gives the messages it knows (`sshd.accepted`, `sshd.failed`,
`sudo.command`, `sudo.denied`, `su.failed`, `useradd`, …) and auditd's
record type (`audit.USER_LOGIN`), else the program's identifier. The guide
lists them.

### The collector
* **Its own process**, `easyrmm-agent collect`, the agent's own binary:
  * **Linux**: its own unit, `easyrmm-agent-collect.service`, which the
    agent writes and removes like its own, with `PartOf=` the agent's unit,
    `CPUQuota=20%` (a fifth of one processor), `MemoryHigh=192M`,
    `MemoryMax=256M`, `Nice=10`, `IOSchedulingClass=idle`. After the agent
    updates itself (ADR-0027) it restarts the collector, which runs the
    same file.
  * **Windows**: a child of the agent's service, which starts it again if
    it stops, in a job object with a hard CPU rate cap of a fifth of one
    processor, a memory limit of 256 MiB and kill-on-close; it also enters
    Windows' background processing mode (lower I/O and memory priority).
    Its parent's restart, as after an update, restarts it.
  * Both run with `GOMAXPROCS=1` and a Go memory limit under the hard one.
    The limits never slow jobs, which run in the agent's process tree, not
    the collector's.
* **Reading**, without cgo:
  * **Windows**: the Event Log API (`wevtapi.dll`: `EvtSubscribe`,
    `EvtNext`, `EvtRender`), one pull subscription per source starting
    after its bookmark, strictly, so that a bookmark Windows no longer has
    (a cleared or wrapped log) is noticed; then from the oldest record,
    with the gap reported. Filters go into the subscription's XPath query
    where they fit, so that Windows does not render what is dropped. Each
    event's system fields and its `EventData` or `UserData` are kept;
    the rendered message only outside the Security log, whose events are
    known by ID and fields (the message would triple their size), capped
    at 2 KiB.
  * **Journal**: `journalctl --follow --output=json` from the source's
    cursor with its matches. The journal's file format is internal to
    systemd and compressed in ways that change between versions;
    `journalctl` is wherever the journal is.
  * **auditd**: its log file by inode and offset, following rotations,
    with the records of one event (one serial) grouped.
  * **Gaps** (entries gone before they were read) are reported with their
    size where the source tells it (Windows' record numbers, auditd's
    serial numbers within a boot), else as of unknown size.
* **The spool**: under the agent's state directory (`collect/`, protected
  like the key), append-only segments per source, each record framed with
  its length and a checksum, and **each append carrying the source's new
  position**: an event and the bookmark after it are written together,
  synced at most once a second. After a crash a torn tail is cut off and
  reading resumes from the last position written; nothing is read twice
  into the spool or skipped.
* **Its limits**: 256 MiB in all by default (`logs.spool`), at most a
  quarter of it per source, and never past a free-space floor on its
  volume (1 GiB or 5%, the smaller). **A source whose share is full pauses
  instead of dropping**: its events wait in Windows' log, the journal or
  auditd's files, which are themselves buffers of hours to days, and only
  a source that wraps past the bookmark loses events, counted as a gap. A
  flood in Application pauses Application, never Security.
* **Redaction** before the spool, on every text field: `ert_` followed by
  43 base64url characters becomes `ert_[redacted]`, and the value after
  `EASYRMM_TOKEN=`, `-Token` and `--token` becomes `[redacted]`. Each
  batch says how many it redacted. The server applies the same rules
  again. Other secrets that people put on command lines are why command
  lines need a permission (below).
* **EasyRMM's own jobs**: process creation events (4688, Sysmon 1, auditd
  `EXECVE`) of a job's processes and their descendants, and script blocks
  (4104) whose path is in a run's directory, are kept, marked with the
  run, and their command lines and script text replaced by "EasyRMM job:
  see the run", where `job.view` shows the script and its arguments.
  ADR-0017 keeps job arguments out of the audit log for the same reason.
  The job worker names each run's directory after its run (a random name
  today) and records the run's first process ID; the collector follows
  descendants through the creation events themselves while the run lasts.
* **Batches**: a source's events are sent when 512 KiB are waiting, when
  the oldest has waited 2 minutes, or 10 seconds after an event that a
  detection uses arrived (the settings carry those codes); at most one
  upload every 10 seconds. A batch is fixed before its first attempt (its
  sequence number and the spool range it covers are recorded), so that a
  retry, also after a restart, sends the same events under the same
  number.
* **Bandwidth**: uploads are paced to `logs.bandwidth` (128 KiB/s by
  default, set per site for slow links), with jitter.

### Uploading
`POST /api/agent/v1/logs`, signed like every agent request, its body JSON
compressed with gzip (`Content-Encoding: gzip`): the spool's generation (a
random ID made with the spool), the batch's sequence number, and per
source its events, its position, and what it dropped, filtered and
redacted.

* **Read in order**: the header is checked first (an unknown or retired
  device's body is never read); at most 2 MiB as sent, within two
  minutes; the signature verified over those bytes; only then
  decompressed, **stopping at 16 MiB**; at most 10,000 events, each at most
  32 KiB once normalized (longer fields are cut, and the event says so).
  The device, organization and site come from the signature's device,
  never from the body.
* **Exactly once**: the store keeps, per device, the generation and the
  highest batch number stored, and stores a batch, its blocks and the
  device's usage in one transaction that takes that row's lock first. A
  batch whose number is not higher is answered as stored without storing
  it again. A new generation (a reinstalled agent) starts a new count. A
  computer restored from a snapshot sends numbers already used: the server
  answers with its own number, and the agent starts a new generation and
  sends again from its spool, so events may arrive twice there, never be
  lost.
* **Answers**: `200` with how much more the device may send today
  (`budget`, bytes, and when it renews); `429` with `Retry-After` when the
  device's or its organization's quota is used up or ingest is stopped
  (`logs_quota`, `logs_paused`); `503` with `Retry-After` when the store is
  unavailable or busy; `403 logs_off` when collection is off for the
  device, which deletes its spool; `413` when a batch is too large, which
  the agent splits. On every refusal the agent keeps its spool and its
  sources pause as their shares fill.
* **Admission**: at most 32 log uploads are processed at once on a server,
  others answered `503` with a jittered `Retry-After`, so that 2,000
  devices returning after an outage do not arrive at once. Each device may
  upload once every 10 seconds, with bursts of six, on top of the limit
  every signed request has.
* **Status**: `POST /api/agent/v1/logs/status`, signed, when something
  changes and at least hourly: each source's state (position time, paused,
  gaps, drops, spool use), the counts while collection is off, and the
  state of each change *Configure logging* makes. A change of the latter
  is audited (`device.logging_configured`, `device.logging_undone`).

### Configuring logging
**Windows**: what it sets, each only raised, never lowered:

| What | Value | Main events |
|---|---|---|
| Advanced audit policy, Account Logon | Credential Validation: success and failure; on domain controllers, Kerberos Authentication Service and Kerberos Service Ticket Operations: success and failure | 4776; 4768, 4769, 4771 |
| Account Management | Computer Account, Security Group and Other Account Management: success; User Account Management: success and failure | 4720 to 4767, 4741 to 4743 |
| Detailed Tracking | Process Creation: success; Plug and Play Events: success | 4688; 6416 |
| Logon/Logoff | Logon: success and failure; Logoff: success; Account Lockout: failure; Special Logon: success; Other Logon/Logoff Events: success and failure | 4624, 4625, 4647, 4672, 4778, 4779, 4800, 4801 |
| Object Access | Other Object Access Events: success and failure | 4698 to 4702 |
| Policy Change | Audit Policy Change: success and failure; Authentication Policy Change: success; MPSSVC Rule-Level Policy Change: success | 4719; 4739; 4946 to 4948 |
| System | Security State Change: success; Security System Extension: success; System Integrity: success and failure | 4608, 4616; 4697; 5038 |
| Command lines in process creation events | `ProcessCreationIncludeCmdLine_Enabled` = 1 under `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit` | 4688 |
| Script block logging | `EnableScriptBlockLogging` = 1 for Windows PowerShell (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`) and PowerShell 7 (`…\PowerShellCore\ScriptBlockLogging`) | 4104 |
| Maximum log sizes | Security at least 256 MiB (1 GiB on domain controllers); System, Application and PowerShell/Operational at least 64 MiB | |

Not set: module logging (4103, which repeats much of what script blocks
show at many times the volume), Logoff's 4634 and connection auditing
(collected nowhere by default), file and share access, Sysmon (installed
and configured by its owner, or not at all), and each log's retention
mode (left as it is, and reported when it is not "overwrite as needed":
"do not overwrite" stops logging when full, "archive" fills the disk).

**Linux:**

| What | Change |
|---|---|
| Persistent journal | `/var/log/journal` created and the journal flushed to it, where `Storage` is `auto` and the directory is missing (the journal is then kept in memory only). An explicit `volatile` or `none` is left and reported |
| auditd | Installed where missing (`auditd` on Debian and Ubuntu, `audit` on the RHEL family) from the distribution's repositories, enabled and started. Not in containers, where the audit subsystem is the host's |
| Audit rules | `/etc/audit/rules.d/60-easyrmm-logs.rules`, loaded with `augenrules --load`, keyed `easyrmm-logs-*`: the identity files, sudoers, SSH and PAM configuration, time, kernel modules, mounts, and commands run with raised privileges (as hardening's file), and also cron and systemd's units under `/etc`, `/etc/ld.so.preload`, root's SSH keys, audit's own configuration, and the commands people run (`execve` with a login UID from `UID_MIN` in `/etc/login.defs`, never unset). Never `-e 2`, `-f 2`, `-b` or `auditd.conf` |

**Group Policy wins.** On Windows the agent reads the computer's
resultant set of policy: an audit subcategory or a registry value above
that Group Policy (domain or local) sets is left alone and shown as *set
by Group Policy*, with the policy's name. A value that something else
already set differently (a script, an image) is left alone too and shown
as *set elsewhere*. The agent checks every hour; a subcategory set back
twice after EasyRMM set it is marked *managed elsewhere* and left from
then on. Where legacy category auditing overrides subcategories, that is
reported and nothing is set.

**Domain controllers** are left alone unless the operator chooses them
(`logs.configure.domainControllers`): their audit policy is the domain's.
Their logs are still collected.

**Who owns what**, so that hardening and this feature never fight:

* **Windows**: audit policy, command lines in process events, script block
  logging and log sizes belong to *Configure logging*. ADR-0054 (proposed)
  reports them in its checks and does not set them; where hardening wants
  them, it asks for `logs.configure`. To be reconciled when both are
  reviewed.
* **Linux**: hardening keeps `60-easyrmm-hardening.rules` with its keys,
  this feature `60-easyrmm-logs.rules` with `easyrmm-logs-*`; neither
  writes the other's file or any other. The kernel treats two rules that
  differ only by key as different rules, so both files load where both
  exist; an event matching both is recorded once, with the key of the
  rule loaded first (hardening's, which sorts first). Each file stands
  alone. The collector takes both features' keys. Both facts are checked
  on machines (below). Hardening's check should look for its own keys,
  since `key=easyrmm-` also matches this feature's.
* **auditd itself**, last one out: whichever feature installs auditd
  writes `/var/lib/easyrmm/auditd-installed`. Each feature's undo removes
  its own rules file and reloads; then, if no `easyrmm` rules file is left
  in `/etc/audit/rules.d/` and that marker exists, it removes auditd if
  removing it removes nothing else (simulated first), and the marker. This
  replaces, for auditd, ADR-0051's record of packages hardening installed,
  which could leave auditd behind when this feature installed it.

**Undo**, on `easyrmm-agent uninstall` (and so the removal of a device,
ADR-0050, and of an agent package, feature 6) and when *Configure logging*
is turned off: each change is recorded before it is made (the value
before and the value set) in `collect/logging.json`, and put back only
where the computer still has the value EasyRMM set; anything changed since
is left and reported. What Windows does with a log already larger than
its restored maximum is checked on CI's Windows runner and documented. The
persistent journal is left in place: removing it would delete the logs
kept since, and the guide says how to remove it. An agent deleted by hand
leaves logging configured, which is harmless.

### The log store
* **A PostgreSQL instance of its own** (`logs-postgres`), from the same
  image as the deployment's, on host networking at loopback port 15433,
  its data under `<data root>/logs` or `EASYRMM_LOGS_ROOT` (a disk of its
  own is recommended above 500 devices), with its own roles
  (`easyrmm_logs_owner` for migrations and partitions, `easyrmm_logs_app`
  for the server) and passwords in `.env`, which `setup.sh` and
  `setup.sh --upgrade` add. Not a database in the shared PostgreSQL:
  * the updater copies and restores whole data directories, and a cluster
    cannot be restored with one database left out (Context);
  * its transaction log, checkpoints, memory, connections and autovacuum
    would be the main database's, so heavy ingest would slow it, and a
    full disk under the shared transaction log stops every database;
  * it can live on another disk, be stopped, dropped or restored without
    touching the rest.

  It costs a second PostgreSQL process (`shared_buffers=256MB`,
  `max_connections=50`; its memory is measured in slice 1). It runs in
  every deployment, whatever the switches, so that there is one shape to
  test.
* **Not another kind of database.** A columnar or search store
  (ClickHouse, OpenSearch, Loki, VictoriaLogs) would compress and search
  better, but would be a second database technology to secure, upgrade,
  back up and test, with tenancy enforced outside PostgreSQL's row-level
  security (ADR-0002). Compressed blocks in PostgreSQL get within reach of
  their storage at this scale (How much). **Not files on disk** either:
  their crash safety, backups, tenancy and sharing between servers would
  all be EasyRMM's to build.
* **Blocks.** A block is one batch's events of one source from one device:
  the events normalized to JSON lines and compressed with DEFLATE and a
  preset dictionary per source (Go's standard library; the dictionaries
  are built from recorded events, never customer data, are compiled into
  the server and never change once released: a block names its codec and
  dictionary). Beside it, the facts searches use: organization, site and
  device; source; first and last event time and when it was received;
  event count and size; the levels present; the codes present with their
  counts; and the user names, addresses and process names in it. Indexes:
  device and time, organization and time, receipt order, and GIN indexes
  on codes, users, addresses and processes. Blocks are written once and
  never rewritten; merging small blocks is not built unless the load test
  shows block facts above a third of the store.
* **Partitions**: by retention class (list: 7, 14, 30, 60, 90, 180 or 365
  days, and `forward`), then by the day the block was received (range).
  Partitions are made a few days ahead and dropped when their class's
  days have passed, by `SECURITY DEFINER` functions the owner role holds;
  the application role reaches only the parent table (insert, select,
  delete) and cannot create, drop or read a partition directly. A dropped
  partition's counts per organization are recorded first, so that gaps
  can be counted.
* **Row-level security**, forced on the parent, with the same
  `easyrmm.scope_*` settings and functions as the main database: a block
  is visible at platform scope, in its organization's scope, or in its
  site's. Organization and site are on each block (row-level security
  without a join), as they were when it was received: a device moved to
  another organization or site leaves its earlier logs where they were.
* **Retention per organization** (`logs.retention`, 30 days by default)
  always wins, also over forwarding. Events already older than it when
  they arrive are not stored, and counted. Shortening it deletes that
  organization's older blocks at once (their space is freed when their
  partitions are dropped); lengthening it applies to blocks received from
  then on. Deleting one person's events (an erasure request) is not
  offered: logs expire with retention, and the guide says so.
* **Quotas** (raw bytes a day): per device (`logs.deviceQuota`, 1 GiB by
  default, set per organization, site or device), per organization
  (`logs.organizationQuota`, none by default), and a storage cap per
  organization (none by default). The server counts usage per device,
  source and day in the store with each batch.
* **Ingest stops before the disk fills**: past a size cap for the whole
  store (`logs.maxSize`, none by default) or a free-disk floor on its
  filesystem (10 GiB or 5%, the larger), ingest stops, agents keep their
  spools and pause, and a console alert is raised (and the EasyRMM event
  `logs.ingest_stopped`, ADR-0053, proposed); it resumes by itself below
  them. The server reads the filesystem's free space through a read-only
  mount of the store's root (`<data root>/logs` or `EASYRMM_LOGS_ROOT`),
  whose PostgreSQL files it cannot read.
* **Purges**: deleting an organization, site or device records it in
  `log_purges` in the main database, from `BEFORE DELETE` triggers in the
  deleting transaction (as migration 00020 records what the engine must
  undo); a worker deletes the matching blocks, status and usage from the
  store within minutes, audits it (`logs.purged`, with counts) and removes
  the row. A weekly sweep deletes logs of devices that neither exist nor
  are remembered as removed, which a restore of the main database can
  leave.
* **Its schema only ever adds**: no column, table or function is dropped,
  renamed or narrowed, new columns have defaults, functions only gain
  parameters with defaults, and queries name their columns. A test
  rejects any other migration. So a server rolled back to an older
  release runs on the newer schema.
* **The updater (amending [ADR-0052](0052-the-host-updater.md#an-upgrade))**:
  its copy leaves `<data root>/logs` and `EASYRMM_LOGS_ROOT` out, and a
  rollback leaves the store as it is.
  Logs received after the backup survive a rollback, and so do forwarding
  positions, which live with them. Its pre-check for room counts the
  store out.
* **Backups**: the log store becomes an optional part of
  [backup-restore.md](../../operations/backup-restore.md) (`pg_dump` of
  the logs database; its blocks do not compress further). A restore
  without it starts with an empty store, which the server's migrations
  make. The backup drill runs once without it and once with it.
* **The server without its store**: if `logs-postgres` is down, the rest
  of EasyRMM works; uploads are answered `503`, agents pause, and the
  console's log views say the store is unavailable.

### Searching and viewing
* **Logs** (a section of the console) and a device's **Logs** tab: filters
  for organization, site, device, source, codes, level, user, address,
  process, time (the last 24 hours by default) and text (a case-insensitive
  substring of any field). Newest first, a summary line per event (from
  templates per known code, such as "Sign-in by {user} from {address},
  type {logon type}"), and every field on opening it.
* **How**: SQL chooses candidate blocks by their facts, partitions pruned
  by receipt day (an event is received after it happens, allowing a day
  for computers' clocks), under the caller's row-level security; the
  server decompresses them in parallel, filters events, and merges them in
  time order. Each request has a budget of 10 seconds: when it runs out,
  the page says how far back it searched and offers to search further.
  Two searches at once per person. A device and a day, or a user across
  the fleet for 30 days, read a few thousand blocks; free text over a whole
  fleet's month is what the budget is for.
* **The device's tab** also shows each source's state (last event, delay,
  paused, gaps, drops, redactions) and each change *Configure logging*
  made, or why not (*set by Group Policy*, *set elsewhere*, *not
  applicable*, failed).
* **Settings → Logs** (super administrators): the switches, the store's
  size, free space, floor and cap; per organization its storage, ingest a
  day, retention, mode and quotas; the measured volume per kind of
  computer (workstation, server, domain controller, Linux) and what the
  fleet's would take for the chosen retention against the space left.
* **Export** of a search as CSV or JSON lines, up to 100,000 events,
  audited like `report.export`.
* **Sensitive fields** (command lines in 4688 and Sysmon events, script
  block text, auditd's `EXECVE` arguments and `PROCTITLE`, and any field a
  custom source marks) are removed by the server, not hidden by the
  console, for a caller without `log.view_sensitive` in the event's
  organization, and replaced by "hidden: needs permission to see command
  lines".
* **Audited**: each search (its filters and result count, not each page)
  and export, once per organization whose events it returned, under that
  organization, as for exports today.
* **Text from computers** is shown as text, never HTML or Markdown.

### Forwarding
* **One list of syslog destinations** (`syslog_destinations`), replacing
  `audit_forwarding` (amending [ADR-0023](0023-audit-forwarding.md)): a
  migration makes its row the first destination, carrying the audit log,
  with its position. Each destination has a name, the transport, host,
  port, CA and client certificate of today (the key sealed with
  `EASYRMM_SECRET_KEY`), and what it carries: **the audit log**, **device
  logs**, or both. For device logs: all organizations or a list, all
  sources or a list, a facility (local0 by default; the audit log keeps
  log audit), and whether sensitive fields go (yes by default: a SIEM
  needs command lines). UDP is offered for the audit log only.
* **Belongs to super administrators** (`settings.manage`), and dials
  through `netguard` as audit forwarding does and as ADR-0053 (proposed)
  keeps for the platform's destinations: loopback and private addresses
  allowed, link-local and cloud metadata refused. Destinations owned by an
  organization, under ADR-0053's organization policy (public addresses,
  private ones only once a super administrator approves them), are a later
  slice.
* **The audit log** goes as ADR-0023 has it, per destination, its
  position kept beside the destination in the main database, with the
  audit log. Audit retention waits for every destination carrying it.
* **Device logs**: each destination's position (receipt time and block)
  lives in the store, beside the logs, so that the updater's rollback does
  not move it back. A forwarder per destination, under an advisory lock in
  the store, reads blocks received at least 10 seconds ago: ingest
  transactions run with PostgreSQL's `transaction_timeout` of 5 seconds
  and stamp blocks with the time they began, so a block older than that is
  visible or never will be, and none is skipped. It sends their events in
  order over a kept connection, up to 1,000 a write, and moves the
  position at block ends: at least once, never out of order. A
  destination that was down catches up from its position; one behind the
  oldest kept block jumps to it, and the events it missed are counted as a
  gap, shown, and alerted.
* **The message**: RFC 5424, HOSTNAME the device's host name (a SIEM
  files the event under the computer it came from), APP-NAME `easyrmm`,
  MSGID the source, the `origin` structured data as for the audit log, and
  MSG the event as JSON with its organization, site and device (IDs and
  names), source, code, level, times and fields. Events are at most 32
  KiB, under the 64 KiB frame.
* **Forward only, don't store** (`logs.mode`, per organization): blocks go
  into the `forward` class, which searches and the console never read,
  kept until every destination carrying them has passed them, and at
  most 7 days.
* **A failing destination**: failing for 15 minutes raises a console
  alert and the EasyRMM events `logs.forwarding_failing` and
  `logs.forwarding_recovered` (ADR-0053). A test message per destination,
  as now.
* **Volume**: at the sizing above, about 0.5 MB/s, 45 GB a day, to each
  destination carrying every device's logs.
* **Other outputs** (HTTP event collectors, Elastic, Microsoft Sentinel)
  are not built: a later ADR when asked for. The routes of
  `/api/v1/settings/audit-forwarding` are retired when the console uses
  the list (ADR-0048's rule).

### Detections
* **Built in, not a rule language.** A rule language (Sigma, say) is a
  later ADR. Detections are alert policies (ADR-0019) of a new kind, `log`,
  naming one detection (`kind` gains `log`). A migration adds the
  defaults as shared policies, as migration 00006 added four, which super
  administrators change or turn off; organizations and sites add their
  own with `monitoring.manage`, like other policies:

| Detection | Matches | Default |
|---|---|---|
| Log cleared | 1102, 104 | On, critical |
| Audit policy changed | 4719, auditd `CONFIG_CHANGE`, not made by EasyRMM's own configuring or jobs (marked by the collector) | On, warning |
| Malware found | Defender 1006, 1015, 1116, 1117; ClamAV and Defender for Endpoint detections | On, critical |
| Protection turned off | Defender 5001, 5010, 5012, 5013 | On, critical |
| Privileged group changed | 4728, 4732, 4756 adding to Administrators, Domain Admins, Enterprise Admins or Schema Admins (by well-known SID); a user added to `sudo` or `wheel` | On, warning |
| Failed sign-ins | At least the policy's threshold (20) of 4625 or `sshd.failed` on one device within its minutes (10) | On, warning |
| Sudo refused | `sudo.denied` | On, warning |
| Account created | 4720, `ADD_USER` | Off |
| Account locked out | 4740 | Off |
| Service installed | 7045, 4697 (software installs do it too) | Off |

* **How**: each minute, the evaluator reads blocks received since its
  position (with the same 10-second horizon) whose codes include a
  detection's, decompresses only those, and tests them; counted
  detections sum the blocks' code counts over their window. It opens
  alerts in its own transaction in the main database, where it keeps its
  position. An alert stays open, counting further matches, until someone
  resolves it or 7 days pass without one (a new resolution, `expired`):
  an event is not a condition that clears.
* **Notifications** through the rules of ADR-0053 (proposed), whose
  condition filter gains `log` and the detection. Storage and forwarding
  problems are EasyRMM events there (`logs.ingest_stopped`,
  `logs.ingest_resumed`,
  `logs.quota_reached` once a day per organization,
  `logs.forwarding_failing`, `logs.forwarding_recovered`).

### Privacy
* **What it holds**: user names and SIDs, IP addresses, computer names,
  times of sign-ins, programs started with their command lines,
  PowerShell scripts, sudo commands and SSH source addresses: personal
  data about the customers' staff. The MSP processes it for the customer.
* **Collected by default on new installs**, as the owner asked, with an
  organization-level switch for customers that decline it, retention per
  organization, purges with the organization, site or device, and nothing
  that is not security-relevant by default: no rendered Security
  messages, no module logging, no file or share access, no network
  connections.
* **Restricted**: sign-in and process events need `log.view`; command
  lines and scripts need `log.view_sensitive`; every search and export is
  audited where the customer's administrators can see it.
* **EasyRMM's tokens are redacted** on the computer and again on the
  server; EasyRMM's jobs' arguments stay with the job.
* **PRIVACY.md and the guide** say what is collected from which computers,
  where it is kept, for how long, where it is forwarded and who sees it,
  and that MSPs tell their customers (and, where the law asks, their
  staff) before collecting.
* At rest, the store is as protected as the main database: on the
  server's disk, readable by its roles, not encrypted beyond the disk's own
  encryption.

### Settings and who
Settings are F1 keys (ADR-0058, proposed); those marked *server* are not
sent to agents, which F1 must allow.

| Key | Set at | By | Default |
|---|---|---|---|
| `logs.collect` | Platform, organization | Super administrators | Per `setup.sh`; asked once on upgrades |
| `logs.configure` | Platform (enforceable), organization, site, device | Organization administrators and above | As above |
| `logs.configure.domainControllers` | Platform, organization | Organization administrators and above | Off |
| `logs.sources` | Platform, organization | Organization administrators and above | The default filters |
| `logs.bandwidth` | Platform, organization, site, device | Site administrators and above | 128 KiB/s |
| `logs.spool` | Platform, organization | Super administrators | 256 MiB |
| `logs.retention`, `logs.mode` (*server*) | Platform, organization | Super administrators | 30 days, store |
| `logs.deviceQuota`, `logs.organizationQuota` (*server*) | Platform, organization, site, device; organization | Super administrators | 1 GiB a day; none |
| `logs.maxSize`, the floor (*server*) | Platform | Super administrators | None; 10 GiB or 5% |

| Permission | Who |
|---|---|
| `log.view`: sign-in, process and other events, the device's Logs tab, search and export | Site Administrators and above, in their sites (as `audit.view`) |
| `log.view_sensitive`: command lines and scripts | Organization Administrators and above, from organization-wide grants only |
| Syslog destinations, Settings → Logs | Super administrators (`settings.manage`) |
| Detections | As other alert policies: shared ones by super administrators, an organization's or site's with `monitoring.manage` there |

Every settings change, destination change and test, search, export and
purge is audited. [rbac.md](../../security/rbac.md) gains the two
permissions.

### The rest
* **Agent facts**: Windows agents report whether the computer is a domain
  controller (`ProductType` is `LanmanNT`), beside the kind of device
  ADR-0053 adds.
* **API**: `POST /api/agent/v1/logs`, `POST /api/agent/v1/logs/status`;
  `POST /api/v1/logs/search`, `POST /api/v1/logs/export`,
  `GET /api/v1/devices/{id}/logs/status`, `GET /api/v1/logs/usage`,
  `GET` and `PUT /api/v1/settings/logs`, and
  `/api/v1/syslog-destinations` (list, create, change, delete, test).
* **New packages** (the agent's collector, the server's store, ingest,
  search and forwarding) get coverage floors in
  `scripts/ci/check-coverage.sh`, and the collector's Windows code a floor
  of its own once the Windows job writes a coverage profile (the plan's
  harnesses).

## Testing
Every test runs the real thing; what cannot run in CI says so and is
marked unverified in IMPLEMENTATION_STATUS until it is run.

* **Unit**: the parsers (Windows event XML, journal JSON, auditd records
  in raw and enriched format, grouped by serial), filters, codes and
  normalized fields, from events recorded on CI's Windows runner and the
  test machines; fuzzing for the server's parsers and the upload's
  decoder; redaction, on a real script block and command line carrying a
  token; the spool (torn tails, the position with the event, shares,
  pausing); the batch fixed before its first attempt; the agent's answer
  to each status; pacing; blocks and their dictionaries; golden RFC 5424
  messages.
* **Integration** (PostgreSQL, with the race detector and coverage
  floors; the store as a second database of the test PostgreSQL, while the
  bundle and updater tests run it as its own instance): partitions per class and day, made and dropped by the owner's
  functions, and the application role unable to touch a partition;
  row-level security on the parent between two organizations, a site and
  the platform; ingest (signature before decompression, each cap, a
  retried batch stored once, a new generation, a restored snapshot,
  collection off); quotas per device and organization; the size cap, and
  the free-disk floor on a small filesystem made for the test; retention
  shortened; purges from each delete; forwarding (the horizon with a slow
  ingest transaction, order, a destination that comes back and catches up,
  one passed by retention and its gap, forward only, the audit log moved
  from `audit_forwarding` with its position); each detection on recorded
  events, counted windows, an alert opened once across two servers; search
  (each filter, order across overlapping blocks, continuing past the
  budget, sensitive fields removed, searches audited per organization);
  the migrations' only-add rule.
* **Windows, on CI's Windows runner** (`windows-2025`, as administrator,
  for real): subscriptions from bookmarks across a restart of the
  collector, nothing lost or twice; a cleared log reported as a gap; the
  collector in its job object with its CPU cap and memory limit;
  configuring logging (`auditpol` and `wevtutil gl` before and after, the
  registry values), then a 4104 from a test script, a 4688 with its
  command line, a 4625 from a wrong password and a 4720 from a new local
  user, collected; a subcategory set by local Group Policy left alone and
  reported; undo, with everything as before; Sysmon downloaded from
  Microsoft and installed with a small configuration, its events collected;
  a script block carrying a token in the install command's form,
  redacted; a job's 4688 and 4104 marked and replaced. Defender detections
  with the EICAR test file where the runner's Defender allows it, else on
  the owner's servers by hand. Uploads from Windows go to the server's
  real ingest handler once the plan's Windows end-to-end harness runs the
  server against the runner's PostgreSQL; until then that path is
  unverified on Windows.
* **Linux machines** (the QEMU harness, `internal/vmtest`, each tested
  image): configuring logging (auditd installed from the local package
  repository the hardening tests use, the rules loaded, the journal made
  persistent), then a restart (all kept); real SSH sign-ins from outside
  through the forwarded port, failed and accepted, `sudo`, `useradd` and
  an edit of `/etc/passwd`, collected with their keys; with hardening's
  rules file too: both load, each event recorded once, either undo leaving
  the other's rules running, and auditd removed only by the last one out;
  undo, with everything as before. The collector uploads to the real
  ingest handler that the test runs on the host, reached at `10.0.2.2`
  through QEMU's user networking (no bridge). ClamAV with the EICAR file on
  one image.
* **The bundle test** (host networking only, never a bridge): the
  deployment with `logs-postgres`, which listens on loopback only (the
  test's existing check); a failed and an accepted SSH sign-in on the
  Debian machine appear in its **Logs** tab (Playwright) and reach a
  syslog receiver written for the test (RFC 5425 over TLS, octet
  counting, recording each message) running on the host's network,
  listening on loopback as a platform destination with a certificate from
  the run's authority, beside the audit log's records; in that container
  auditd is reported not applicable. With slice 9, an organization's
  destination in a network namespace of its own joined by a veth pair, as
  the webhook test of ADR-0053 (proposed) does. With the updater: an upgrade from a
  release without the store, and a rollback leaving it in place with the
  older server running on the newer schema.
* **Load**: `tools/agentsim` uploads logs from the recorded events at each
  kind of computer's rate. On CI, 500 devices for an hour at four times
  the sizing's rate: ingest latency, the server's processor and memory,
  bytes stored per event and the compression ratio, forwarding throughput
  to the test receiver. On the owner's host, recorded in
  [drills.md](../../development/drills.md): 2,000 devices for 24 hours,
  and searches over a store filled to 30 days at the sizing's volume.
* **By hand on real computers**, recorded with dates: a domain with Group
  Policy setting audit policy, a domain controller chosen and not chosen,
  Defender detections and protection turned off, the owner's Windows and
  Linux servers.

## Slices
Each merges and is verified on its own, after F1 and F2:

1. **The store and Linux sign-ins**: `logs-postgres` in the deployment
   and `setup.sh`, the schema, partitions, row-level security, quotas,
   the cap, the floor and purges; ingest; the collector with its unit,
   limits, spool and uploads; `linux.auth`; the device's **Logs** tab;
   the switches, the checklist and `log.view`; the updater's copy without
   the store (if the updater is built). *Verified*: integration, the
   machines, the bundle test's sign-ins in the tab, the CI load run, and
   the sizing redone from measured volumes.
2. **Windows Security**: the Windows collector, its job object,
   redaction, EasyRMM's jobs marked. *Verified*: the Windows runner.
3. **Configuring logging**: Windows and Linux, Group Policy, domain
   controllers, ownership with hardening, undo. *Verified*: the Windows
   runner and the machines, both features' rules together.
4. **The other sources**: Windows System, Application, Defender,
   PowerShell, Sysmon, RDP, WMI; Linux audit, system, antivirus; custom
   sources; `logs.sources`; the counts while collection is off.
   *Verified*: the runner (Sysmon, script blocks), the machines (auditd,
   ClamAV).
5. **Forwarding**: the destination list with the audit log moved into it,
   device logs, positions, gaps, failing alerts. *Verified*: integration
   and the bundle test's syslog receiver.
6. **Organizations**: retention classes, forward only, organization
   quotas and storage caps, Settings → Logs per organization.
   *Verified*: integration.
7. **Detections**: the `log` policies, alerts, notifications and
   EasyRMM's events. *Verified*: integration, and in the bundle test a
   burst of failed sign-ins reaching ADR-0053's webhook receiver.
8. **The Logs page**: fleet search, `log.view_sensitive`, export, audit.
   *Verified*: console tests, and search times on the owner's host.
9. **Organizations' own destinations**, under ADR-0053's organization
   policy. *Verified*: the bundle test's namespace receiver.

## What changed from the plan
* **The store is a PostgreSQL instance of its own**, not a database in
  the shared one: the updater's copy could not leave the latter out.
* **Compressed blocks with indexed facts, not a row per event**: about a
  sixth of the space at 2,000 devices.
* **Partitions by retention class, then day**, so that each
  organization's retention frees space on time.
* **`log.view` is Site Administrators and above**, as `audit.view`, not
  Organization Administrators; command lines stay with Organization
  Administrators.
* **Events of EasyRMM's own jobs are kept**, with their command lines and
  script text replaced by the run, not dropped: what ran stays visible.
* **Module logging is not configured**; script block logging is.
* **`auth.log` and `secure` are read only without a journal**.
* **A source pauses instead of dropping** when its spool share is full,
  since Windows' logs, the journal and auditd's files hold the events.
* **The persistent journal stays on undo.**
* **auditd's removal is last one out**, amending ADR-0051.
* **Detections are alert policies of a new kind** with a fixed set.
* **Device logs go over TCP or TLS only**; organizations' own destinations
  are a later slice.

## Consequences
* An MSP sees sign-ins, account and group changes, processes, scripts,
  services, antivirus detections and protection changes across its
  customers' Windows and Linux computers in EasyRMM, is alerted on the
  ones that matter, and sends them to its SIEM, without another agent.
* Each computer gets stronger logging by default, which its own Event
  Viewer and journal keep too; Group Policy keeps precedence; uninstalling
  puts it back, except the persistent journal.
* The deployment gains a second PostgreSQL instance and, at 2,000 devices
  and 30 days, roughly 150 to 200 GB of disk for logs, best on a disk of
  its own; the guide's host requirements say so per fleet size.
* A device may lose events only when the computer's own log wraps past
  what was read, which is counted and shown; events can arrive twice only
  after a computer is restored from a snapshot, or at a forwarding
  destination after a failure.
* Logs survive the updater's rollback; the main database's restore can
  leave logs of devices it no longer knows, which the weekly sweep
  removes.
* Searches over a whole fleet's month by free text can take several
  steps; searches by device, user, address or code are quick.
* People who can see a computer's sign-ins can see who works when;
  customers can decline collection per organization, and every search is
  audited for their administrators.
* ADR-0023's single collector becomes a list; ADR-0052's copy leaves the
  store out; ADR-0051's undo follows the last-one-out rule for auditd;
  ADR-0054 is to leave audit policy to this feature; ADR-0058 must allow
  keys that stay on the server; ADR-0053's rules gain the `log` condition
  and these EasyRMM events. database.md, backup-restore.md, rbac.md,
  PRIVACY.md, the guide, IMPLEMENTATION_STATUS, ROADMAP and the CHANGELOG
  change with each slice.
