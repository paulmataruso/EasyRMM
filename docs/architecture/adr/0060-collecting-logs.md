# ADR-0060: Collecting logs

* Status: Proposed (2026-11-21). Not implemented. Revised six times the
  same day after an independent review and five checks.
* Builds on: [ADR-0002](0002-postgresql-rls-tenant-isolation.md)
  (row-level security), [ADR-0009](0009-agent-protocol.md) (the agent
  protocol, with its section "Evolving the protocol" from pull request
  #52, merged on 2026-11-21 after this branch began),
  [ADR-0017](0017-scripts-and-jobs.md) (jobs),
  [ADR-0019](0019-monitoring-and-alerts.md) (alerts),
  [ADR-0023](0023-audit-forwarding.md) (audit forwarding),
  [ADR-0024](0024-enrollment-approval.md) (approval tokens),
  [ADR-0027](0027-agent-updates.md) (agent updates),
  [ADR-0050](0050-removing-a-device.md) (removing a device),
  [ADR-0051](0051-hardening-linux-computers.md) (hardening Linux),
  [ADR-0052](0052-the-host-updater.md) (the host updater), and three ADRs
  proposed beside this one and not merged yet, so cited without links:
  ADR-0058 (signed settings, the plan's F1), ADR-0053 (one notification
  sender, F2) and ADR-0054 (hardening Windows).
* Amends: [ADR-0017](0017-scripts-and-jobs.md) (Windows jobs inside
  their job object, slice 0; Linux jobs with a login UID of their own,
  slice 2; its guidance: no secrets as arguments),
  [ADR-0023](0023-audit-forwarding.md) (one list of syslog destinations),
  [ADR-0051](0051-hardening-linux-computers.md) (who removes auditd) and
  [ADR-0052](0052-the-host-updater.md) (the updater never touches the log
  store or waits for it, keeps its `.env` lines across a rollback, and
  reports the data root's size).
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
  5424 messages whose text is the record in JSON, over TLS (1.2 or later;
  a pasted CA as the only trust anchor when one is given, else the
  system's roots; an optional client certificate with its key sealed),
  TCP or UDP (`service.go`, `transport.go`, `message.go`). It dials
  through `server/internal/netguard`, which refuses link-local addresses
  and two cloud metadata addresses and allows loopback and private ones.
  Audit retention waits for the collector.
* **Agent requests are signed over their body.** The signature covers the
  body's SHA-256 (`internal/agentproto/agentproto.go`). The server checks
  the header before reading the body, so an unknown device's body is
  never read; a device removed by force (ADR-0050) is known, so its body
  is read and then refused on routes that do not serve it (`signedFor`).
  It reads at most 1 MiB (4 MiB for inventory and job results) within
  two minutes. Each device may send one signed request a second with
  bursts of 120; the limit is checked before the body and spent only
  after the signature is verified, so that requests naming someone else's
  device cannot use up its allowance
  (`server/internal/httpapi/agentapi/agentapi.go`). Answers the agent acts
  on can be signed back to the request (`signDownload`).
* **Evolving the protocol** (ADR-0009, pull request #52, merged on
  2026-11-21 after this branch began):
  the server ignores request fields it does not know (protocol level 2);
  heartbeat answers carry `protocol: 2`; agents send fields added after
  level 2 only to servers of that level or higher; features the agent's
  behaviour depends on are listed in the answer; an unknown endpoint
  (`404`) means "not supported". Before the body, the server checks only
  the header's form, its freshness and that the device exists
  (`BeginSigned`, `server/internal/agents/signed.go`), so a sender who
  knows a device's ID can start requests in its name.
* **The agent runs with full rights and no limits.** Its systemd unit sets
  no limits (`UnitContent`, `agent/host/service.go`); the Windows service
  runs as LocalSystem (`agent/host/system_windows.go`). Its state, with
  the device's key, is `/var/lib/easyrmm-agent` or
  `%ProgramData%\EasyRMM\Agent`, which only SYSTEM and Administrators can
  reach (`protectedDACL`). On Linux it is always a systemd service
  (`install.sh` installs it as one), and it updates itself by executing
  the new build in its own process
  (`agent/cmd/easyrmm-agent/restart_other.go`).
* **Job arguments are on the command line.** Each run gets a directory
  with a random name, `run-*`, under the jobs directory
  (`agent/jobs/exec.go`). On Windows PowerShell runs `-File script.ps1`
  followed by the arguments, so `-Name value` binds named parameters, and
  cmd gets them inside its `/C` line (`agent/jobs/exec_windows.go`); on
  Linux the interpreter (`sh`, `bash` or `python3`,
  `internal/agentproto/jobs.go`) gets the script and the arguments
  (`agent/jobs/exec_unix.go`). Process auditing records command lines
  (Windows' 4688 once command lines are on, auditd's `EXECVE`), and other
  local processes can read them while the job runs. ADR-0017 keeps
  argument values out of the audit log for this reason. On Windows the
  job object is made and assigned after the process has started, and a
  run goes on without one if that fails (`start`).
* **Linux jobs are not audited today.** The agent is a systemd service,
  so its jobs have no login UID; rules for what people run (`auid` set)
  never match them.
* **Secrets reach the logs this feature reads.** The console's Windows
  install command runs `install.ps1` as a script block with
  `-Token '<token>'` (`windowsInstallCommand`,
  `web/src/pages/devices/AddDevicesPage.tsx`), which script block logging
  records; `install.sh` still takes `--token`, which "puts the token on
  sh's command line" (`server/internal/httpapi/agentapi/install.sh.tmpl`).
  Deployment and approval tokens are `ert_` and 43 base64url characters
  (`newTokenSecret`, `server/internal/agents/tokens.go`), usable for 1 to
  90 days until used up; an approval token's devices wait for approval
  (ADR-0024).
* **One PostgreSQL holds every database.** The deployment's PostgreSQL
  (`deploy/docker-compose.yml`: host networking, loopback port 15432,
  `max_connections=200`, `shared_buffers=256MB`, initialised with
  `--auth-local=peer`) holds EasyRMM's database, the engine's and
  Authentik's. `easypatch-db-init` sets its roles' passwords from `.env`
  each time it runs (`docker/postgres/easypatch-db-init.sh`); the engine's
  services depend on it, the server does not, and the engine's secrets
  are not required by Compose (`:-`), so a broken engine never keeps
  EasyRMM from starting. Tenant
  tables force row-level security on the `easyrmm.scope_*` settings
  ([database.md](../database.md)); because forcing applies to the owner
  too, owner-run code needs an owner policy (`audit_forwarding_owner`,
  migration 00008) and owner functions fix their `search_path`
  (`easyrmm_purge_audit`). Deleting an organization, site or device fires
  `BEFORE DELETE` triggers that record what the engine must undo
  (migration 00020).
* **The data root and the updater.** Everything the deployment keeps is
  under one data root (`/srv/easyrmm`, or `setup.sh --data-root`,
  `deploy/scripts/setup.sh`). The updater
  ([ADR-0052](0052-the-host-updater.md#an-upgrade)) copies the whole data
  root and the deployment directory with `.env` before each upgrade
  (checking for room first); a rollback moves the failed data root aside,
  keeps it until the next successful upgrade, restores the copy into an
  empty root and brings back the previous `.env`. `setup.sh --upgrade`
  then adds secrets missing from `.env` with new values (`fill_secret`).
  While the updater's `hold` file exists (pull request #51:
  `/run/easyrmm-updater/hold` in the server), the server answers `503`
  with `Retry-After` and its readiness check still passes. A database
  inside the shared PostgreSQL could not be left out of the copy: the
  transaction log and the record of which transactions committed belong to
  the whole cluster, so a cluster with one database's newer files is
  corrupt.
* **Alerts are seen by everyone who sees the device** (`alerts_read`,
  migration 00006; `alert.view` from Read-Only up,
  [rbac.md](../../security/rbac.md)), and ADR-0053 (proposed) sends them
  to chat and webhooks.
* **Hardening.** [ADR-0051](0051-hardening-linux-computers.md) writes
  `/etc/audit/rules.d/60-easyrmm-hardening.rules`, says "Log collection
  will keep its rules in another file", and reports rules already
  immutable instead of loading them. Its script in progress (H2, on the
  hardening branch) keys its rules `easyrmm-hardening-*`, ignores other
  `easyrmm-` keys in its check, generates the rules per computer (a watch
  on `sshd_config.d` only where it exists), and on undo keeps auditd
  while another `*-easyrmm-*.rules` file exists, after which its record of
  having installed auditd is gone. ADR-0054 (accepted 2026-11-22)
  makes its `audit` module report only and leaves Windows audit policy to
  this feature; as decided in its review, it compares against this ADR's
  audit table and builds, in its slice W1, the one reader of who owns a
  setting. As written at its revision of 2026-11-21 (commit `27b05a0`),
  that reader reads Group Policy's resultant set of policy and `gpresult
  /x`, the MDM Bridge in `root\cimv2\mdm\dmmap`, OSConfig, and Defender's
  Tamper Protection, and gives check only where it cannot read the owner:
  resultant set of policy logging turned off (`RSoPLogging` 0), Group
  Policy Preferences and MDM until W1 proves how to read them, the
  Configuration Manager client, PowerShell DSC in `ApplyAndAutoCorrect`,
  and Azure machine configuration. Its check (M6) has the reader give a
  result for each value: an owner and its policy, none, or *cannot tell*
  with the reason; that definition is ADR-0054's to write, and this ADR
  follows it.
* **Test harnesses.** CI's Windows job runs the agent's Windows tests for
  real on `windows-latest`, as an administrator
  (`.github/workflows/backend-tests.yml`, "Agent tests on Windows"); the
  bundle test runs the deployment with a data root of its own and checks
  that nothing is made under `/srv/easyrmm`, beside a Debian machine with
  systemd, on host networking (`scripts/e2e/bundle.sh`); `tools/agentsim`
  simulates thousands of agents; `server/internal/auditfwd/collector_test.go`
  has a syslog receiver on loopback. The machine test harness
  (`internal/vmtest`: distributions' cloud images under QEMU with user
  networking) is on the hardening branch, not yet on `main`.

### How much
The volume decides the store. These are assumptions, after the default
filters below (which leave out computer accounts' network sign-ins and the
heavy events of the audit table), until slice 1 measures real computers;
the store's layout is confirmed or changed from those measurements before
slice 2 merges:

| Kind | Devices | Events a day each | Raw a day each | Raw a day, all |
|---|--:|--:|--:|--:|
| Windows workstation | 1,700 | 10,000 | 9 MB | 15.3 GB |
| Windows member server | 200 | 50,000 | 45 MB | 9.0 GB |
| Domain controller | 50 | 200,000 | 180 MB | 9.0 GB |
| Linux server | 50 | 20,000 | 14 MB | 0.7 GB |
| **An MSP with 2,000 devices** | | **38 million** (440 a second, peaks of several times that) | | **34 GB** |

Windows is 33.3 of the 34 GB, so the measurements that matter are
Windows', taken before the store is built. A raw event is about 900 bytes
on Windows (its fields as JSON, without the rendered message) and 700 on
Linux. Thirty days are about 1 TB of raw events.

* **A row per event in PostgreSQL** costs about 1.1 KB with its tuple
  header and two indexes (rows under 2 KB are not compressed): about
  1.25 TB for 30 days, 1.1 billion rows, written twice (heap and
  transaction log).
* **Compressed blocks** of events cost the compressed events (6 to 8 times
  smaller is assumed: 130 to 170 GB for 30 days), a row and three
  indexes per block (1.8 million blocks a day at the upload pace below:
  about 8 GB), and the hourly facts searches use (below: 10 to 30 GB,
  most of it domain controllers' many users and addresses). About 150 to
  210 GB.

## Decision

### In short
* The agent runs a **collector**, a process of its own without the
  device's key, network access, privileges or rights to change anything,
  with CPU,
  memory, bandwidth and disk limits. It reads Windows' event logs and
  Linux's journal and auditd log from its own positions, filters, redacts
  EasyRMM's tokens and writes batches to a spool; the agent seals them
  (marking its own jobs' events) and uploads them, signed and compressed,
  and the server stores each exactly once.
* **Configure logging** (on by default) sets Windows audit policy from one
  table shared with hardening, log sizes and PowerShell script block
  logging, command lines in process events per organization (on by
  default), and on Linux auditd rules and a persistent journal; it leaves
  what Group Policy, MDM or another owner holds, and undoes its changes on
  uninstall. Jobs start as today, with Windows jobs inside their job
  object from the start (slice 0) and Linux jobs with a login UID of
  their own (slice 2), so that their events are known; their argument
  values are replaced in EasyRMM's copy of those events, while the
  computer's own logs hold them.
* The logs live in a **PostgreSQL instance of their own, outside the data
  root** that the updater copies, as compressed blocks with hourly facts,
  partitioned by retention class and time, under row-level security.
  Quotas per kind of computer, a storage share per organization, a size
  cap and a free-disk floor stop ingest before the store can fill its
  disk, refusing the organizations over their share first. Nothing
  depends on the store: a broken one degrades logs, never EasyRMM.
* The console searches them (**Logs**, and a device's **Logs** tab);
  command lines and script text need a permission of their own, enforced
  by the server in results, text search and exports.
* **One list of syslog destinations** carries the audit log and device
  logs; built-in **detections** raise alerts, carrying no event's
  content, that the rules of ADR-0053 (proposed) send.

### Two switches
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
* **While collection is off for the platform**, the collector counts
  events per source under the filters (counts only, sent with its status),
  so that Settings → Logs can show the volume per kind of computer before
  anyone turns collection on. An organization that declined collection
  (`logs.collect` off for it) is not counted either.
* **Turning collection off** for a device, in the signed settings (F1),
  deletes its spool and positions; turning it on again starts from that
  moment. No other answer deletes anything (Uploading). The first start
  ever reads the previous 24 hours too, so that what led up to an install
  is there.

### What is collected
Each source has a default filter for its security-relevant part, which
organization administrators can change (`logs.sources`): sources on or
off, codes included or excluded, a minimum level, and whether a source is
a **priority source** (below). They can add up to ten sources of their
own (a Windows channel, or journal matches by unit or identifier), each
with a filter.

**Windows** (each channel read only where it exists):

| Source | Channel | Default filter |
|---|---|---|
| `windows.security` (priority) | Security | 1102 (log cleared), and the events marked collected in the audit table (Configuring logging). Sign-ins of SYSTEM, LOCAL SERVICE, NETWORK SERVICE, the window manager's and font driver's accounts, services' sign-ins, and computer accounts' (`HOST$`) network sign-ins are left out: a domain controller or file server records one for every computer that touches it |
| `windows.system` | System | Critical and error from any provider; 104 (log cleared), 1074 (restart and by whom), 6005, 6006, 6008 (starts, unexpected stops), 7040, 7045 (service changed, installed) |
| `windows.application` | Application | Critical and error; 1033, 1034, 11707, 11724 (programs installed and removed) |
| `windows.defender` (priority) | Microsoft-Windows-Windows Defender/Operational | Detections and actions (1006 to 1009, 1015, 1116 to 1119), scans failed (1005, 2001, 3002), protection changed or off (5001, 5004, 5007, 5008, 5010, 5012), Tamper Protection blocking a change (5013) |
| `windows.powershell` | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational | 4104 (script blocks) |
| `windows.sysmon` (priority) | Microsoft-Windows-Sysmon/Operational, when Sysmon is installed | Every event but 3, 7, 10 and 22 (network connections, image loads, process access, DNS queries), the four a broad Sysmon configuration makes largest |
| `windows.rdp` | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational, -RemoteConnectionManager/Operational | 21, 23, 24, 25, 39, 40; 1149 |
| `windows.wmi` | Microsoft-Windows-WMI-Activity/Operational | 5861 (a permanent WMI subscription, a common way to persist) |

**Linux** (the agent always runs under systemd, so the journal is there):

| Source | Where | Default filter |
|---|---|---|
| `linux.auth` (priority) | The journal: facilities auth and authpriv (sshd, sudo, su, login, PAM, polkit, the account tools) and systemd-logind | Everything |
| `linux.audit` (priority) | auditd's log (`log_file` in `auditd.conf`) | Records carrying an EasyRMM key (`easyrmm-logs-*` and `easyrmm-hardening-*`), and sign-ins, authentication, sudo, account and group changes, audit configuration changes, auditd starting and stopping, SELinux denials and anomalies (`LOGIN`, `USER_LOGIN`, `USER_AUTH`, `USER_CMD`, `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`, `USER_MGMT`, `GRP_MGMT`, `USER_CHAUTHTOK`, `CONFIG_CHANGE`, `DAEMON_*`, `AVC`, `USER_AVC`, `ANOM_*`) |
| `linux.system` | The journal | Priority error and above, any unit |
| `linux.av` (priority) | The journal of Defender for Endpoint and ClamAV units, when installed (`mdatp.service`, `clamav-daemon.service`, `clamd@*.service`, `clamav-freshclam.service`) | Everything |
| `linux.file` | `/var/log/auth.log` or `/var/log/secure` | Only where the journal keeps nothing (`Storage=none`) or journald is not running. Elsewhere the journal holds the same messages, which rsyslog writes to those files from it: reading both would store each twice |

**Codes.** Every event gets a code that filters, detections and the
console use: a Windows event's ID; on Linux, a name the server's parser
gives the messages it knows (`sshd.accepted`, `sshd.failed`,
`sudo.command`, `sudo.denied`, `su.failed`, `useradd`, …) and auditd's
record type (`audit.USER_LOGIN`), else the program's identifier. The guide
lists them.

**Sensitive fields** are classified by field name, the same in every
source, built-in or custom; a custom source can mark more fields
sensitive, never fewer:

* Windows: `CommandLine` and `ParentCommandLine` (4688, Sysmon 1),
  `ScriptBlockText` (4104), `TaskContent` and `TaskContentNew` (4698 to
  4702), `ImagePath` (7045), `ServiceFileName` (4697), 5861's
  `CONSUMER` and `PossibleCause` (the subscription's command), and
  Sysmon 19's `Query` and 20's `Destination` (a WMI filter and consumer).
* **Rendered messages repeat those fields**, so an event with a sensitive
  field is kept without its rendered message (its fields carry
  everything), and any other event's message is itself treated as
  sensitive when its source is a custom one.
* Linux: auditd's `EXECVE` arguments (`a0` onwards), `PROCTITLE`'s
  `proctitle` and `USER_CMD`'s `cmd`; the journal's `_CMDLINE`; and sudo's
  command, which the parser takes out of the message (`COMMAND=`) into a
  field of its own, keeping a copy of the message without it.

### The collector
* **Its own process**, `easyrmm-agent collect`, the agent's own binary,
  which reads, filters, redacts and writes batches to its spool, and does
  nothing else: it has no network access, cannot reach the agent's state
  or key, and changes nothing on the computer. *Configure logging* runs
  in the agent (below), never in the collector.
  * **Linux**: its own unit, `easyrmm-agent-collect.service`, which the
    agent writes and removes like its own, with **no capability**
    (decided in review: with one that bypasses file permissions, a parser
    exploit could read `/etc/shadow` or host keys and carry them out
    through the spool):
    * `DynamicUser=yes` (an unnamed user of its own), `NoNewPrivileges=yes`,
      an empty `CapabilityBoundingSet=`, `ProtectSystem=strict`,
      `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`;
      `StateDirectory=easyrmm-collect` (the spool, the only place it
      writes); `InaccessiblePaths=` the agent's state and hardening's
      (`/var/lib/easyrmm-agent`, `/var/lib/easyrmm-hardening`);
      `RestrictAddressFamilies=AF_UNIX` and `IPAddressDeny=any`;
      `PartOf=` the agent's unit;
    * limits: `CPUQuota=20%` (a fifth of one processor),
      `MemoryHigh=192M`, `MemoryMax=256M`, `Nice=10`, `IOWeight=10` (a low
      share of the disk that cannot starve, unlike the idle class);
    * **the journal** through `SupplementaryGroups=systemd-journal`, the
      group `journalctl` is made for, so `journalctl` runs as the
      collector's user and opens the journal's files itself (passing it
      descriptors would not work: it finds and opens the files it needs);
    * **auditd's log**, which only root can read, through descriptors: the
      agent opens the current file and each rotated one read-only and
      passes the descriptors to the collector over a Unix socket in the
      spool, also after a rotation (the agent watches auditd's log
      directory), and the collector reads them by inode and offset as
      before.

    The collector can so read what any unprivileged user can, and the
    journal, and nothing else; what it writes goes only to its spool,
    which the agent uploads to EasyRMM's own server. Two limits remain:
    * **The journal group reads every unit's and every user's journal**,
      including secrets other services and users log there (a token in a
      unit's output, a password in a failed command). The collector's
      filters keep only what its sources select, but a compromised
      collector could put anything it reads into its spool, and so into
      the store, where holders of `log.view` would see it; redaction
      catches only EasyRMM's own tokens.
    * **Name lookups**: `AF_UNIX` is needed for the agent's socket, and
      over it a lookup through systemd-resolved (its socket in
      `/run/systemd/resolve`) or the system bus (`/run/dbus`) sends a name
      of the collector's choosing to the network, so a compromised
      collector could leak data in DNS queries. Slice 1 adds those two
      directories to `InaccessiblePaths=` and keeps that if `journalctl`
      still works without them; until that is verified, this is a limit.
  * **Windows**: a service of its own, `easyrmm-collect`, which the agent
    installs and removes with its own, running as its virtual account
    (`NT SERVICE\easyrmm-collect`, whose SID derives from the service's
    name and so is the same on every computer):
    * **Reading, without any group** (decided in review: on a domain
      controller Event Log Readers is a domain group, and adding to it
      would change the directory): *Configure logging*, or the agent when
      that is off, adds read access (`0x1`) for the collector's SID to the
      access list of each channel it collects (`wevtutil sl <channel>
      /ca:`), the list before recorded for undo, on every computer. Where
      Group Policy's "Configure log access" sets a channel's list, owners
      win and the list is never changed: if it already grants the
      collector's SID read access (the channel's effective list, from
      `wevtutil gl`, holds such an entry), the channel is collected;
      otherwise it is *managed elsewhere*, not collected, and the device's
      tab says to add the collector's SID to that policy. Where the reader
      *cannot tell* who owns the list (Owners win, below), the list is not
      changed either, and the same holds: collected if it already grants
      the SID, otherwise not, with the reason and the same advice. Whether
      the Security log's list can be changed this way is checked on the
      runner first (slice 3).
    * Its spool, `%ProgramData%\EasyRMM\Collect`, is made with access for
      SYSTEM, Administrators and that account only; the agent's state is
      not readable by it (`protectedDACL`).
    * **No network**: the collector's code opens no sockets, and a
      persistent filter of EasyRMM's own in the Windows Filtering Platform
      blocks connecting and listening for the service's SID. Such a filter
      works whether or not Windows Firewall is on (third-party firewalls
      often turn it off), since both use the platform; where the filter
      cannot be added, the device's tab says so, and the limit is that a
      compromised collector could then reach the network as its own
      account, which holds no secret of EasyRMM's. Name lookups go through
      the DNS Client service (Dnscache), which sends the query as its own
      account, so the filter does not stop them: a compromised collector
      could still leak data in DNS queries, which is a limit too.
    * It puts itself in a job object at start, with a hard CPU rate cap of
      a fifth of one processor, a memory limit of 256 MiB and
      kill-on-close, and enters background processing mode (lower I/O and
      memory priority).
  * Both run with `GOMAXPROCS=1` and a Go memory limit under the hard one.
    The limits never slow jobs, which run in the agent's process tree.
    The work the Event Log service does for the collector's queries
    (evaluating the filter, rendering) is outside the cap: the collector
    pulls at most a set number of events a second per source while
    catching up, and the Windows runner test measures the service's
    processor use during a flood.
  * After the agent updates itself (ADR-0027), or rolls back after a
    crash, it restarts the collector, so that both run the same build.
* **Reading**, without cgo:
  * **Windows**: the Event Log API (`wevtapi.dll`: `EvtSubscribe`,
    `EvtNext`, `EvtRender`), one pull subscription per source starting
    after its bookmark, strictly, so that a bookmark Windows no longer has
    (a cleared or wrapped log) is noticed. Filters go into the
    subscription's XPath query where they fit, so that Windows does not
    render what is dropped. A filtered subscription's bookmark names the
    last *matching* record, so a quiet source would report a false gap
    once the log wraps past it: the collector also reads the log's newest
    record number before draining the subscription, and once it is
    drained records that every record up to that number was considered.
    A gap is reported only when the oldest record in the log is past that
    position. Each event's system fields and its `EventData` or `UserData`
    are kept; the rendered message, capped at 2 KiB, only outside the
    Security log (whose events are known by ID and fields, and whose
    message would triple their size) and never for an event with a
    sensitive field (Sensitive fields).
  * **Journal**: `journalctl --follow --all --output=json` from the
    source's cursor with its matches (`--all`, or fields over 4,096 bytes
    come out empty). The journal's file format is internal to systemd;
    `journalctl` is wherever the journal is. `--after-cursor` passes over
    entries vacuumed since without a word, so at each start the collector
    compares its cursor's time with the oldest entry the journal holds and
    reports a gap of unknown size when the oldest is later.
  * **auditd**: its log file, through the descriptors the agent passes,
    by inode and offset, following rotations, with the records of one
    event (one serial) grouped, and the values
    auditd writes in hexadecimal (`proctitle`, `EXECVE` arguments, `cmd`,
    anything with spaces) decoded.
  * **Gaps** (entries gone before they were read) are reported with their
    size where the source tells it (Windows' record numbers, auditd's
    serial numbers within a boot), else as of unknown size.
* **Crashes**: each event is parsed and filtered under a recovery from
  panics; one that panics is counted as a gap and passed. Against crashes
  a recovery cannot catch, the collector records the position it starts
  reading from; after a crash it reads from there one event at a time,
  recording each position first, and an event during which it crashed
  twice is passed and counted as a gap, so that one crafted entry cannot
  hold a source forever.
* **The spool**: `/var/lib/easyrmm-collect` or
  `%ProgramData%\EasyRMM\Collect`, append-only segments per source, each
  record framed with its length and a checksum, and **each append
  carrying the source's new position**: an event and the position after it
  are written together, synced at most once a second. After a crash a torn
  tail is cut off and reading resumes from the last position written;
  nothing is read twice into the spool or skipped. Segments and batches
  carry a format number; a format changes only in ways the previous agent
  release reads, so an agent that rolls back keeps its spool.
* **Its limits**: 256 MiB in all by default (`logs.spool`), at most a
  quarter of it per source, and never past a free-space floor on its
  volume (1 GiB or 5%, the smaller). **A source whose share is full pauses
  instead of dropping**: its events wait in Windows' log, the journal or
  auditd's files, which are themselves buffers of hours to days, and only
  a source that wraps past its position loses events, counted as a gap. A
  flood in Application pauses Application, never Security.
* **Redaction** before the spool, on every text field, decoded first
  (auditd's hexadecimal, the journal's byte arrays, which `journalctl`
  prints for values that are not text) and, for PowerShell's 4104, on the
  whole script: a script too long for one event comes in parts with one
  script block ID, which are joined before redaction (a part waits at most
  a minute for the others; one whose others never come is redacted alone
  and marked incomplete), so that a token split across two parts is
  found. `ert_` followed by 43 base64url characters becomes
  `ert_[redacted]`, and the value after `EASYRMM_TOKEN=`, `-Token` and
  `--token` becomes `[redacted]`. Each batch says how many it redacted.
  The agent applies the rules again when it seals a batch, and the server
  once more. Other secrets that people put on command lines and in scripts
  are why those fields need a permission (Sensitive fields).
* **Batches**: two **streams** per device, *priority* (the priority
  sources above) and *other*, each with its own batches. The collector
  closes a batch when 512 KiB are waiting, when the oldest event has
  waited 2 minutes, or 10 seconds after an event that a detection uses
  arrived (the settings carry those codes); a batch is never larger than
  what the device's bandwidth (below) sends in 20 seconds, so that a slow
  link still delivers each within the server's body deadline (at 16 KiB/s,
  320 KiB). At most one upload every 10 seconds.
* **Sealing**, by the agent, which holds the key and knows its jobs: it
  takes a closed batch from the spool, marks the events of EasyRMM's own
  jobs and replaces their argument values (below), applies the redaction
  rules again, numbers it in its stream and records its hash. A sealed
  batch is fixed: a retry, also after a restart, sends the same bytes
  under the same number.
* **EasyRMM's own jobs** stay visible, since a SIEM must see what the RMM
  ran: their process creation events (4688, Sysmon 1, auditd `EXECVE`)
  and script blocks (4104) are kept with their command lines and script
  text, and gain the run's ID and the script's SHA-256. Job arguments stay
  on the command line, as today (slice 0), so sealing replaces them by
  `[job argument 2]`, never by a hash, which a short password would not
  survive:
  * **The run's own command line, by record** (decided in review). When
    it creates the run's process, the agent records the exact command
    line it built and the position of every token in it. Sealing
    replaces that line wherever it appears, in any event of any source
    during the run's lifetime, whether or not the event is marked as the
    run's: every argument token is replaced whole, quotes and escapes
    included, parameter names too, and the interpreter, its options and
    the script's path are kept. Sealing never searches for a value's
    text in that line. It covers:
    * on Windows, 4688's and Sysmon 1's `CommandLine` of the run's
      process; a child's `ParentCommandLine`, also when the job object's
      `JOB_OBJECT_MSG_NEW_PROCESS` was dropped, since the line is matched,
      not the process; and PowerShell's *Host Application* in the
      PowerShell Operational log's 4100 and 4103 and in the classic
      Windows PowerShell log's 400, 403 and 600;
    * on Linux, `EXECVE`'s arguments by index (`aN`, and each `aN[k]`
      chunk of a long one, with `aN_len` dropped); `PROCTITLE` by
      position, including a value the kernel cut off at its 128-byte
      limit; and the journal's `_CMDLINE`.

    The agent keeps each run's command line and token positions in its
    protected state, which the collector cannot read, until every
    source's position has passed the run's end, then deletes them.
  * **In what the script passes on** to programs it starts: values of six
    characters or more, wherever they appear in that run's events
    (shorter ones are rarely secrets and would match too much).

  The replacing happens at sealing, so the collector's spool on the
  computer holds the raw values; it is readable only by administrators
  (root on Linux) and the collector, no wider than the Security log.
  Beyond that it protects what leaves the computer (sealed batches, the
  store, forwarding), not the computer's own logs, which hold the values
  as for any process (Consequences; ADR-0017's guidance gains: do not
  pass secrets as arguments). `job.view` shows the run with its
  arguments (amended by
  [ADR-0063](0063-who-sees-job-output-and-arguments.md): the argument values
  need `job.view_sensitive`, each read audited). A job's processes are known by more than their ID, which
  Windows and Linux reuse:
  * **Windows**: after slice 0 every run's process starts inside its job
    object; the agent asks the job object to report every process that
    joins it (`JOB_OBJECT_MSG_NEW_PROCESS` on the job's completion port)
    and records its ID and creation time; an event matches by both.
  * **Linux**: jobs are audited by a rule of their own (decided in
    review). The agent starts each run through a small launcher, its own
    binary, which writes the login UID of a system user the agent creates
    at install, `easyrmm-jobs` (no shell, no home), to
    `/proc/self/loginuid` before it executes the interpreter. The kernel
    then gives the run an audit session of its own, inherited by
    everything it starts; the agent records the run's session ID, and
    *Configure logging*'s rules file holds a rule for `execve` by that
    login UID, keyed `easyrmm-logs-jobs`. An event matches a run by its
    session ID, which the kernel does not reuse while it runs: auditd's
    records carry `ses`, and the journal records `_AUDIT_SESSION` with
    each entry, so that sudo's `COMMAND=` lines (`linux.auth`, slice 2)
    match too. The launcher and this matching come with slice 2 (decided
    in review), the rule with slice 4. Without
    *Configure logging* (or without auditd, or where the kernel refuses
    the login UID, as in a container) Linux jobs are not audited, and the
    device's tab says so. Jobs still run as root; only their login UID
    changes. A job could still change its own login UID; that is
    reported as the job's last event, not prevented.
* **Bandwidth**: uploads are paced to `logs.bandwidth` (128 KiB/s by
  default, set per site for slow links, at least 8 KiB/s), with jitter.

### Uploading
`POST /api/agent/v1/logs`, signed like every agent request, its body JSON
compressed with gzip (`Content-Encoding: gzip`): the spool's generation (a
random ID made with the spool), the stream, the batch's number and the
SHA-256 of its content, the agent's clock, and per source its events, its
position, and what it dropped, filtered and redacted. The agent sends it,
and the status below, only to a server whose heartbeat answer lists the
`logs` feature (ADR-0009's rule for features, pull request #52); the
batch's and the status's fields follow that ADR's rules too.

* **Read in order**:
  1. The header is checked first; an unknown device's body is never read.
     Before reading, two counts are taken, both answered `503` with a
     jittered `Retry-After` when full: at most 64 log bodies read at once
     on a server, and at most two for the device the header names (which
     is not proven until the signature is checked, so this count is per
     *claimed* device).
  2. At most 2 MiB as sent, within 30 seconds, and never slower than 4
     KiB/s after its first 5 seconds (a batch is sized for that, and
     `logs.bandwidth` cannot be set below 8 KiB/s).
  3. The signature verified over those bytes; a device removed by force is
     then refused, as on other routes.
  4. Then the device's limits are spent: one upload every 10 seconds with
     bursts of six, on top of the limit every signed request has, and
     **one upload in flight per device** (a second gets `429`).
  5. Then a processing slot, at most 16 on a server, waited for at most 5
     seconds, else `503` with a jittered `Retry-After`, so that 2,000
     devices returning after an outage do not arrive at once.
  6. Decompressed and parsed as a stream, never held whole, **stopping at
     16 MiB**; at most 10,000 events, each at most 32 KiB once normalized
     (longer fields are cut, and the event says so). The device,
     organization and site come from the signature's device, never from
     the body.

  Memory is so bounded at about 64 × 2 MiB of bodies and 16 uploads of a
  few MiB each. A sender without a device key needs 32 device IDs to fill
  the 64 reads, each body for at most 30 seconds at no less than 4 KiB/s,
  which delays log uploads and nothing else; one who knows a device's ID
  can delay that device's log uploads the same way.
* **Exactly once**: the store keeps, per device and stream, the
  generation, the highest batch number stored and that batch's hash, and
  stores a batch, its blocks and the device's usage in one transaction
  that takes that row's lock first and reads the store's era (Forwarding)
  inside it. The blocks and facts are prepared (compressed, hashed)
  before it begins, and their receipt sequence numbers are drawn last,
  just before the commit (decided in review), so
  that the transaction is short. It sets `SET LOCAL
  transaction_timeout = '30s'` (which ends the connection, and the pool
  drops it), only so that a stuck transaction cannot hold the device's
  lock and the forwarding horizon (Forwarding) for long; nothing depends
  on it for correctness. The same number with the same hash is
  a retry, answered as stored without storing it again. Anything else at
  or below the highest number (a computer restored from a snapshot, whose
  spool sends numbers already used with other contents) is answered
  `409 resync`: the agent starts a new generation and sends again from its
  spool, so events may arrive twice there, never be lost. A new
  generation (a reinstalled agent, a resync) starts a new count.
* **Answers**, each signed back to the request as `signDownload` does, and
  acted on only when the signature is valid. Anything unsigned (a proxy's
  error, the updater's hold) is retried with backoff (at most an hour
  apart) and reported in the status, and never deletes a batch; only
  `413`, `408` and `404` are also understood unsigned (below), and only
  five `413`s at the floor set a batch aside. A proxy in front of the
  server is trusted that far: it could already drop every upload.
  * `200` with how much more the device may send today per stream
    (`budget`, bytes, and when it renews).
  * `429` with `Retry-After` when a quota is used up or ingest is stopped
    for the organization (`logs_quota`, `logs_paused`), or the device has
    an upload in flight.
  * `503` with `Retry-After` when the store is unavailable, busy, or the
    server is held.
  * `403 logs_off` when collection is off for the device: the agent
    pauses and keeps its spool until its signed settings say otherwise.
  * `409 resync` (above).
  * `413` for batch N, signed or not (a proxy in front of the server may
    allow less than 2 MiB; nginx's default is 1 MiB): nothing was stored,
    so the agent unseals N and every later batch of that stream that is
    sealed but not stored, halves the stream's batch size, and seals
    again from N at the new size, splitting closed batches as it needs
    (decided in review). None of those later batches was sent, since a
    stream's batches go in order, one at a time, and their events stay in
    the spool until the server stores them. Only numbers never stored are
    used again; if N had in fact been stored (its answer lost, then a
    proxy's limit lowered before the retry), the resealed N is answered
    `409 resync` (above): nothing is lost, and events may arrive twice.
    Unsealing and sealing again is one atomic step of the spool (the new
    sealed batches replace the old with one rename of their directory),
    so that a crash leaves the old set or the new, never a mix.
    * The size has a floor of 64 KiB and grows back slowly after uploads
      succeed (by a quarter after each 20 stored in a row), staying below
      any size refused in the last 24 hours.
    * A batch at the floor, or one holding a single event, that is
      refused with `413` five times is set aside as below, with the reason
      `too_large`, and keeps its number; the stream goes on from the next
      number, so a limit no batch can meet never stops it.
  * **A body cut off** (decided in review): a `408 body_timeout` (unsigned,
    since the body was never verified, as `readBody` answers a body past
    its deadline today; the 30-second and the 4 KiB/s rules both answer
    it), or the agent's own send not finishing within 30 seconds, means
    the link is slower than `logs.bandwidth` for now. The agent unseals,
    halves and seals again as for a `413`, so that a link slower than its
    setting still uploads (64 KiB at the 4 KiB/s minimum takes 16
    seconds). At the floor the batch is retried with backoff and reported
    in the status, never set aside: a slow link can recover, the events
    wait in the spool and the sources pause. An unsigned `408` can only
    make batches smaller.
  * `404` (a server without this endpoint, such as one rolled back to an
    earlier release): not supported; the agent pauses, keeps its spool and
    tries again when a heartbeat answer lists `logs`.
  * Any other signed `4xx`: the batch is set aside (kept in the spool's
    `rejected/`, at most 32 MiB, oldest removed first), reported in the
    status with the reason, and the stream goes on; it is never retried
    forever.

  On every refusal the agent keeps its spool and its sources pause as
  their shares fill.
* **Status**: `POST /api/agent/v1/logs/status`, signed, when something
  changes and at least hourly: each source's state (position time, paused,
  gaps, drops, spool use, set-aside batches), the counts while collection
  is off, and the state of each change *Configure logging* makes. A change
  of the latter is audited (`device.logging_configured`,
  `device.logging_undone`).

### Configuring logging
It runs in the agent, never the collector: on Windows a PowerShell script
the agent carries, which reads who owns each setting with ADR-0054's
reader (built in its slice W1; this feature does not build another), and
on Linux a shell script; both report every change in the status. It runs
when its settings change, at the agent's start, and after Group Policy is
processed (seen in the GroupPolicy Operational log), at most hourly.

**Windows audit policy**, the one table (decided in ADR-0054's review):
ADR-0054's `audit` check cites it and compares against it. It adopts
the audit subcategories of Microsoft's security baselines for Windows 11
and Windows Server 2025; slice 4 checks
each value against the baselines' own files, and adds the same way
anything else they set. Values are only raised, never lowered. Volumes are
estimates of what each writes to the computer's own Security log, measured
in slice 1; the collector takes only the events in the third column. A
subcategory that would wrap a 1,024,000 KB Security log in under seven
days on a measured kind of computer becomes *baseline, not set by
default* by an amendment of this table, and ADR-0054 then shows it as
information, not a gap.

| Subcategory | Set | Collected by default (not collected) | Volume on the computer |
|---|---|---|---|
| Account Logon: Credential Validation | Success, failure | 4776 failures | Low; high on domain controllers (every NTLM sign-in) |
| Account Logon: Kerberos Authentication Service (domain controllers) | Success, failure | 4768, 4771 failures | High (every ticket) |
| Account Logon: Kerberos Service Ticket Operations (domain controllers) | Success, failure | 4769 failures | High |
| Account Management: Computer Account Management | Success | 4741 to 4743 | Low |
| Account Management: Other Account Management Events | Success | 4782, 4793 | Low |
| Account Management: Security Group Management | Success | 4727 to 4737, 4754 to 4758 (not 4799, a group's members listed) | Low; 4799 moderate |
| Account Management: User Account Management | Success, failure | 4720 to 4726, 4738, 4740, 4765 to 4767, 4780, 4781, 4794 (not 4798, a user's groups listed) | Low; 4798 moderate |
| Detailed Tracking: Plug and Play Events | Success | 6416 | Low |
| Detailed Tracking: Process Creation | Success | 4688 | Moderate to high: one per process |
| DS Access: Directory Service Access (domain controllers) | Failure | 4662 failures | Low |
| DS Access: Directory Service Changes (domain controllers) | Success | 5136, 5137, 5138, 5139, 5141 | Moderate, with the directory's changes |
| Logon/Logoff: Account Lockout | Failure | 4625 | Low |
| Logon/Logoff: Group Membership | Success | None (4627, one per sign-in, listing its groups) | As many as sign-ins, each large: high on servers |
| Logon/Logoff: Logon | Success, failure | 4624, 4625, 4648 (without the sign-ins left out above) | High on servers and domain controllers |
| Logon/Logoff: Logoff | Left as it is | 4647 (not 4634, every sign-out) | |
| Logon/Logoff: Other Logon/Logoff Events | Success, failure | 4778, 4779, 4800, 4801 | Low |
| Logon/Logoff: Special Logon | Success | 4672, 4964 (without the system accounts') | Moderate |
| Object Access: Detailed File Share | Failure | None (5145 failures) | Low; moderate on file servers with misconfigured clients |
| Object Access: File Share | Success, failure | 5142, 5143, 5144 (shares added, changed, removed; not 5140, each share session) | High on file servers and domain controllers, whose SYSVOL every computer reads |
| Object Access: Other Object Access Events | Success, failure | 4698 to 4702 (scheduled tasks) | Low |
| Object Access: Removable Storage | Success, failure | None (4663, one per file touched on a removable disk) | None to very high, with USB disks |
| Policy Change: Audit Policy Change | Success | 4719, 4906, 4912 (not 4907, which patching writes) | Low |
| Policy Change: Authentication Policy Change | Success | 4706, 4707, 4713, 4716, 4739 | Low |
| Policy Change: Authorization Policy Change | Success | 4704, 4705 (user rights; not 4703, a token's right adjusted, nor 4670) | 4703 high |
| Policy Change: MPSSVC Rule-Level Policy Change | Success, failure | 4946 to 4948 | Low; moderate where software adds firewall rules |
| Policy Change: Other Policy Change Events | Failure | None | Low |
| Privilege Use: Sensitive Privilege Use | Success, failure | None (4673, 4674) | Moderate to high: some programs use privileges constantly |
| System: Other System Events | Success, failure | 5024, 5025, 5030, 5034, 5035, 5037 (the firewall service; not 5058, 5059, 5061, key file operations) | 5058 and 5059 moderate to high |
| System: Security State Change | Success | 4608, 4616 | Low |
| System: Security System Extension | Success | 4610, 4611, 4614, 4622, 4697 | Low |
| System: System Integrity | Success, failure | 4612 (audit events lost), 4615, 4618, 5038 | Low |

The Kerberos and DS Access rows apply to domain controllers only, and only
when they are chosen (below).

**Windows, the other settings**, also only raised:

| Setting | Value | Why |
|---|---|---|
| Subcategories override categories | `SCENoApplyLegacyAuditPolicy` = 1 under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | Without it, legacy category settings can override the table. Set here, not only reported (STIG WN11-SO-000030); where Group Policy sets legacy categories, the whole audit policy is *managed elsewhere* and nothing in the table is set |
| Command lines in process creation events | `ProcessCreationIncludeCmdLine_Enabled` = 1 under `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit` | 4688's command line. Per organization (`logs.commandLines`, on by default); where it is set, the console says that the computer's own Security log then holds the arguments of every process, EasyRMM's jobs' included, for its administrators and Event Log Readers |
| Script block logging | `EnableScriptBlockLogging` = 1 for Windows PowerShell (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`) and PowerShell 7 (`…\PowerShellCore\ScriptBlockLogging`) | 4104 |
| Who can read the PowerShell logs | The two PowerShell Operational logs' access list (`wevtutil sl /ca:`), and the classic Windows PowerShell log's (its `CustomSD` under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell`, decided in review): read for SYSTEM, Administrators, Event Log Readers and the collector only; every other reader's read right removed, write rights unchanged, each list before recorded for undo | Script blocks hold whatever secrets scripts contain, and the classic log's 400, 403 and 600 hold every PowerShell host's command line, by default |
| The collector's read access | Read (`0x1`) for the collector's SID in each collected channel's access list, the list before recorded for undo (The collector) | Without a group change anywhere, also on domain controllers |
| Security log size | At least 1,024,000 KB (4 GiB on domain controllers when chosen) | The STIGs' minimum (WN11-AU-000505, WN25-CC-000280), which ADR-0054's check compares with; the 256 MiB first proposed would fail it. It costs at most a gigabyte of the system disk and keeps days of history on the computer for a collector that is paused or offline; a domain controller writes far more. Not raised where the system volume has under 10 GiB free: reported |
| Other log sizes | System, Application and the PowerShell Operational logs at least 65,536 KB | Above the STIGs' 32,768 KB for System and Application |

Not set: module logging (4103, which repeats much of what script blocks
show at many times the volume), Logoff (Windows' own default writes 4634,
which the collector leaves out), file system auditing (access lists on
files), Sysmon (installed and configured by its owner, or not at all),
and each log's retention mode (left as it is, and reported when it is not
"overwrite as needed": "do not overwrite" stops logging when full,
"archive" fills the disk). Protected Event Logging, which encrypts script
blocks to a certificate, was considered and not chosen: the collector
would forward text only the server could read, other local tools would
lose it, and its keys would be one more thing to manage.

**Owners win**, with ADR-0054's words and reader. For each value the
reader gives one of three results, as ADR-0054's check (M6) has it
define them: an owner and its policy, none, or *cannot tell* with the
reason. *Configure logging* acts on each:

* **An owner**: the value is never written. It is *in place* if the
  owner's value is as strict as the table's, otherwise *managed
  elsewhere*, naming the owner and its policy, with ADR-0054's words:
  *set by Group Policy* (from the domain or the local Group Policy
  object, with the policy's name), *set by MDM*, *set by OSConfig*, *set
  by Defender for Endpoint* and *protected by Tamper Protection*.
* **None**: the value is raised and its value before recorded for undo,
  as hardening does.
* ***Cannot tell***: **check only**, as hardening does (decided in
  ADR-0054's check): the value is reported against the table, with the
  reason, and never written. That is the result wherever an owner could
  hold the value and the reader cannot read it: resultant set of policy
  logging turned off; Group Policy Preferences and MDM until W1 proves
  their reading; and Configuration Manager's remediating baselines,
  PowerShell DSC and Azure machine configuration until readers for them
  exist. Each of these can own audit policy and log sizes (the check
  names Azure's Windows baseline and the `AuditPolicyDsc` module, which
  both set audit policy).

Audit subcategories that
Group Policy sets come from its own extension (Advanced Audit Policy
Configuration, from `audit.csv` files), not from registry policy, so
ADR-0054's reader takes them from `gpresult /x`'s audit settings with the
winning policy (W1 confirms this against a domain policy); this ADR's
tests and W1's use the same domain policies. A value set back twice
after EasyRMM set it has an owner the reader cannot see: it becomes
*managed elsewhere* (owner unknown) and is left from then on.

**Domain controllers** are left alone unless the operator chooses them
(`logs.configure.domainControllers`): their audit policy is the domain's.
Their logs are still collected.

**Linux:**

| What | Change |
|---|---|
| Persistent journal | `/var/log/journal` created and the journal flushed to it, where `Storage` is `auto` and the directory is missing (the journal is then kept in memory only). An explicit `volatile` or `none` is left and reported |
| auditd | Installed where missing (`auditd` on Debian and Ubuntu, `audit` on the RHEL family) from the distribution's repositories, enabled and started, and `/var/lib/easyrmm/auditd-installed` written (below). Not in containers, where the audit subsystem is the host's |
| Audit rules | `/etc/audit/rules.d/60-easyrmm-logs.rules`, keyed `easyrmm-logs-*`, generated for the computer, as hardening's are: the identity files, sudoers, SSH and PAM configuration, time, kernel modules, mounts, and commands run with raised privileges (as hardening's file), and also cron's and systemd's units under `/etc`, `/etc/ld.so.preload`, root's SSH keys, audit's own configuration, the commands people run (`execve` with a login UID from `UID_MIN` in `/etc/login.defs`, never unset), and EasyRMM's jobs (`execve` with the login UID of `easyrmm-jobs`, keyed `easyrmm-logs-jobs`). A watch is written only for a path that exists (`/root/.ssh`, cron's spool differ between computers), a system call rule only for the architectures and calls the computer has. `-b 8192` only where the loaded backlog limit is lower (recorded for undo). Never `-e`, `-f`, `-c`, `-i` or `auditd.conf` |

The commands rule also records cron's jobs and remote tools such as
Ansible, which run with a login UID; slice 1 measures it on machines with
a cron job every minute and an Ansible run, and the rule gains exclusions
if their share is large.

**Loading Linux's rules safely.** `augenrules` merges every file into one
and `auditctl -R` stops at the first line that fails, so one bad line in
this file would also stop every file after it (such as a
`99-finalize.rules` with `-e 2`). Nothing checks a rules file's syntax
before it loads (`augenrules --check` only says whether `audit.rules` is
older than the files), so the safety is the loading itself: the file is
generated from fixed lines for what the computer has, loaded with
`augenrules --load`, and every rule in it confirmed loaded. `auditctl
-l` prints the rules as the kernel holds them, normalised (syscalls and
`-F` fields in its own order, a watch possibly as a `-F path=` or `-F
dir=` rule), not as written, so the check compares by key and count: the
number of loaded rules carrying each `easyrmm-logs-*` key must equal the
number of the file's lines carrying it. If any falls short, the file is
removed and the rules loaded again, so that the computer is back to its
previous rules, and the change is reported failed. Where the loaded
rules are already immutable (`enabled 2`), the file is written, loads at
the next restart, and that is reported; undo cannot unload it before one
(as ADR-0051).

**Who owns what**, so that hardening and this feature never fight:

* **Windows**: the audit table, `SCENoApplyLegacyAuditPolicy`, command
  lines in process events, script block logging and its logs' readers,
  and log sizes belong to *Configure logging*. ADR-0054's `audit` and
  `powershell` modules report them against this table and name
  *Configure logging* (`logs.configure`) as the way to set them.
* **Linux**: hardening keeps `60-easyrmm-hardening.rules` with
  `easyrmm-hardening-*`, this feature `60-easyrmm-logs.rules` with
  `easyrmm-logs-*`; neither writes the other's file or any other, and each
  file stands alone. H2's check already ignores keys that are not its
  own. The kernel treats two rules that differ only by key as different
  rules, so both files load where both exist; an event matching both is
  recorded once, with the key of the rule loaded first (hardening's, which
  sorts first). The collector takes both features' keys. Both facts are
  checked on machines (Testing).
* **auditd itself**, last one out. Whichever feature installs auditd
  writes `/var/lib/easyrmm/auditd-installed` (outside both features'
  state, which their undo removes). Each feature's undo removes its own
  rules file and reloads; then, if no `*-easyrmm-*.rules` file is left in
  `/etc/audit/rules.d/`, every file left there is one the package shipped
  and unchanged (`dpkg --verify` or `rpm -V`: an operator's own rules
  keep auditd), and the marker exists, it removes auditd if removing it
  removes nothing else (simulated first), and the marker. H2 today keeps
  auditd while another EasyRMM rules file exists and then forgets that it
  installed it, so this feature's undo could never remove it: H2 adopts
  the marker, or, if it merges without it, slice 4 makes that change to
  hardening's script with hardening's tests. This replaces, for auditd,
  ADR-0051's record of the packages hardening installed.

**Undo**, on `easyrmm-agent uninstall` (and so the removal of a device,
ADR-0050, and of an agent package, feature 6) and when *Configure logging*
is turned off: each change is recorded before it is made (the value
before and the value set) in the agent's state (`logging.json`), and put
back only where the computer still has the value EasyRMM set; anything
changed since is left and reported. What Windows does with a log already
larger than its restored maximum is checked on CI's Windows runner and
documented. The persistent journal is left in place: removing it would
delete the logs kept since, and the guide says how to remove it. An agent
deleted by hand leaves logging configured, which is harmless.

### The log store
* **Where: outside the data root** (decided in review).
  `EASYRMM_LOGS_ROOT`, by default the data root's sibling `<data
  root>-logs` (`/srv/easyrmm-logs`; with `--data-root /data/rmm`,
  `/data/rmm-logs`), so that nothing is made under `/srv` when the data
  root is elsewhere:
  * `setup.sh` takes `--logs-root`, strips a trailing `/` from
    `--data-root` before adding `-logs`, writes the value to `.env`
    (`setup.sh --upgrade` adds the default when it is missing), and
    refuses a logs root inside the data root or the data root inside it;
  * Compose names it
    `${EASYRMM_LOGS_ROOT:-${EASYRMM_DATA_ROOT:-/srv/easyrmm}-logs}`,
    never a fixed `/srv/easyrmm-logs`;
  * it holds the cluster (`postgres/`, owner 70:70, mode 700, as the main
    one's), the local socket's directory (`run/`, owner 70:70, mode 700),
    `logs-db-init`'s status (`status/`, owner 70:70, mode 755) and a
    ballast file (below); run without root, `setup.sh` adds the three
    directories to those it asks the operator to create;
  * the updater never copies, moves or deletes it (amending ADR-0052,
    below), so a rollback cannot take it away and a later upgrade cannot
    delete it.

  A disk of its own is recommended above 500 devices.
* **A PostgreSQL instance of its own** (`logs-postgres`), from the same
  image as the deployment's, on host networking at loopback port 15433,
  initialised with `--auth-host=scram-sha-256 --auth-local=peer` as the
  main one, with its own roles (`easyrmm_logs_owner` for migrations and
  partitions, `easyrmm_logs_app` for the server). Its secrets are not
  required by Compose (`:-`, as the engine's are), so that missing ones
  never stop the deployment.
  * **The store's identity is `EASYRMM_LOGS_STORE_ID` alone**, a random
    ID in `.env` made by `setup.sh` and kept across a rollback with the
    other `EASYRMM_LOGS_*` lines (below). The server writes it into an
    empty store at first use. A store holding another ID (a reinstall that
    found an old store, an `.env` from elsewhere) is not used, and
    Settings → Logs says why and what to do, on the host, since the
    server cannot reach such a store: `setup.sh --adopt-logs-store` writes
    that store's ID, which `logs-db-init` reports, into `.env`, and the
    next start sets its passwords; or the store's directory is moved
    away. The server records in the audit log its first use of a store it
    had reported as another installation's.
  * **Passwords follow `.env`.** `logs-db-init` is a one-shot service, but
    unlike `easypatch-db-init`, which connects over loopback with the
    superuser's password (`PGPASSWORD`), it connects over the store's
    local socket as the `postgres` user, which peer authentication admits
    without a password. That needs the logs root's `run/` mounted as the
    socket directory in both `logs-postgres` and `logs-db-init`, and
    `logs-db-init` running as uid 70, the image's `postgres`. It sets the
    superuser's and both roles' passwords from `.env` each time the
    deployment starts, but only in a store that is empty or holds
    `.env`'s store ID (peer authentication would admit it to any store
    under that root). A `.env` restored by hand, or one whose values
    `fill_secret` made again, so leaves the store usable.
  * **The finished-restore marker** (decided in review): one row in a
    schema of its own, `easyrmm_logs_ready`, readable by the server's
    roles, holding the cluster's `system_identifier`. It counts only
    when that matches the cluster's own, so a dump that did carry it (one
    made without the backup's `--exclude-schema`) cannot bring a valid
    marker into a new cluster.
    * `logs-db-init` writes it into a new store (a logs database with no
      tables, as `initdb` leaves it) and never into one that has tables.
    * The guide's restore refuses a target store that already has a
      marker or any table, starts with `pg_restore --section=pre-data`
      (which makes the tables at once, so that `logs-db-init` never takes
      a store still being restored for an empty one), then restores the
      data and the rest, and writes the marker last.
    * A store without a marker that counts is unavailable: uploads are
      answered `503`, the server runs no migration and records no
      identity in it (Forwarding), and the log views and `logs-db-init`'s
      status say a restore is unfinished. An interrupted restore so stays
      unavailable until the guide's restore is finished.
  * **A broken store never keeps EasyRMM down** (decided in review). A
    full or failed logs disk, a store still recovering, or missing
    secrets, never stops a start, an upgrade or a rollback:
    * nothing depends on `logs-postgres` or `logs-db-init`: the server
      starts without them, as it does without the engine's init;
    * `logs-db-init` always exits 0; it waits a while for the store's
      socket and writes what it found (done, unreachable, a secret
      missing, a restore unfinished, another installation's store with
      its ID) to
      `status/logs-db-init.json` (mode 644), which the server reads
      through its read-only mount of the logs root and shows in Settings
      → Logs;
    * the server's readiness never depends on the store: an unreachable
      store, or one refusing the server's passwords, shows as degraded
      logs (uploads answered `503`, log views saying why);
    * the updater's held start, and a rollback's start, wait (`--wait`)
      for every service but `logs-postgres` and `logs-db-init`, which they
      start without waiting for (amending ADR-0052).
  * Not a database in the shared PostgreSQL: the updater copies and
    restores whole data directories, and a cluster cannot be restored with
    one database left out (Context); its transaction log, checkpoints,
    memory, connections and autovacuum would be the main database's, so
    heavy ingest would slow it, and a full disk under the shared
    transaction log stops every database; and it could not live on
    another disk.

  It costs a second PostgreSQL process (`shared_buffers=256MB`,
  `max_connections=50`, `max_locks_per_transaction=512`, below; its
  memory is measured in slice 2). It runs in every deployment, whatever
  the switches, so that there is one shape to test.
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
  are built from recorded events, never customer data, compiled into the
  server, and never change once released: a block names its codec and
  dictionary). The block's column is stored `EXTERNAL`, so PostgreSQL
  does not try to compress it again. Beside it: organization, site and
  device; source and stream; first and last event time; when it was
  received; the store's era, the ID of the transaction that wrote it
  (`pg_current_xact_id()`, an `xid8`) and its receipt sequence (all
  three for Forwarding); event count and size; the levels present; and
  the codes present with their counts. Indexes (B-tree only): device and
  receipt time, organization and receipt time, (era, transaction ID,
  receipt sequence). Blocks are written once and never
  rewritten; merging small blocks is not built unless the load test shows
  block rows above a third of the store.
* **Facts**, in a table of their own: for each device, hour received and
  kind (code, user, address, process, file hash, service or task name),
  the values seen, each as a 64-bit hash of its normalized text, with the
  organization and site. Indexes: (organization, kind, value hash, hour)
  and (kind, value hash, hour). A search for a user, address or process
  finds the devices and hours that had it, then reads only those
  devices' blocks in those hours, and keeps the events whose value
  matches (a hash collision costs reading, never a wrong result).
  Row-level security lets an index drive a query only through leakproof
  operators; array and JSON containment (`@>`, `&&`, `?`) are not, which
  is why there are no GIN indexes, while equality and ranges on UUIDs,
  integers and times are. Tests run `EXPLAIN` as the application role in
  an organization's scope and the platform's, and fail on a sequential
  scan of facts or blocks; the load test's search times are taken through
  the application role.
* **Partitions**: blocks and facts alike, by retention class (list: 7,
  14, 30, 60, 90, 180 or 365 days, and `forward`), then by the time
  received (range): a day for classes under 90 days, a week for 90 and
  180, a month for 365, so that about 200 partitions exist with every
  class in use (only classes in use have any). The server's maintenance
  connects as the owner role, never through functions, since a
  partition is detached with `DETACH PARTITION … CONCURRENTLY`, which
  cannot run inside a function's transaction and does not lock the parent
  against reads and writes: partitions are made a few days ahead (made
  apart and attached), and detached then dropped when their class's time
  has passed, each statement with a `lock_timeout` of 5 seconds and
  retried with backoff, so that maintenance never queues ingest behind
  it. A concurrent detach that was interrupted leaves its partition
  pending (`pg_inherits.inhdetachpending`); maintenance finds such
  partitions first and completes them with `DETACH PARTITION … FINALIZE`
  before anything else. A dropped partition's counts per organization
  are recorded first, so that gaps can be counted.
  `max_locks_per_transaction` is 512, so that a search across classes and
  a month does not run out of lock space. Closed partitions of the classes of 90 days and more are frozen
  (`VACUUM (FREEZE)`) once, so that wraparound vacuums never rewrite a
  year of logs.
* **Row-level security**, forced on every table holding an organization's
  data (blocks, facts, usage, status, the stream rows with their batch
  numbers, the devices' names), with the same `easyrmm.scope_*` settings
  as the main database: a row is visible at platform scope, in its
  organization's scope, or in its site's. The owner role has a policy of
  its own (as `audit_forwarding_owner`), and functions the owner holds fix
  their `search_path`. Organization and site are on each row (no join), as
  they were when it was received.
* **Retention per organization** (`logs.retention`, 30 days by default)
  always wins, also over forwarding. It counts from receipt, so that a
  computer whose clock is wrong keeps its events: an event whose own time
  is older than retention is stored like any other. The agent's clock in
  each upload gives its skew; a device off by more than 5 minutes is
  flagged on its tab, and its events show both times. A daily job deletes
  each organization's blocks past its retention wherever they are (after
  retention is shortened, or within a week's or month's partition), and
  partitions are dropped when their class's time has passed. Lengthening
  retention applies to blocks received from then on.
* **Quotas**, raw bytes a day, counted per device, stream, source and day
  in the store with each batch:
  * **Per device, by kind of computer** (`logs.deviceQuota`, set per
    organization, site or device): workstations 100 MiB, member servers
    500 MiB, domain controllers 2 GiB, Linux servers 200 MiB, about ten
    times the sizing above, redone from slice 1's measurements. The other
    stream may use at most half of it, so that a flood in Application
    never takes the room Security and Defender need.
  * **Per organization** (`logs.organizationQuota`), none by default.
  * **A storage share per organization** by default: past 90% of the
    store's usable space (its filesystem less the floor), ingest is
    refused first to the organizations holding more than their share (their
    devices' part of all devices, times two; `logs.organizationShare`
    sets another per organization), so that one organization cannot stop
    the others.
* **Ingest stops before the disk fills**: past a size cap for the whole
  store (`logs.maxSize`, none by default) or a free-disk floor on its
  filesystem (10 GiB or 5%, the larger), ingest stops for everyone,
  agents keep their spools and pause, and a console alert is raised (and
  the EasyRMM event `logs.ingest_stopped`, ADR-0053, proposed); it
  resumes by itself below them.
  * Free space is read before each batch is stored, through a read-only
    mount of the logs root, whose PostgreSQL files the server cannot read.
  * **On a filesystem shared with the data root** (the server compares
    the two mounts' device numbers), the floor also keeps room for the
    updater's copy and the main database's growth: the data root's size,
    which the updater writes to its status hourly (amending ADR-0052),
    plus 20%; without the updater, twice the main database's size.
  * **A ballast file, best effort** (decided in review): 2 GiB of random
    data (so that a compressing filesystem cannot shrink it) in the logs
    root, which the guide's recovery deletes to start PostgreSQL again if
    the disk filled anyway (by something else), before retention is
    lowered or the oldest partitions dropped. `setup.sh` writes it when
    it is missing and there is room for it above the floor; when there is
    not, or the write fails, it warns, removes what it wrote, and goes on.
    `setup.sh --upgrade` never fails an upgrade over it: the backup the
    updater just took may share the filesystem, and finishing the upgrade
    matters more than the ballast. Settings → Logs shows a missing ballast
    (seen through the read-only mount) as a warning, and the next
    `setup.sh` run tries again. On a copy-on-write
    filesystem with snapshots (btrfs, ZFS) deleting it may free nothing,
    so it is no guarantee there; `setup.sh` and the guide say so.
  * `setup.sh` says how many devices the logs root's free space holds at
    30 days, and warns when that is fewer than a few hundred or when it is
    the root filesystem.
* **Removed devices' logs stay until retention ends** (a device removed
  under ADR-0050; decided in review, and a question for the owner),
  under
  their organization and site, named as they were (the store keeps each
  device's last name), and marked removed; a device enrolled again is a
  new device. Logs are purged earlier only:
  * **with their organization or site**: deleting one records it in
    `log_purges` in the main database, from `BEFORE DELETE` triggers in
    the deleting transaction (as migration 00020 records what the engine
    must undo); or
  * **when an Organization Administrator asks** for a device's logs to be
    deleted (a removed device's, or one moved to another organization):
    audited when asked, carried out after 7 days unless cancelled, and
    audited again with counts.

  A worker carries out a purge: it records the scope in the store (a
  tombstone, which ingest checks under the device's row lock and refuses).
  Once the tombstone has committed, it takes a transaction ID in a
  transaction of its own (`w = pg_current_xact_id()`), records `w` with
  the purge and commits; then it polls, in transactions that hold no ID,
  until the horizon (`pg_snapshot_xmin(pg_current_snapshot())`,
  Forwarding) is above `w` (decided in review). Every ingest transaction
  that took its ID before `w`, and so may have checked before the
  tombstone committed, has then ended; one that takes its ID after `w`
  takes it after the commit, checks after taking the row lock, and so
  sees the tombstone.
  * Anything holding an ID holds the wait, not only ingest (a migration,
    an open `psql` session), so it is not bounded by ingest's 30 seconds:
    the purge polls, survives a restart (it resumes from its recorded
    `w`), and shows in Settings → Logs what it is waiting on (the oldest
    session holding an ID, from `pg_stat_activity`). Other roles'
    `backend_xid` is hidden there without `pg_read_all_stats`, so
    `logs-db-init` grants that role to `easyrmm_logs_app`, the role that
    reads it (decided in review).
  * A snapshot's `xmax` is not a safe mark: it is one past the latest
    *completed* ID, so an ingest transaction that took its ID between the
    tombstone's ID and its commit, and is still open, lies at or above
    it. Checked while writing this on PostgreSQL 18.6: in exactly that
    case the snapshot's `xmin` already reached its `xmax`, while the
    horizon stayed at or below `w` until the ingest transaction ended.

  It then deletes the matching blocks, facts,
  status and usage, audits it (`logs.purged`, with counts) and removes the
  row. Logs of an organization the main database no longer has (after a
  restore of the main database) are shown to super administrators as
  *orphaned* and expire with retention; nothing deletes them early but a
  super administrator's purge, so that a wrong or restored main database
  never deletes logs by itself.
* **A device moved to another organization** leaves its earlier logs with
  the organization that held it then, which the new one never sees; the
  move dialog offers the purge above.
* **The schema stays readable by the release before**, so that a server
  rolled back by the updater runs on it:
  * no column, table or function is dropped, renamed or narrowed; new
    columns have defaults; queries name their columns;
  * a function's parameters never change: a new parameter would make a
    second overload, and calls that were fine become ambiguous for both
    servers, so new behaviour gets a function of a new name;
  * no new constraint, trigger or policy that the previous release's
    reads or writes would fail;
  * a new stored value (a retention class, a fact's kind, a source, a
    codec or dictionary) is read by one release before any release writes
    it, and code reading the store passes over values it does not know;
  * the batch and status fields follow ADR-0009's rules (pull request
    #52);
  * long migrations of the store (a new index on blocks, rewriting facts)
    run in the background after the upgrade is confirmed (the server sees
    the updater's `hold` gone), never inside the 20-minute held start.

  A test applies each new migration and then runs the previous release's
  store tests (its reads and writes, with its queries) against the
  result, and rejects a migration that drops, renames, narrows or changes
  a function's parameters.
* **The updater (amending [ADR-0052](0052-the-host-updater.md#an-upgrade))**:
  * it never copies, moves or deletes the logs root, and its room check
    leaves it out;
  * a rollback keeps the current `.env`'s `EASYRMM_LOGS_*` lines in the
    `.env` it brings back (an older release ignores them), so that a later
    upgrade finds the same store, where it is, with the same passwords and
    store ID;
  * its held start, and a rollback's start, wait for every service but
    `logs-postgres` and `logs-db-init`, which they start without waiting
    for; neither the store nor `logs-db-init` can fail a held start, so a
    store problem never rolls back an upgrade;
  * it writes the data root's size to its status hourly (the floor above).

  Logs received after the backup, forwarding positions and the store's
  purges survive a rollback; what the main database forgets is in
  Detections and Forwarding.
* **Backups**: the log store becomes an optional part of
  [backup-restore.md](../../operations/backup-restore.md):
  `pg_dump -Fd -Z0 -j 4 --exclude-schema=easyrmm_logs_ready` (a
  directory, uncompressed since blocks are, in parallel, without the
  marker). A restore without it starts with an empty store, which the
  server's migrations make; a restore with it goes into a new cluster,
  with `pg_restore` and then the marker. Either way the store is a new
  cluster with a new identity, so forwarding and detections start at its
  current era and report the gap (Forwarding). The backup drill runs
  once without it and once with it. A new major version of PostgreSQL is
  moved to with `pg_upgrade --link`, by the guide, as for the main one,
  after ingest is held and forwarding and detections reach the horizon
  (Forwarding).
* **The server without its store**: if `logs-postgres` is down,
  recovering, full or refusing the server's passwords, at the server's
  start or later, the rest of EasyRMM works and the server stays ready;
  uploads are answered `503`, agents pause, and the console's log views
  say the store is unavailable and why, with `logs-db-init`'s last
  status.

### Searching and viewing
* **Logs** (a section of the console) and a device's **Logs** tab: filters
  for organization, site, device, source, codes, level, user, address,
  process, file hash, service or task name, time (the last 24 hours by
  default) and text (a case-insensitive substring of any field the caller
  may see). Newest first, a summary line per event (from templates per
  known code, such as "Sign-in by {user} from {address}, type {logon
  type}"), and every field on opening it.
* **How**: facts choose devices and hours, or the device and time do; SQL
  chooses the candidate blocks under the caller's row-level security,
  partitions pruned by receipt time (an event is received after it
  happens: the server keeps the earliest event time in each partition, so
  that a late upload is still found; events of a computer whose clock is
  off by more than a day are found by receipt time and marked); the server
  decompresses them, filters events, and merges them in time order.
* **Limits for the whole server**, not only per request:
  * a pool of decompression workers (half the server's processors) and a
    memory budget for decompressed blocks (512 MiB), shared between
    organizations in turn, so that one organization's search cannot slow
    another's;
  * each request stops when its client goes away;
  * a request answers within 10 seconds with what it found and how far
    back it searched; a search that needs longer continues in the
    background, with its progress shown, and its results kept for an hour;
  * two searches at once per person; exports use the same pool;
  * the load test measures agents' heartbeat latency while searches run.

  A device and a day, or a user across the fleet for 30 days, read a few
  thousand blocks; free text over a whole fleet's month is what the
  background search is for.
* **The device's tab** also shows each source's state (last event, delay,
  paused, gaps, drops, redactions, set-aside batches), a clock skew, and
  each change *Configure logging* made, or why not (*in place*, *managed
  elsewhere* with the owner, *check only* because the reader *cannot
  tell* the owner, with the reason, *not applicable*, failed).
* **Settings → Logs** (super administrators): the switches, the store's
  size, free space, floor and cap; per organization its storage, share,
  ingest a day, retention, mode and quotas; the measured volume per kind
  of computer (workstation, server, domain controller, Linux) and what the
  fleet's would take for the chosen retention against the space left;
  orphaned organizations; `logs-db-init`'s status, purges waiting and on
  what, position resets; and **holding ingest** (audited), which answers
  uploads `503` while agents keep their spools, for maintenance such as
  the guide's `pg_upgrade`.
* **Export** of a search as CSV or JSON lines, up to 100,000 events,
  audited like `report.export`. A CSV cell that begins with `=`, `+`, `-`,
  `@`, a tab or a carriage return gets a leading `'`, so that a
  spreadsheet does not run it.
* **Sensitive fields** (What is collected) are removed by the server, not
  hidden by the console, for a caller without `log.view_sensitive` in the
  event's organization, and replaced by "hidden: needs permission to see
  command lines"; for that caller text search ignores them, so that it
  cannot be used to probe their content, and exports leave them out.
* **Audited**: each search (its filters and result count, not each page)
  and export, once per organization whose events it returned, under that
  organization, as for exports today.
* **Text from computers** is shown as text, never HTML or Markdown.

### Forwarding
* **One list of syslog destinations** (`syslog_destinations`), replacing
  `audit_forwarding` (amending [ADR-0023](0023-audit-forwarding.md)): a
  migration makes its row the first destination, carrying the audit log,
  with its position. Each destination has a name, the transport, host,
  port, optional CA and client certificate of today (the key sealed with
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
* **Device logs**: each destination's position (the era, transaction ID
  and receipt sequence of the last block sent, with the store's identity,
  below) lives in the store, with a copy in the main database, beside
  the logs, so that the updater's rollback does not move it back. A
  forwarder per destination, under an advisory lock in the store, walks
  blocks in (era, transaction ID, receipt sequence) order from its
  position, **up to an exact horizon** (decided in review): the oldest
  transaction still running, `pg_snapshot_xmin(pg_current_snapshot())`,
  read in a transaction that has written nothing (one that has a
  transaction ID counts itself as running).
  * Every transaction with an ID below the horizon has committed or
    rolled back, so the blocks below it are final: no block can appear
    later behind a position. Ingest transactions take their ID with the
    device's row lock (`FOR UPDATE` assigns one), and with 16 at once one
    that took its ID earlier may commit later; its blocks are simply not
    reached until it ends. Nothing rests on a timeout or a clock: a
    transaction held up in its commit (a slow disk flushing the
    transaction log) holds the horizon back until it ends, and the walk
    waits.
  * A device's batches are stored one at a time (one upload in flight,
    under its row lock), so its blocks are walked in the order it sent
    them.
  * Read-only transactions (searches, the forwarders' own reads) take no
    ID and never hold the horizon back; anything that keeps an ID for
    long (a stuck ingest until its 30 seconds, maintenance's detach while
    it waits, a background migration) delays forwarding and detections,
    never makes them skip, and each destination shows how far behind it
    is.
  * `xid8` is the 64-bit transaction ID with its epoch, which does not
    wrap around (2^64 IDs) and is compared as a number, so the order
    holds for a partition's whole life; 32-bit wraparound does not
    touch it.
  * **The store's identity and its eras** (decided in review).
    Transaction IDs start again in a new cluster (a store reset to empty,
    or restored from a dump: `pg_dump`, Backups), so blocks are ordered
    first by an era, a counter kept in the store, and every position is
    kept with the store's identity: the cluster's `system_identifier`
    (from `pg_control_system()`, made by `initdb`, readable by any role)
    and that counter.
    * **Only a complete store has an identity** (decided in review). A
      store without its finished-restore marker (The log store) counts as
      unavailable, and the after-connect hook below records no identity
      and raises no era until the marker is there, so that a store being
      restored while the server runs is never used half-restored.
    * On every new connection to the store (the pool's after-connect
      hook), not only at start, the server raises the era when the
      cluster's identifier is not the one recorded beside the counter, in
      one conditional statement (`UPDATE … SET era = era + 1,
      system_identifier = $1 WHERE system_identifier IS DISTINCT FROM $1
      RETURNING era`), so that two connections cannot both raise it. A
      store reset or restored while the server runs is so caught on the
      first connection made to it once its marker is there, since the old
      connections end with the old cluster.
    * Ingest reads the era inside its own transaction, never from a
      cache. Blocks of earlier eras are all final; the horizon applies to
      the current one.
    * **Positions are kept twice, with the identity** (decided in
      review): the forwarders' in the store (so that the updater's
      rollback does not move them back) with a copy in the main database,
      and the detections evaluator's in the main database with a copy in
      the store. The store's copy is always written before the main
      database's commits, so that a crash between them leaves the store's
      copy ahead, never behind. Each position is of one of two kinds:
      *after a block* (the era, ID and sequence of the last block
      handled) or *at the horizon* (where a destination without a
      position, or a reset, starts, naming no block). Each forwarder and
      the evaluator run under an advisory lock in the store, one writer
      per position.
    * **Another identity** (a store reset to empty, restored from a dump,
      or moved by `pg_upgrade`): the position is reset to the start of the
      current era, and the gap, with the times it covers as far as they
      are known, is shown in the console and audited
      (`logs.position_reset`).
    * **The same identity, but the store went back** (a file-level
      restore of the logs root, which neither part of the identity
      shows): the store's copy of a position behind the main database's,
      whatever the counter says; or a position *after a block* whose ID
      is strictly above `pg_snapshot_xmax(pg_current_snapshot())`, which
      is one past the latest completed transaction ID (the block it names
      was written by a completed transaction, so on a sound store its ID
      is below that). A position *at the horizon* is never judged by the
      latter rule: on an idle store the horizon and `xmax` are the same
      number, which a sound position at the horizon may hold. The
      position is then reset to the current horizon, never to the start
      of the era, which would read the whole era again, and the gap is
      shown and audited as above.
    * `pg_upgrade` keeps the transaction counter but writes into a
      cluster made by `initdb`, so its identifier is expected to change
      (checked when the guide's procedure is written). The guide's
      upgrade therefore first holds ingest (Settings → Logs, uploads then
      answered `503`), then waits for forwarding and detections to reach
      the horizon, and only then stops the store, so that the reset loses
      nothing; anything left is reported as a gap.
  * Checked while writing this on PostgreSQL 18.6 (the deployment's
    image, in a throwaway container): `SELECT … FOR UPDATE` assigns a
    transaction ID; while a transaction that took its ID first stayed
    open, the block a later one had committed stayed at or above the
    horizon, and once the first committed both were below it, in ID
    order; an open repeatable
    read transaction that only read held no ID and did not hold the
    horizon back; a transaction with an ID saw its own ID as the horizon;
    a new cluster's first IDs are in the hundreds (757 there); a query on
    (transaction ID, sequence) with a row comparison and the horizon used
    the index; and `SET LOCAL transaction_timeout` set inside a
    transaction ended that transaction's connection when it ran over, and
    did not touch the next transaction.

  It sends their events in order over a kept connection, up to 1,000 a
  write, and moves the position at block ends, in a transaction of its
  own: at least once, never out of order. A destination that was down
  catches up from its position; one behind the oldest kept block jumps to
  it, and the events it missed are counted as a gap, shown, and alerted.
  A deleted destination's position is kept for 7 days, so that one a
  rollback brings back continues where it stopped; a destination without
  a position (made since the backup's restore, or after those 7 days)
  starts at the horizon and says from when.
* **The message**: RFC 5424, HOSTNAME the device's host name (a SIEM
  files the event under the computer it came from), APP-NAME `easyrmm`,
  MSGID the source, the `origin` structured data as for the audit log, and
  MSG the event as JSON with its organization, site and device (IDs and
  names), source, code, level, times, the device's clock skew and fields.
  Events are at most 32 KiB, under the 64 KiB frame.
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
| Audit policy changed | 4719, auditd `CONFIG_CHANGE` | On, warning |
| Malware found | Defender 1006, 1015, 1116, 1117; ClamAV and Defender for Endpoint detections | On, critical |
| Protection turned off | Defender 5001, 5010, 5012 | On, critical |
| Tamper Protection blocked a change | Defender 5013: something tried to change protected settings | On, warning |
| Privileged group changed | 4728, 4732, 4756 adding to Administrators, Domain Admins, Enterprise Admins or Schema Admins (by well-known SID); a user added to `sudo` or `wheel` | On, warning |
| Failed sign-ins | At least the policy's threshold (20) of 4625 or `sshd.failed` on one device within its minutes (10) | On, warning |
| Sudo refused | `sudo.denied` | On, warning |
| Account created | 4720, `ADD_USER` | Off |
| Account locked out | 4740 | Off |
| Service installed | 7045, 4697 (software installs do it too) | Off |

* **EasyRMM's own changes are not alerts.** A match explained by
  EasyRMM is shown in the logs with its cause and opens no alert:
  * a change *Configure logging* made, which the agent reports with its
    time and what it changed (4719, `CONFIG_CHANGE`);
  * a job whose result lists the change, within its run's time on that
    device: hardening's apply and undo of `defender` (ADR-0054), whose
    undo can turn protection settings back off (5001, 5010, 5012), and
    hardening's `audit` module on Linux loading or removing its rules
    (`CONFIG_CHANGE`);
  * Group Policy applying audit policy: 4719s by SYSTEM while the
    computer's Group Policy is processed (the GroupPolicy Operational
    log's start and end), setting what the reader shows Group Policy owns.
    Checked with a domain policy (Testing).
* **How**: each minute, the evaluator walks blocks from its position as
  the forwarder does (in (era, transaction ID, receipt sequence) order, up
  to the same exact horizon), decompresses only those whose codes
  include a detection's, and tests them; counted
  detections count events by their own time within their window, so that
  a late upload counts where it happened. It opens alerts in its own
  transaction in the main database, where it keeps its position with the
  store's identity and a copy in the store (Forwarding), under an
  advisory lock in the store, one evaluator writing at a time. An alert
  stays open, counting further matches, until someone resolves it or 7
  days pass without one (a new resolution, `expired`): an event is not a
  condition that clears.
* **An alert carries the detection, the device, the count and the times,
  never an event's fields**: everyone who sees the device sees its alerts,
  and notifications leave EasyRMM. The alert links to the events, which
  need `log.view`.
* **After a rollback** the evaluator's position is the backup's, so it
  evaluates again what was received since and opens again the alerts the
  rollback discarded, marked so; their notifications are not sent again
  for events received before the rollback.
* **Notifications** through the rules of ADR-0053 (proposed), whose
  condition filter gains `log` and the detection. Storage and forwarding
  problems are EasyRMM events there (`logs.ingest_stopped`,
  `logs.ingest_resumed`, `logs.quota_reached` once a day per organization,
  `logs.forwarding_failing`, `logs.forwarding_recovered`).

### Privacy
* **What it holds**: user names and SIDs, IP addresses, computer names,
  times of sign-ins, programs started with their command lines,
  PowerShell scripts, sudo commands and SSH source addresses: personal
  data about the customers' staff. The MSP processes it for the customer,
  who is the controller.
* **Collected by default on new installs**, as the plan has it (a
  question for the owner, below), with an
  organization-level switch for customers that decline it (then not even
  counted), retention per organization, purges with the organization or
  site or on request, and nothing that is not security-relevant by
  default: no rendered Security messages, no module logging, no file or
  share access, no network connections.
* **Restricted**: sign-in and process events need `log.view`; command
  lines and scripts need `log.view_sensitive`, enforced in results, text
  search and exports; alerts and notifications carry no event content;
  every search and export is audited where the customer's administrators
  can see it.
* **EasyRMM's tokens are redacted** on the computer, by the agent and by
  the server; EasyRMM's jobs' argument values are replaced in what
  EasyRMM collects, and are otherwise seen only with the job.
* **What stays on the computer.** Configuring logging makes each computer
  record more: script blocks and command lines hold whatever secrets
  scripts and command lines carry (other tools' passwords, an install
  command's token), in logs that the computer's administrators and Event
  Log Readers can read, for as long as the logs keep them. Redaction
  covers what EasyRMM collects, not what stays. With command lines in
  process events on (`logs.commandLines`, Settings and who), that
  includes the argument values of EasyRMM's own jobs, which the console
  says where the setting is, and ADR-0017's guidance says not to pass
  secrets as arguments; for PowerShell jobs, the classic Windows
  PowerShell log holds them already, by default (Consequences). To
  shrink the rest: the PowerShell logs' other readers, the classic log's
  included, are removed; and the console's install card for Windows
  proposes an approval token valid for one day (ADR-0024: its devices
  wait for approval, so a token read later from a log enrolls nothing
  unseen), saying why.
* **Erasure of one person's events** is not built: blocks are written
  once, compressed, and expire with retention. The design rests on the
  controller's legitimate interest in network and information security
  (GDPR Article 6(1)(f), which Recital 49 names), with retention limiting
  how long anything is kept; whether an objection or erasure request
  must be met before retention ends is for the controller to assess, and
  the guide says what EasyRMM can do (shorten retention, purge a device or
  site). A question for the owner, below.
* **PRIVACY.md and the guide** say what is collected from which computers,
  where it is kept, for how long, where it is forwarded, who sees it, what
  stays on the computers, and that MSPs tell their customers (and, where
  the law asks, their staff) before collecting.
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
| `logs.commandLines`: command lines in Windows' process creation events, where *Configure logging* is on | Platform, organization | Organization administrators and above | On (decided in review; a question for the owner) |
| `logs.sources` (with priority sources) | Platform, organization | Organization administrators and above | The default filters |
| `logs.bandwidth` | Platform, organization, site, device | Site administrators and above | 128 KiB/s |
| `logs.spool` | Platform, organization | Super administrators | 256 MiB |
| `logs.retention`, `logs.mode` (*server*) | Platform, organization | Super administrators | 30 days, store |
| `logs.deviceQuota` (*server*) | Platform, organization, site, device, per kind of computer | Super administrators | 100 MiB, 500 MiB, 2 GiB, 200 MiB a day |
| `logs.organizationQuota`, `logs.organizationShare` (*server*) | Platform, organization | Super administrators | None; twice its devices' part |
| `logs.maxSize`, the floor (*server*) | Platform | Super administrators | None; 10 GiB or 5% |

| Permission | Who |
|---|---|
| `log.view`: sign-in, process and other events, the device's Logs tab, search and export | Site Administrators and above, in their sites (as `audit.view`) |
| `log.view_sensitive`: command lines and scripts | Organization Administrators and above, from organization-wide grants only |
| Purging a device's logs | Organization Administrators and above (`org.manage`) |
| Syslog destinations, Settings → Logs, orphaned logs | Super administrators (`settings.manage`) |
| Detections | As other alert policies: shared ones by super administrators, an organization's or site's with `monitoring.manage` there |

`log.view` is at Site Administrators, who may be a customer's own staff,
because what it shows they can already reach: Technicians and above have
a terminal on the site's computers (`device.terminal`) and can read the
event logs there. What `log.view` adds is search across the site and
history after a computer is gone. Command lines and scripts, which carry
other people's secrets, stay with Organization Administrators; that limits
reading in bulk, not a technician reading one computer's log through a
terminal.

**`logs.commandLines`** says, where it is set, what turning it on means
on the computer itself: Windows' Security log then holds every process's
command line, the argument values of EasyRMM's jobs included, readable
there by the computer's administrators and Event Log Readers until the
log wraps. EasyRMM's own copy has job argument values replaced (The
collector); the computer's log does not. Turning it off puts back the
value before. On Linux, auditd's `EXECVE` records always carry
arguments and its log is readable by root only, so the setting is
Windows' alone.

Every settings change, destination change and test, search, export and
purge is audited. [rbac.md](../../security/rbac.md) gains the two
permissions.

### The rest
* **Agent facts**: Windows agents report whether the computer is a domain
  controller (`ProductType` is `LanmanNT`), beside the kind of device
  ADR-0053 adds. Like every field added after protocol level 2, it is
  sent only to a server whose last answer said level 2 or higher
  (ADR-0009, pull request #52).
* **API**: `POST /api/agent/v1/logs`, `POST /api/agent/v1/logs/status`;
  `POST /api/v1/logs/search` (and its background searches),
  `POST /api/v1/logs/export`, `GET /api/v1/devices/{id}/logs/status`,
  `POST` and `DELETE /api/v1/devices/{id}/logs/purge`,
  `GET /api/v1/logs/usage`, `GET` and `PUT /api/v1/settings/logs`, and
  `/api/v1/syslog-destinations` (list, create, change, delete, test).
* **New packages** (the agent's collector and sealing, the server's store,
  ingest, search and forwarding) get coverage floors in
  `scripts/ci/check-coverage.sh`, and the collector's Windows code a floor
  of its own once the Windows job writes a coverage profile (the plan's
  harnesses).

## Testing
Every test runs the real thing; what cannot run in CI says so and is
marked unverified in IMPLEMENTATION_STATUS until it is run.

* **Unit**: the parsers (Windows event XML, journal JSON with byte arrays
  and long fields, auditd records in raw and enriched format with
  hexadecimal values, grouped by serial), filters, codes and normalized
  fields, from events recorded on CI's Windows runner and the test
  machines; **fuzzing** of the collector's parsers, the server's parsers
  and the upload's decoder; redaction, on a real script block and command
  line carrying a token, a hexadecimal `PROCTITLE` carrying `--token`, and
  a script long enough to split across two 4104 events with the token at
  the split; sensitive fields classified by name in every source; the
  spool (torn tails, the position with the event, shares, pausing, an
  older format read by the next release); the crash rules (a parser panic
  passed, an event crashing twice passed and counted); sealing (job
  events marked; the run's own command line replaced by its record,
  every argument token whole, short ones and parameter names included,
  with PowerShell's and cmd's quoting and escapes, in 4688, Sysmon 1, a
  child's `ParentCommandLine` with its new-process message dropped,
  PowerShell's Host Application in 4100, 4103, 400, 403 and 600, an
  unmarked event of another source, `EXECVE` by index with split `aN[k]`
  chunks and `aN_len` dropped, a `PROCTITLE` cut at 128 bytes in the
  middle of a value, and the journal's `_CMDLINE`; a value that also
  appears elsewhere in the line not searched for; the record kept until
  every source has passed the run's end, then deleted; values of six
  characters or more replaced in what the run starts; the batch fixed);
  the agent's
  answer to each status, signed and unsigned (an unsigned refusal never
  setting a batch aside); a `413` on N with N+1 and N+2 already sealed
  (all three resealed from N at half the size, no number stored twice), a
  second `413` on the resealed N, a resealed N that the server had stored
  (`409 resync`, nothing lost), a batch at the floor and a single event
  over the limit set aside after five tries with `too_large`; a `408` and
  a send past 30 seconds halving the size like a `413`, and at the floor
  retried, never set aside; the size growing back, never above one
  refused that day; batch sizes from bandwidth;
  blocks and their dictionaries; golden RFC 5424 messages; CSV formula
  cells.
* **Integration** (PostgreSQL, with the race detector and coverage
  floors; the store as a second database of the test PostgreSQL, while the
  bundle and updater tests run it as its own instance):
  * partitions per class and period, made, attached, detached and dropped
    by the owner's maintenance with `lock_timeout`, while a long search
    holds the parent, with every class; an interrupted concurrent detach
    finished; the application role unable to touch a partition; freezing;
  * row-level security on every store table between two organizations, a
    site and the platform, and the owner's policy; `EXPLAIN` as the
    application role showing index scans of facts and blocks in an
    organization's scope and the platform's;
  * ingest: signature before decompression, each cap, the 64 reads, two
    per claimed device and the minimum rate, the 16 slots, one in flight
    per device, a retried batch stored once, a batch accepted after a gap
    in its stream's numbers (one set aside on the agent), a
    restored snapshot answered `resync` (the same number, other contents),
    a new generation, collection off, a force-removed device refused;
  * quotas per kind, the other stream's half, organization quotas, the
    organization share refused first at 90%, the size cap, the free-disk
    floor on a small filesystem made for the test, with and without the
    data root on it;
  * retention: the daily deletion after shortening and inside weekly
    partitions; a skewed clock's events kept;
  * purges: from each delete, a device's purge after its delay, an upload
    committing during a purge refused; an ingest transaction that took
    its ID between the tombstone's ID and its commit, still open, holding
    the purge until it ends and its blocks deleted after; an open `psql`
    session holding an ID holding the purge, shown as what it waits on; a
    purge resumed after a restart; orphaned organizations left alone;
  * the schema rules: the previous release's store tests passing on each
    new migration; a migration changing a function's parameters refused;
    a block written with a dictionary the release before reads;
  * forwarding (the horizon: an ingest transaction that took its ID
    first and commits last, held open across several walks, its blocks
    reached once it commits and none skipped by the forwarder or the
    evaluator; one rolled back; a stuck one ended by its 30 seconds; a
    search open meanwhile not holding the horizon; the walk's own read
    holding no ID; the walk's query using the (era, ID, sequence) index;
    the store's identity: a store reset to empty with the main database
    kept, and a store restored from a dump while the server runs, each
    caught on the next connection, a new era begun, ingest writing it,
    the forwarders' and the evaluator's positions reset to its start with
    the gap shown and audited, and no block of it skipped; during that
    restore, connections finding no marker take no upload, run no
    migration and record no identity, until the marker is written last;
    an interrupted restore left unavailable, `logs-db-init` not marking
    it; the era raised once when two connections find a new cluster at
    once; the same identity with the store gone back (the logs root
    restored from a file copy): a store copy of a position behind the
    main database's, and a position after a block whose ID is above the
    snapshot's `xmax`, each reset to the current horizon, not to the
    era's start, with the gap shown; an idle store with a position at the
    horizon giving no reset; a crash between a position's two writes not
    taken for a store gone back; two evaluators started at once, one
    writing; order per
    device, a destination that comes back and catches up, one passed by
    retention
    and its gap, a deleted destination restored within 7 days, one with
    no position, forward only, the audit log moved from
    `audit_forwarding` with its position);
  * each detection on recorded events, counted windows by event time, an
    alert opened once across two servers, an alert carrying no fields,
    EasyRMM's own changes opening none, re-evaluation after a rollback
    without notifications;
  * search (each filter, order across overlapping blocks, the shared
    worker pool fair between two organizations, cancellation, a
    background search, sensitive fields removed and ignored by text
    search and exports, searches audited per organization).
* **Windows, on CI's Windows runner** (`windows-latest`, as
  administrator, for real):
  * the collector as its service and virtual account, reading each
    collected channel, the Security log's included, through its own entry
    in the channel's access list, with no group changed; unable to read
    the agent's state; its network blocked by its filtering-platform
    filter with Windows Firewall turned off; its job object's CPU cap and
    memory limit; the Event Log service's processor use during a flood;
  * subscriptions from positions across a restart of the collector,
    nothing lost or twice; a cleared log reported as a gap; a filtered
    source quiet while the log wraps, reporting no gap;
  * slice 0's checks (Slices);
  * configuring logging: `auditpol /get /category:*`, `wevtutil gl` and
    the registry before and after, matching the table; then a 4104 from a
    test script, a 4688 with its command line, a 4625 from a wrong
    password and a 4720 from a new local user, collected; a subcategory
    set by local Group Policy left *managed elsewhere*; a channel whose
    access list local Group Policy sets, *managed elsewhere* and not
    collected; with resultant set of policy logging turned off, every
    value check only (*cannot tell*, with the reason), nothing written
    and no channel's access list changed, and a channel whose list
    already grants the collector's SID still collected, by Group Policy
    and with that logging off; a Group Policy object with
    registry preference items, and a DSC configuration in
    `ApplyAndAutoCorrect` setting audit policy, both check only; the
    classic Windows PowerShell log's default access list read and
    recorded first (who could read its 400, 403 and 600 before), then
    each PowerShell log's list narrowed, a non-administrator's script
    still logged and that user unable to read the logs; undo, access
    lists included, with everything as before;
  * Sysmon downloaded from Microsoft and installed with a small
    configuration, its events collected; a script block carrying a token
    in the install command's form, redacted; a job with arguments: its
    own 4688 and Sysmon 1 and a child's, and its 4104, marked with the
    run, every argument value replaced on its own command line and long
    ones in the child's, matched by job object and creation time, while
    the computer's Security log still holds the values (the case the
    console warns of);
  * uploads to the server's real ingest handler, in a Go test that starts
    the runner image's PostgreSQL;
  * Defender detections with the EICAR test file where the runner's
    Defender allows it, else on the owner's servers by hand.
* **Linux machines** (the QEMU harness, `internal/vmtest`, each tested
  image):
  * the collector's unit: its user without any capability, auditd's log
    read through the descriptors the agent passes, across a rotation;
    `/etc/shadow`, host keys and the agent's state unreadable; no network;
    `CPUQuota` holding under a flood, `MemoryMax` reached and the unit
    restarted;
  * configuring logging (auditd installed from the local package
    repository the hardening tests use, the rules generated for the
    machine and loaded, the journal made persistent), then a restart (all
    kept); a machine without `/root/.ssh` and cron's spool, whose rules
    still load with a later file's `-e 2`; rules already immutable;
  * real SSH sign-ins from outside through the forwarded port, failed and
    accepted, `sudo`, `useradd` and an edit of `/etc/passwd`, collected
    with their keys; a job's processes recorded under
    `easyrmm-logs-jobs` and marked with their run by session;
  * with hardening's rules file too: both load, each event recorded once,
    either undo leaving the other's rules running, auditd removed only by
    the last one out, and kept when an operator's own rules file is
    there;
  * a journal vacuumed past the cursor, reported as a gap; `Storage=none`
    read from the files;
  * undo, with everything as before;
  * the collector's batches uploaded to the real ingest handler that the
    test runs on the host, reached at `10.0.2.2` through QEMU's user
    networking (no bridge); ClamAV with the EICAR file on one image.
* **The bundle test** (host networking only, never a bridge): the
  deployment with `logs-postgres`, which listens on loopback only (the
  test's existing check, and port 15433 added to the ports it needs
  free), its logs root the data root's sibling and nothing made under
  `/srv/easyrmm` or `/srv/easyrmm-logs`; with `logs-postgres` stopped and
  its secrets removed, the deployment still starts, the server's
  readiness passes and EasyRMM works, uploads answered `503`, and
  `logs-db-init` exits 0 with its status shown in Settings → Logs; the
  same with the store's passwords changed behind the server's back, and
  with a store from another run's `.env` (another store ID), which is
  not used and is named; a failed and an accepted SSH sign-in on the
  Debian machine appear in its **Logs** tab
  (Playwright) and reach a syslog receiver written for the test (RFC 5425
  over TLS, octet counting, recording each message) running on the host's
  network, listening on loopback as a platform destination with a
  certificate from the run's authority, beside the audit log's records;
  in that container auditd is reported not applicable. With slice 10, an
  organization's destination in a network namespace of its own joined by
  a veth pair, as the webhook test of ADR-0053 (proposed) does.
* **The updater's tests**, counting blocks before and after each:
  * an upgrade from a release without the store, then a rollback to it
    and an upgrade again (new passwords in `.env`, the store used, uploads
    accepted, no block lost);
  * a rollback during a failed upgrade, and one after a confirmed
    upgrade, the store untouched and the older server running on the
    newer schema;
  * a held start, and a rollback's start, with the logs disk full,
    `logs-postgres` failing or still recovering, a store refusing the
    server's passwords, and a store holding another store ID, each
    completing with the server ready, logs degraded and `logs-db-init`'s
    status shown in Settings → Logs, and none rolled back; `logs-db-init`
    exiting 0 in each.
* **Load**: `tools/agentsim` uploads logs from the recorded events at each
  kind of computer's rate.
  * On CI, 500 devices for an hour at four times the sizing's rate: ingest
    latency, the server's processor and memory, bytes stored per event and
    the compression ratio, forwarding throughput to the test receiver; with
    one device flooding and one sending its bodies slowly, the others'
    acceptance and latency unchanged; searches running, heartbeat latency
    measured.
  * On the owner's host, recorded in
    [drills.md](../../development/drills.md): 2,000 devices for 24 hours,
    and searches over a store filled to 30 days at the sizing's volume.
* **By hand on real computers**, recorded with dates: a domain whose
  Group Policy sets audit policy (shared with ADR-0054's domain tests): the
  reader's *managed elsewhere*, and Group Policy's own 4719s opening no
  alert; a domain controller chosen and not chosen, the collector reading
  its Security log through the channel's own access list with no group
  changed; a channel whose access Group Policy sets; Defender detections,
  protection turned off and
  Tamper Protection blocking a change; the owner's Windows and Linux
  servers.

## Slices
Each merges and is verified on its own, after F1 and F2.

0. **Windows jobs inside their job object** (amending
   [ADR-0017](0017-scripts-and-jobs.md); decided in review). Otherwise
   jobs start exactly as today, in every shell: the same interpreter,
   command line and arguments, so exit codes, parameter binding and output
   do not change. A wrapper that kept argument values off the command
   line was dropped in review: run inside PowerShell it could not match
   `-File`'s binding or exit codes and is refused under Constrained
   Language Mode, and every existing script relies on its exit code. What
   protects argument values now is in The collector (EasyRMM's own jobs)
   and Consequences.
   * **Every process in its job object.** Today the job object is
     assigned after the process starts, and a run goes on without one if
     that fails (`start`, `agent/jobs/exec_windows.go`). Now, still
     through `os/exec` (decided in review), so that Go's list of inherited
     handles (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), the pipes and the
     command line's quoting stay as they are:
     1. the agent makes the job object and attaches its completion port,
        and refuses the run, with the reason, if either fails;
     2. it starts the process with `CREATE_SUSPENDED` added to its
        creation flags;
     3. it assigns the process to the job object, and if that fails
        terminates the suspended process and refuses the run;
     4. it resumes the process's single thread, found by listing the
        process's threads (Toolhelp32: `CreateToolhelp32Snapshot` with
        `TH32CS_SNAPTHREAD`), since Go's `syscall` closes the thread
        handle at once.

     Nothing the process starts can escape before it is assigned, since
     it has not run.
   * **Order**: slice 0 merges before slice 3, since marking Windows
     jobs' events relies on every process of a run being in its job
     object from its start (The collector). No release needs to come
     between them: argument values are on the command line in every
     release, so ADR-0027's crash rollback to an earlier agent changes
     nothing there. The job's payload does not change, so an agent of the
     previous release still runs the new server's jobs.

   *Verified*: the Windows runner: every process of a job, a short-lived
   one included, in its job object and reported on its completion port; a
   run whose job object cannot be assigned refused with the reason and
   its suspended process gone; the handles the job inherits unchanged;
   PowerShell and cmd jobs with arguments giving the same exit codes (an
   `exit N`, a normal end after a failing native command, a thrown
   error), output and errors as the release before; stopping a run
   stopping everything it started; every existing job test unchanged; an
   agent of the previous release running the new server's jobs.
1. **Measuring.** A script for EasyRMM's jobs (PowerShell and sh), added
   to the library by hand, that reads what the computer's logs hold for
   the last 7 days and reports, per source, code and audit subcategory,
   the events and bytes with and without the default filters. Run on CI's
   runner and the test machines, and by hand on the owner's computers and
   any pilot MSP's: workstations, a member server, a file server, a domain
   controller, Linux servers with cron and Ansible. *Verified*: the sizing
   table, the quotas by kind and the audit table's volumes are redone from
   it, and the store's layout (block size, partition periods, facts) is
   confirmed or this ADR amended before slice 2 merges.
2. **The store and Linux sign-ins**: `logs-postgres`, `logs-db-init` and
   the logs root in the deployment and `setup.sh`, the deployment starting
   without them; the schema in its final
   two-level layout, row-level security, facts, quotas by kind, the
   organization share, the cap, the floor, the ballast and purges;
   ingest with streams, signed answers and admission; the collector with
   its unit, limits, spool, auditd's descriptors and the agent's sealing,
   with each run's command line recorded and replaced; the jobs' launcher
   with the `easyrmm-jobs` user and matching by audit session (amending
   ADR-0017: each Linux run with that login UID; decided in review, since
   sealing matches Linux events to runs by it, sudo's journal lines from
   `linux.auth` included); redaction on the computer, the agent and the
   server; `linux.auth`; sensitive fields and their removal, `log.view`
   and `log.view_sensitive`; the device's **Logs** tab; the switches and
   the checklist; the updater's amendments (if the updater is built).
   *Verified*: integration, the machines (each Linux run's processes with
   `easyrmm-jobs`'s login UID and a session of their own, a job's `sudo`
   line in the journal matched to its run with its arguments replaced,
   every existing Linux job test unchanged with the launcher), the bundle
   test's sign-ins in the tab, the updater's tests, the CI load run.
3. **Windows Security**: the Windows collector, its service, account,
   channel access, filtering-platform filter and job object, EasyRMM's
   jobs marked. *Verified*: the Windows runner,
   with uploads to the real ingest handler.
4. **Configuring logging**, after ADR-0054's W1 (the ownership reader)
   and with H2's marker: Windows' table and settings, command lines in
   process events per organization (`logs.commandLines`) and what the
   console says about them, owners, domain controllers, the PowerShell
   logs' readers, the collector's channel access, the console's install
   card; Linux's rules generated per machine, the jobs' rule included,
   the journal and auditd; undo.
   *Verified*: the Windows runner and the machines, both features' rules
   together; `logs.commandLines` off leaving the value as it was before;
   a Linux job's `EXECVE` records keyed `easyrmm-logs-jobs` and matched
   to its run; the domain by hand.
5. **The other sources**: Windows System, Application, Defender,
   PowerShell, Sysmon, RDP, WMI; Linux audit, system, antivirus; custom
   sources; `logs.sources`; the counts while collection is off.
   *Verified*: the runner (Sysmon, script blocks), the machines (auditd,
   ClamAV).
6. **Forwarding**: the destination list with the audit log moved into it,
   device logs, positions, gaps, failing alerts. *Verified*: integration
   and the bundle test's syslog receiver.
7. **Organizations**: retention classes beyond 30 days, forward only,
   organization quotas and shares in the console, device purges, moves,
   Settings → Logs per organization. *Verified*: integration.
8. **Detections**: the `log` policies, EasyRMM's own changes, alerts,
   notifications and EasyRMM's events. *Verified*: integration, and in the
   bundle test a burst of failed sign-ins reaching ADR-0053's webhook
   receiver.
9. **The Logs page**: fleet search, background searches, the shared
   worker pool, export. *Verified*: console tests, and search times on the
   owner's host.
10. **Organizations' own destinations**, under ADR-0053's organization
    policy. *Verified*: the bundle test's namespace receiver.

## What changed from the plan
* **The store is a PostgreSQL instance of its own, outside the data
  root**, not a database in the shared one: the updater's copy could not
  leave the latter out, and a store inside the data root would be moved
  aside and later deleted by a rollback. The updater leaves it out always,
  not "unless asked".
* **Compressed blocks with hourly facts, not a row per event**: about a
  sixth of the space at 2,000 devices; B-tree indexes on hashed values,
  since row-level security keeps GIN indexes from being used.
* **Partitions by retention class, then day, week or month**, made and
  dropped by the server's maintenance connecting as the owner, not by
  functions, which cannot detach a partition concurrently.
* **A removed device's logs stay until retention ends**; they are purged
  with their organization or site, or on an Organization Administrator's
  request.
* **`logs.collect` can also be set per organization** (the plan had it
  platform only), for customers that decline.
* **`setup.sh` takes `--no-collect-logs` and `--no-configure-logging`**
  instead of `--collect-logs`: both are on by default, so the flags turn
  them off.
* **`TOKEN=` is not a redaction rule**: EasyRMM's tokens are found by
  their own form (`ert_` and 43 characters) wherever they are, after
  `TOKEN=` too, and the remaining rules name EasyRMM's own options.
* **`log.view` is Site Administrators and above**, as `audit.view`, not
  Organization Administrators; command lines stay with Organization
  Administrators.
* **Events of EasyRMM's own jobs are kept in full**, with the run and the
  script's hash, and only argument values replaced in EasyRMM's copy,
  not dropped; Windows jobs start inside their job object (slice 0), and
  Linux jobs get a login UID of their own (slice 2) and an audit rule
  (slice 4), decided in review. Job arguments stay on the command line,
  and command lines in process events are an organization setting.
* **Module logging is not configured**; script block logging is, and the
  PowerShell logs' readers are narrowed.
* **The audit table is the baselines'** and shared with ADR-0054, which
  only reports it; `SCENoApplyLegacyAuditPolicy` is set; the Security log
  is at least 1,024,000 KB.
* **`auth.log` and `secure` are read only where the journal keeps
  nothing**.
* **A source pauses instead of dropping** when its spool share is full,
  since Windows' logs, the journal and auditd's files hold the events.
* **The collector has no key, no network and no privilege**: on Linux no
  capability (auditd's log through descriptors the agent passes), on
  Windows read access in each channel's own access list rather than a
  group (decided in review); the agent seals and uploads.
* **The persistent journal stays on undo.**
* **auditd's removal is last one out**, amending ADR-0051.
* **Detections are alert policies of a new kind** with a fixed set.
* **Device logs go over TCP or TLS only**; organizations' own destinations
  are a later slice.
* **Measuring comes first** (slice 1), before the store is built.
* **A broken log store never stops EasyRMM**: nothing depends on it,
  `logs-db-init` always exits 0 and reports a status, the server's
  readiness never depends on the store, and the updater does not wait
  for either, so a store problem never rolls back an upgrade.
* **Forwarding and detections walk to an exact horizon**, the oldest
  running transaction's ID, instead of a time margin.
* **Owners the reader cannot tell are check only** (ADR-0054's
  *cannot tell*): Configuring logging never writes a value whose owner it
  cannot see.

## Consequences
* An MSP sees sign-ins, account and group changes, processes, scripts,
  services, antivirus detections and protection changes across its
  customers' Windows and Linux computers in EasyRMM, is alerted on the
  ones that matter, and sends them to its SIEM, without another agent.
* Each computer gets the baselines' audit policy and stronger logging by
  default, which its own Event Viewer and journal keep too; Group Policy,
  MDM and other owners keep precedence; uninstalling puts it back, except
  the persistent journal.
* **Computers keep secrets in their own logs**: script blocks and command
  lines record what scripts and command lines carry, readable by the
  computer's administrators and Event Log Readers until the logs wrap.
  EasyRMM's tokens are kept out where it can; PRIVACY.md says what
  remains.
* **Job argument values reach the computer's own logs.** With command
  lines in process events on, as they are by default, each computer's
  Security log holds the argument values of EasyRMM's jobs, as it holds
  every process's command line, readable there by its administrators and
  Event Log Readers until the log wraps; so does Sysmon's log where
  Sysmon is installed, and on Linux auditd's log (root only) once the
  jobs' rule is in place. Today the Security log and auditd's log do
  not, without command-line auditing and that rule; but the classic
  Windows PowerShell log already does for PowerShell jobs, since its 400,
  403 and 600 record each PowerShell host's command line at every start,
  by default, and *Configure logging* now narrows who can read it. On
  Linux every local user can read a running job's arguments in
  `/proc/<pid>/cmdline`, as today. The collector's spool holds the raw
  values until sealing, readable by administrators only. EasyRMM's own
  copy has them replaced. The console says so where `logs.commandLines`
  is set, and ADR-0017's guidance gains: do not pass secrets as
  arguments.
* The deployment gains a second PostgreSQL instance in a directory beside
  the data root and, at 2,000 devices and 30 days, roughly 150 to 210 GB
  of disk for logs, best on a disk of its own; the guide's host
  requirements say so per fleet size.
* A device may lose events only when the computer's own log wraps past
  what was read, or an event crashes the collector twice, both counted and
  shown, or when a batch is set aside (kept on the computer and
  reported); a stream's batch numbers can then skip. Events can arrive
  twice after a `resync`: a computer restored from a snapshot, or a
  batch stored whose answer was lost and which a proxy's lowered limit
  then made the agent reseal; and at a forwarding destination after a
  failure. After a change of the store's identity, forwarding and
  detections start at its new era, and after the store went back
  (restored from a file copy) at the current horizon, reporting the gap
  either way.
* Logs survive the updater's rollback; alerts the rollback discarded are
  opened again; logs of devices and organizations the main database
  forgets stay until retention, visible to super administrators.
* Every Windows job now starts inside its job object, and every Linux
  job runs with the login UID of `easyrmm-jobs`, which shows in their
  audit records and in tools that read login UIDs. Otherwise jobs start
  exactly as before: the same command lines, binding and exit codes.
* Where the ownership reader cannot tell who owns a value (Configuration
  Manager clients, DSC, Azure machine configuration, resultant set of
  policy logging turned off), Configuring logging only reports, and a
  channel whose access list it cannot change is not collected unless
  that list already grants the collector's SID.
* Store problems never stop or roll back EasyRMM; they show as degraded
  logs with `logs-db-init`'s status.
* Searches over a whole fleet's month by free text run in the background;
  searches by device, user, address, process or code are quick.
* People who can see a computer's sign-ins can see who works when;
  customers can decline collection per organization, and every search is
  audited for their administrators.
* ADR-0017's Windows jobs start inside their job object, its Linux jobs
  get a login UID of their own, and its guidance says not to pass
  secrets as arguments; ADR-0023's
  single collector becomes a list; ADR-0052's updater never touches the
  store and reports the data root's size; ADR-0051's undo follows the
  last-one-out rule for auditd, which H2 adopts; ADR-0054 reports this
  ADR's audit table and builds the ownership reader both use; ADR-0058
  must allow keys that stay on the server; ADR-0053's rules gain the `log`
  condition and these EasyRMM events. database.md, backup-restore.md,
  rbac.md, PRIVACY.md, the guide, IMPLEMENTATION_STATUS, ROADMAP and the
  CHANGELOG change with each slice.

## Questions for the owner
These are the owner's to answer; until then the ADR proposes what is
written above.

1. Collection on by default for new installs, with 30-day retention?
2. `log.view` at Site Administrators (who may be customers' staff, and
   already have terminals), or Organization Administrators?
3. A second PostgreSQL instance, by default at `<data root>-logs` outside
   the updater's copy, with a disk of its own recommended above about 500
   devices?
4. Domain controllers configured only when chosen (then with Kerberos
   and directory service auditing and a 4 GiB Security log)?
5. EasyRMM's job events kept in full with only argument values replaced,
   where the plan dropped them?
6. The previous 24 hours read on first start?
7. Organizations' own SIEM destinations, and a rule language such as
   Sigma, wanted later?
8. No erasure of one person's events, logs expiring with retention, on
   the basis stated in Privacy?
9. A removed device's logs kept until retention ends, purged earlier only
   with its organization or site, or by an Organization Administrator's
   audited request carried out after 7 days?
10. The full baseline audit policy and a 1,024,000 KB Security log on
    every Windows computer by default?
11. The console's Windows install card proposing a one-day approval token
    by default?
12. On computers where the reader *cannot tell* who owns a channel's
    access list (Configuration Manager clients are common in larger
    networks), the Security log is not collected unless that list already
    grants the collector's SID: acceptable until W1's readers exist, as
    ADR-0054 asks for hardening's check only?
13. Should command lines in process events default on, given that job
    argument values then appear in the computer's own Security log?
