# ADR-0069: Recovering agents from either side, live agent logs, and one device tree

* Status: Accepted (2026-11-23, after an independent review). Slice R1
  implemented; the rest not implemented.
* Revised after an independent review (2026-11-23): logs go over signed
  HTTPS, since the agent channel carries nothing from the agent; the
  EasyPatch agent is repaired in place, keeping its enrollment; the
  recovery copy lives in the agent's protected state directory and is
  checked against a hash the server sends; nothing repairs or alerts on a
  device being removed; a move to another site moves the MeshCentral node;
  a move to another organization cancels the old organization's queued
  runs and ends sessions; real permissions; no repair during a
  self-update; an *attempt* is defined; the data the conditions need is
  added; engine results gain a diagnostics field.
* Asked for by the owner (2026-11-23), after a device checked in while its
  MeshAgent was not connected to MeshCentral and nothing in EasyRMM could
  bring it back. The owner's words set the requirements below; everything
  marked *decided in review* is mine and the owner can overturn it.
* Amends, each gaining an *Amended by ADR-0069* line when its slice lands:
  [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (MeshAgent delivery: a watchdog and
  a repair path), [ADR-0021](0021-console-navigation.md) (one tree on every
  device view), [ADR-0031](0031-easypatch-agent-install.md) (the EasyRMM
  agent repairs the EasyPatch agent, and the reverse), and
  [ADR-0059](0059-the-agents-websocket-channel.md) (log records on the channel).
* Related, unchanged: [ADR-0060](0060-collecting-logs.md) collects the
  computer's own logs (Windows events, syslog). This ADR is about the
  agents' own diagnostic logs only.

## Context

A device has three agents, each run as LocalSystem or root:

* the **EasyRMM agent** (`agent/`, Go), which checks in to EasyRMM,
  installs MeshAgent from the settings the server signs
  (`agent/meshagent/meshagent.go`), and installs the EasyPatch agent
  (`agent/easypatch/easypatch.go`, ADR-0031);
* **MeshAgent**, which carries remote sessions to MeshCentral. MeshCentral
  has one device group per site (`mesh_sites`);
* the **EasyPatch agent** (`easypatch/agent/`, .NET), which polls its
  engine over HTTPS for jobs (installs, removals, policy, messages, its own
  update).

What happens today when one of them breaks:

* MeshAgent is restarted when it exits, by systemd
  (`agent/meshagent/service.go:148`), by Windows' recovery actions
  (`system_windows.go:943`) or by the EasyRMM agent's child supervisor
  (`meshagent.go:202-223`). Nothing repairs a MeshAgent that runs but
  cannot connect: a broken or missing program, settings pointing at another
  server, or a node in another site's MeshCentral group. The server only
  sees that MeshCentral says the node is not connected, and the console
  says so without a reason (`DeviceDetailPage.tsx:125`).
* Nothing repairs a stopped or broken EasyPatch agent. EasyRMM only
  reinstalls it when the link check fails.
* Nothing repairs a stopped or broken EasyRMM agent. The EasyPatch agent,
  which is often still running, has no way to help.
* Both agents write logs to local files only (the EasyRMM agent at Info,
  with no level setting; the EasyPatch agent to rolling files and the
  Windows event log). To find out why something failed, someone has to
  sign in to the computer.
* The console's tree (`web/src/nav/tree.ts`) knows organizations, sites and
  devices, not device groups, and each section shows a different subset:
  Patching stops at sites, Scripts shows no devices, Organizations stops at
  sites. Nothing in the console or the API moves a device to another group,
  site or organization after enrollment.

## The requirements (the owner's)

1. **Recovery from either side.** If patching is down, EasyRMM fixes it
   from the EasyRMM agent; if the EasyRMM agent is down, EasyRMM fixes it
   from the patching side. Both sides can recover MeshAgent's connection to
   MeshCentral.
2. **Verbose logging** for the EasyRMM agent and the EasyPatch agent, sent
   live to EasyRMM and stored there, so the console shows what is going on
   and why something is not working.
3. **One tree, 100% coherent, on every view**: organizations, sites, device
   groups (always shown when there are any) and devices. Selecting a node
   filters whatever the view lists. Views differ only in what they offer
   once a group or device is selected.
4. **Drag and drop** devices onto any organization, site or group in the
   tree, since there is no easy way today to change a device's group after
   enrollment.

## Decision

### Who may do what

| Action | Permission (existing unless marked new) |
|---|---|
| Repair through the EasyRMM agent (MeshAgent, EasyPatch agent) | `device.edit` on the device |
| Repair through patching (the EasyRMM agent, MeshAgent) | `patch.manage` on the device |
| Turn verbose logging on or off | `device.edit` on the device |
| Read agent logs | `log.view` (new, the name ADR-0060 chose), held by Technicians and above |
| Move a device to another group in its site | `device.edit` on the device |
| Move a device to another site in its organization | `device.edit` on the device and `site.manage` on both sites |
| Move a device to another organization | `device.edit` on the device and `org.manage` on both organizations |
| Turn automatic repairs off for an organization | `org.manage` |

### Part R: recovery from either side

A **repair** has a target (`easyrmm-agent`, `meshagent` or
`easypatch-agent`), the agent that carries it out, and steps tried in
order:

| Step | What it does |
|---|---|
| `restart` | Restarts the target's service (Windows service, systemd unit), or its child process where MeshAgent runs as the EasyRMM agent's child |
| `repair` | Puts the target's program and service back in place without losing its identity: enrollment, node ID and keys stay |

**What each path can do:**

| Carried by | Target | Steps |
|---|---|---|
| EasyRMM agent | MeshAgent | `restart`; `repair`: stop it, write the program and its settings (`.msh`) again from the server-signed MeshAgent and settings (ADR-0015), keeping its node identity file, start it |
| EasyRMM agent | EasyPatch agent | `restart`; `repair` in place, keeping its enrollment: on Windows `msiexec /fa` with the same version's package, downloaded and verified as the installer does today; on Linux `apt-get install --reinstall` or `dnf reinstall` of the same version. It never runs the install path, which refuses an enrolled agent (`easypatch.go:220-227`) and would make a new endpoint |
| EasyPatch agent | EasyRMM agent | `restart`; `repair` from the recovery copy (below) |
| EasyPatch agent | MeshAgent | `restart` only. MeshAgent's settings are signed by EasyRMM, so through patching the EasyRMM agent is repaired first and then repairs MeshAgent |

**The recovery copy.** The EasyRMM agent keeps a copy of its own program in
`recovery/` under its state directory (`host.State()`: `%ProgramData%`'s
EasyRMM agent directory on Windows, `/var/lib/easyrmm-agent` on Linux),
protected by `host.Protect` and checked by the agent's existing state
checks like the rest of that directory. It writes the copy only after a
self-update has reached its new version (`update.Reached()`, ADR-0027),
never during the update's probation, and from the program it is running.
The server records the SHA-256 of each agent build it publishes, and each
device's build, as `devices.agent_sha256`.

The EasyPatch agent's `repair` of the EasyRMM agent:

1. refuses while the state directory holds the self-update marker
   (`update.json`), since an update is in progress or its probation is open;
2. opens the copy without following links or reparse points, and refuses
   unless its owner is LocalSystem or root and only LocalSystem,
   Administrators or root may write it and every directory above it;
3. refuses unless its SHA-256 equals the hash in the job, which EasyRMM
   took from `devices.agent_sha256`;
4. runs the copy's own `easyrmm-agent repair-install` command (new). That
   command, the EasyRMM agent's own code, puts itself back in the program
   directory, registers its service as the installer does and starts it.
   The .NET side builds no service definition.

**MeshAgent watchdog** (EasyRMM agent). Each heartbeat reports MeshAgent's
state: installed, running, node ID, the MeshCentral host its settings
name, and the last error it could read. The console replaces "its
MeshAgent is not connected" with the reason: not installed, installed but
not running, settings for another server, running but not connected
since a time, or its node is in another site's MeshCentral group.

**The EasyPatch jobs.** The engine gains two job types, sent only to agent
versions that support them (the engine knows each endpoint's version):

* `RepairCompanion {target, step, expectedSha256}`: a fixed action, not a
  command line. The agent maps the target and step to code it ships with.
* `CollectLogs` (Part L).

Their results use a new `Diagnostics` field, separate from the 2,000
character message (`AgentDtos.cs:260-272`): at most 256 KiB, redacted by
the agent (Part L), kept 14 days by the engine. EasyRMM requests both
through the connector and moves the diagnostics into its own log store.
The engine's contract test and `eptest` gain them.

**Never for a device that is leaving.** No repair, automatic or by hand,
and none of Part R's alerts, for a device with a row in `device_removals`,
`easypatch_removals` or `easypatch_opt_outs`, or a target the device is
not meant to have (an EasyPatch agent where patching is off for its
organization). Removing a device's EasyRMM agent deletes the recovery copy
first.

**What the server needs to know** (new data):

* `devices.remote_changed_at`: when the device's MeshCentral state last
  changed, set by the device sync (`server/internal/remote/service.go`).
* The EasyPatch agent's last check-in: the server reads it from the engine
  for linked endpoints every 5 minutes (one list call per engine
  organization) and stores it as `easypatch_devices.agent_seen_at`.
* Conditions are not judged while EasyRMM's own connection to MeshCentral
  or to the engine is down, or within 15 minutes after it returns, so an
  outage of either does not open alerts or start repairs on every device.

**Automatic repairs.** An *attempt* is one escalation: the first step,
then the next if the target is still broken after the wait. Its timer
starts when the condition is first seen. At most one attempt per target
per device in 6 hours, and 3 a day. Each organization can turn automatic
repairs off (a new `organizations.auto_repair`, default on); repairs by
hand stay available.

| Condition | Seen for | Carried by | Step, then after |
|---|---|---|---|
| EasyRMM agent checks in, MeshAgent not connected | 10 min | EasyRMM agent | `restart`; `repair` after 20 more min |
| EasyRMM agent checks in, EasyPatch agent silent past twice its check-in interval | 30 min | EasyRMM agent | `restart`; `repair` after 30 more min |
| EasyRMM agent silent, EasyPatch agent checking in | 15 min | EasyPatch agent | `restart` the EasyRMM agent; `repair` after 30 more min |

When the EasyRMM agent comes back after a repair through patching and
MeshAgent is still not connected, the first row starts over. A device
whose attempt ends broken gets one alert (*Repair failed*, warning) with
the last step's diagnostics.

**Default alerts** (the owner's, 2026-11-23). Two shared policies, on from
the start like *Disk failing*, each a new alert condition (the conditions'
`CHECK` constraint in migration 00031 gains them):

| Policy | Opens when | Resolves when |
|---|---|---|
| *Remote access down* (critical) | The EasyRMM agent checks in but MeshAgent has not been connected for 15 minutes (`remote_changed_at`) | MeshCentral sees it connected |
| *EasyRMM agent silent* (critical) | MeshCentral sees MeshAgent connected but the EasyRMM agent has not checked in for 15 minutes | The EasyRMM agent checks in |

They follow the same rules as Part R's conditions: nothing for a device
being removed, nothing while EasyRMM cannot reach MeshCentral. Each card
shows the watchdog's reason and the repairs tried since the alert opened.
As for every shared policy, an operator can change the 15 minutes or turn
it off, and add organization or site policies instead.

**Amended 2026-11-23 (decided in review), slice R1.** What the code
settled:

* A repair step reaches the agent as a signed instruction in a heartbeat
  answer (target and step from fixed lists, bound to the device, valid 15
  minutes, the job key signing it), and its outcome comes back in the next
  heartbeats. It is carried out in the background, so a slow download does
  not hold the heartbeats.
* `devices.remote_changed_at` is set by a database trigger on changes of
  `remote_online`, which covers the device sync and a heartbeat's link
  alike; it starts at the migration for devices that exist, so an upgrade
  opens no alert for a state that is not new. A device with none yet counts
  from its enrollment.
* "Settings for another server" is judged by the server: the agent reports
  the host its settings name, and the server compares it with the host of
  the settings it would hand the device's site (remembered for 10
  minutes). "Its node is in another site's group" is a flag the device sync
  sets when it unlinks such a node (`devices.mesh_wrong_group`) and clears
  when a sync finds the node in the device's own site.
* The step wait of a repair someone asks for is 2 minutes; a step the
  carrying agent does not take in 15 minutes, or a repair of an hour, ends
  it as failed. A failed step goes straight to the next. Automatic
  repairs keep the waits in the table above (slice R2).
* The two alert conditions are `remote_down` and `agent_silent`. Their
  alerts are judged only while EasyRMM's control session to MeshCentral is
  open and has been for 15 minutes, which also covers a restart of the
  server. Without remote access their alerts resolve. The "never for a
  device that is leaving" rule covers all three tables in this slice, for
  alerts and for repairs by hand.

**Amended 2026-11-23 (decided in review), slice R2.** What the code
settled:

* `devices.agent_sha256` already existed (ADR-0027: the SHA-256 the agent
  reports for its build, and the server's published builds carry theirs);
  R2 adds nothing there. The recovery copy is the running program, so its
  hash is the device's.
* The repair instruction carries the EasyPatch package for the
  `easypatch-agent` `repair` step, and only for it (`RepairPayload.EasyPatch`:
  the engine's CA and the packages of the version installed, size and
  SHA-256 included, checked as an install checks them; no enrollment
  token). The version is the one the device reported, or, where the agent's
  program is gone and it reports none, the engine's last record of it; where
  the engine no longer lists it, the repair ends with that reason, since an
  update is not a repair. The agent refuses an agent that is not enrolled
  and a package of another version than the one it finds installed.
* An EasyPatch repair's step wait by hand is 7 minutes, not 2: the engine's
  view of a check-in reaches EasyRMM every 5 minutes. Automatic repairs
  wait 20 minutes (MeshAgent) and 30 minutes (EasyPatch agent) after each
  step, so an automatic repair may run 2 hours (a repair by hand, 1).
* "Silent past twice its check-in interval" is 10 minutes: twice the
  engine's default interval of a minute is below what a 5-minute poll can
  tell, and the engine's per-endpoint interval is not read. An organization
  that sets it longer is waited on for the condition's 30 minutes.
* The time since a condition holds is kept in `agent_conditions`, written by
  the evaluator and forgotten for a target whenever its condition cannot be
  judged, so after an outage the clocks start over.
* MeshAgent is repaired automatically only where the EasyRMM agent
  supervises it (it reported MeshAgent's state) and the site has a
  MeshCentral group; the EasyPatch agent only where it is linked.
* *Repair failed* is alert kind `repair_failed`, with no policy (the
  subject is the target). The sweep that resolves alerts of changed or
  deleted policies leaves it alone; the recovery service resolves it when
  the target is back or the device starts to leave.
* The row of the table where the EasyPatch agent repairs the EasyRMM agent
  (and the EasyPatch agent's own `RepairCompanion` job) is slice R3. In R2
  `repair-install`, the recovery copy and its removal exist and are tested
  on Windows and Linux; nothing runs the copy yet but a person.
* The recovery copy is made only by an agent that can read its own
  executable (it has an updater), after its first heartbeat past probation,
  and is tried again at each start; a failure is logged.
* Removal: the recovery copy goes before the service in an uninstall by hand
  and in a removal the server asked for.

**Amended 2026-11-23 (decided in review), slice R3.** What the code
settled:

* The engine's `RepairCompanion` job carries `target`, `step` and
  `expectedSha256`; the engine refuses anything off the fixed lists (the EasyRMM
  agent: `restart`, or `repair` with a lower-case SHA-256; MeshAgent: `restart`
  and no hash), and sends the jobs only to an agent that declares the
  `repair-companion` and `collect-logs` capabilities (Windows and Linux agents
  from this version; the engine knows no more of an agent's version than
  what it declares). The jobs expire in 30 minutes and go before other queued
  work, though the agent still takes one job at a time: a repair behind a
  running install waits for it.
* `Diagnostics` is a new field of a job's result and of the engine's job
  detail, kept apart from the message: 256 KiB of UTF-8 at most (the engine
  refuses more), kept 14 days after the job ended (the engine's job
  maintenance empties it; the job stays). The agent redacts with the rules of
  `logredact` (the EasyPatch agent's `LogRedactor` now has them all: names
  like secrets, `ert_`, `ept_`, bearer tokens, PEM blocks, and a line it
  cannot redact in time is withheld, never sent).
* The four checks are made in this order and each refuses with a code the job
  reports: the update marker, then links and owner and access list, then the
  hash, then `repair-install` of the copy. Two readings of "the system": on
  Windows the copy may be owned by LocalSystem **or the Administrators group**,
  because Windows makes that group the owner of what a process running as
  SYSTEM creates (the EasyRMM agent's own state check accepts both); and for
  the directories *above* the copy's own folder only the rights that let
  someone replace what lies below count (delete what the folder holds, delete
  it, change its access list or owner, full control), since ProgramData and a
  drive's root let every user add a folder and a strict reading would refuse
  every Windows computer (the same rule as ADR-0064's folders above a
  PowerShell install). On Linux every directory above, and the copy, must be
  owned by root, not writable by group or others, and the copy must have one
  hard link. Links are found by `stat` without following them; the copy is
  hashed and run from the path checked, which only root or the system could
  have changed. POSIX ACLs are not read.
* Security review (decided in review): the hash a repair is checked against
  is never the device's own word (`devices.agent_sha256` is set by its heartbeat).
  EasyRMM sends it only when it is the SHA-256 of a build this server
  publishes for the device's platform and architecture: a bundled build, or a
  row of `signed_agent_builds`. Otherwise the *repair* step is refused with a
  reason the console shows; *restart* steps stay allowed. So a device running
  a build the server no longer publishes cannot be repaired from its copy:
  update or reinstall its agent. On Windows each directory above the copy must
  also be owned by SYSTEM, Administrators or TrustedInstaller, since an owner
  can rewrite the access list; and the redaction rules cover command-line
  forms (`--password x`, `-Password x`, `/password x`) in the agent's and the
  server's `logredact`, and the job's message, not only its diagnostics.
* Through patching, a step is carried out by EasyRMM asking the engine for the
  job (the server's repair loop, not a heartbeat), reading its result, and
  cancelling in the engine a job that did not run within 15 minutes so that it
  cannot run after the repair moved on. The step's diagnostics are kept on the
  repair (`agent_repairs.diagnostics`, redacted again by the server, 256 KiB,
  14 days) because the agent log table (slice L1) was not on this branch's
  base. Amended 2026-11-23 (decided in review): L1 has landed, but moving them
  into `agent_log_records` is not a few lines (free text must be split into
  records, `recovery` would depend on `agentlogs`, and the column and its
  retention go), so they stay on the repair until a slice of their own does it,
  with a source per agent. A `CollectLogs` job is built and tested through
  the connector (`easypatch.Service.CollectLogs`, `CompanionResult`) for L1's
  Logs tab to ask for when the EasyRMM agent is down; nothing in R3 asks
  for it.
* *EasyRMM agent silent while the EasyPatch agent checks in*: the EasyRMM agent
  has not checked in for 3 minutes but did before, the device is patched and
  its EasyPatch agent is linked and heard from by the engine within 10 minutes;
  15 minutes of that, then `restart`, and `repair` after 30 more minutes, with
  R2's limits, exclusions and settling. A repair by hand waits 2 minutes after
  a step, because the answer is the EasyRMM agent's own heartbeat, and is
  refused while the agent checks in or while the EasyPatch agent has been
  silent for 10 minutes. When the EasyRMM agent comes back and MeshAgent is
  still not connected, the first row's clock starts over by itself: the
  condition could not hold while the agent was silent.

**By hand**: the device page offers *Reconnect remote access* and *Repair
patching agent* (with `device.edit`) and *Repair EasyRMM agent through
patching* (with `patch.manage`), each showing its steps and outcome.

### Part L: live agent logs

* **Levels.** Both agents log at Info by default and at Debug while the
  device is in *verbose* mode, set for 1 to 24 hours (default 2) on a
  device or a group, ending by itself, audited. The EasyRMM agent's logger
  gains a level (today it has none, `logfile.go`); the EasyPatch agent
  already has one (`Program.cs:80-96`).
* **Sending.** The agent channel carries nothing from the agent
  (ADR-0059), so the EasyRMM agent sends batches to
  `POST /api/agent/v1/agent-logs`, signed like its heartbeat, every 30
  seconds, or every 2 seconds while someone is watching the device's
  logs: the server asks for that with a new channel message,
  `logs.follow {until}`. The server acknowledges the highest sequence it
  stored; the agent drops what was acknowledged. Unsent records wait in a
  file of at most 20 MB under the state directory, oldest dropped first;
  the next batch says how many were dropped.
* **Sources.** The EasyRMM agent sends its own records and new lines from
  the EasyPatch agent's log files and MeshAgent's log where it keeps one,
  each tagged with its source.
* **When the EasyRMM agent is down**, EasyRMM collects through patching: a
  `CollectLogs` job returns the last 500 lines of each of the three agents'
  logs in its `Diagnostics` field, and each `RepairCompanion` result
  carries its target's.
* **Redaction at the source**, by both agents, before a record leaves the
  computer: values of fields named like secrets (token, password, secret,
  key, authorization, cookie), and anything shaped like an EasyRMM
  enrollment token (`ert_`), an EasyPatch token (`ept_`), a bearer token
  or a PEM block. The server applies the same rules again before storing.
* **Storage.** One table, `agent_log_records` (device, source, time,
  level, message, attributes as JSON, sequence for de-duplication),
  indexed by device and time, with row-level security as for devices.
  Kept 14 days (the owner's; a deployment setting, 1 to 90), deleted in
  batches by the server's maintenance loop; at most 200,000 records per
  device per day. An estimate: a few hundred records a day per device at
  Info, up to about 50,000 a day in verbose mode.
* **The console.** The device page gains a **Logs** tab (ADR-0068's tab,
  not yet built; this is its first mode, *Agent logs*): a live tail,
  filters by source, level, time and text, *Verbose for…*, and a download
  as text or JSON lines. PRIVACY.md gains what agent logs can hold (user
  names, paths, host names) and how long they are kept.

### Part T: one device tree on every view

* The tree's levels are organization → site → device group → device.
  Groups always show under their site when it has any; devices without a
  group show directly under the site, after its groups.
* Every view about devices shows the same tree, with the same nodes and
  devices: Organizations, Devices, Alerts, Scripts, Jobs and Patching.
  Settings keeps its own list (the owner's).
* Selecting a node sets `organizationId`, `siteId`, `groupId` or
  `deviceId` in the address, and every list on every view filters by it.
  The server's list endpoints gain `groupId` where they lack it. With a
  device selected, each view shows that device's part: its page, its
  alerts, its jobs, its scripts' runs, its patching.
* For large fleets the tree loads a node's devices when it is opened, has
  a search box, and renders only the rows on screen.
* A site's menu in the tree offers *New group* (`site.manage`); a group's
  offers *Rename* and *Delete* (its devices move to the site).

### Part D: moving devices

* **API.** `POST /api/v1/devices/move` with up to 500 device IDs, a target
  site and an optional group. It checks every device first and moves all
  or none, with the permissions above. Each device's move is audited.
* **Remote access follows.** The MeshCentral client gains a call that
  moves a node to another device group (MeshCentral's `changeDeviceMesh`).
  A move records the device's new site as the desired state; the device
  sync moves the node to the new site's group instead of unlinking it as
  it does today for a node in another site's group
  (`remote/service.go:414-420`), and the heartbeat's link check accepts
  the node while the move is pending (`heartbeat.go:123`). The next
  heartbeat reply carries the new site's signed MeshAgent settings, and
  the agent rewrites the group in its `.msh` and restarts MeshAgent.
* **Patching follows.** The engine's existing site reconcile
  (`reconcile.go:717`) moves the endpoint to the matching engine site. On
  a move to another organization the link follows the existing *moved*
  rule (`links.go:401-419`): if automatic installs are on and the agent is
  neither imported nor opted out, the endpoint is removed from the old
  engine organization and the agent re-enrolled in the new one; otherwise
  the link stays unlinked with its reason. Patch history stays with the
  old organization.
* **Another organization's data stays with it.** Before a move to another
  organization the API cancels the device's queued job runs of the old
  organization (audited), refuses while a run is in progress ("try again
  when it finishes"), and ends open remote sessions. Job runs, alert
  history, patch history and audit records keep their organization and
  site, so the old organization's people keep their history and the new
  organization's do not see it; open alerts are resolved as *device
  moved*. D1's pull request lists every table that holds a device's
  `organization_id` or `site_id` and says for each whether it moves or
  stays, with a test per table.
* **The console.** Device rows, in the tree and in every device list, can
  be dragged (one or many selected) onto an organization, site or group
  node. A move to another site or organization asks for confirmation,
  naming what follows. Every drag has a keyboard and screen-reader
  equivalent: *Move to…* in the row's menu, in bulk actions and on the
  device's page opens the same tree as a picker.

### Amended 2026-11-23 (decided in review), slice L1

Found while building slice L1; the safe choice was made and is recorded
here.

* **`logs.follow {until}` travels in answers, not on the channel.**
  ADR-0059's channel is not built (the ADR is Proposed). The EasyRMM agent
  receives `logs.followUntil` and `logs.verboseUntil` (Unix seconds) in the
  heartbeat answer and in the answer to each log batch, with the meaning
  this ADR gives `logs.follow`. The first 2-second sends can therefore
  start up to a minute after someone opens the Logs tab (the heartbeat's
  interval); once sending, each batch's answer renews them. When the
  channel exists, the same message moves there. The agent never follows
  longer than 15 minutes, nor logs at Debug longer than 24 hours, from
  what an answer says, and ends verbose mode at its end time by itself.
* **Sequence numbers** start at the time in microseconds the first time an
  agent runs and rise from there, kept across restarts (the buffer file and
  a small file of the last acknowledged), so an agent whose state was lost
  never repeats one the server holds. The server keeps one record per
  device and sequence, and writes records of its own, sequence -1, to say
  how many records an agent dropped or the server refused at the daily cap.
* **The retention setting** is the deployment setting
  `EASYRMM_AGENT_LOG_RETENTION_DAYS` (1 to 90, default 14), counted from
  when the server received a record, since a device's clock may be wrong.
* **Verbose mode on a group** is kept as its own row and covers devices
  added to the group later. A device's own setting and its group's are
  both in force; the later end wins.
* **Not in slice L1:** verbose mode does not change the EasyPatch agent's
  own level yet; the agent reads its log file at the level the file has.

## Slices

Each is one pull request, in this order within its chain; the three
chains are independent.

| Chain | Slice | Contents |
|---|---|---|
| Tree | T1 | Group level in the tree; one tree on every device view; `groupId` filters on the server |
| Tree | D1 | Move API; MeshCentral node moves and signed settings; the organization rules and the table list; drag and drop; *Move to…*; group menu (new, rename, delete) |
| Logs | L1 | EasyRMM agent levels, buffer and signed batches; `logs.follow`; tailing the EasyPatch and MeshAgent logs; storage, retention; the device's Logs tab with *Agent logs*; verbose mode; `log.view` |
| Recovery | R1 | MeshAgent state in the heartbeat and the console's reasons; watchdog; *Reconnect remote access* (restart, reinstall); the two default alerts |
| Recovery | R2 | EasyRMM agent repairs the EasyPatch agent in place; the recovery copy and `repair-install`; `devices.agent_sha256`; the EasyPatch agent's check-in time; automatic repairs, their limits and *Repair failed* |
| Recovery | R3 | EasyPatch `RepairCompanion` and `CollectLogs`; the connector and `eptest`; repairs through patching |

## Testing

* Agents: unit tests for each step on Windows and Linux runners (stop a
  service, delete a program, corrupt the recovery copy and see the hash
  refuse it); the redaction rules against a table of secrets.
* Server: integration tests for the repair schedule (limits, back-off,
  the alert), the move API (permissions, all-or-none, MeshCentral and
  engine effects), log intake (de-duplication, caps, retention, RLS).
* EasyPatch: engine and agent tests for both job types; the contract
  test; `eptest` copies the engine's rules.
* Console: vitest for the tree on every view and for drag and drop and
  its keyboard equivalent; one end-to-end story that moves a device
  across sites and still opens a remote session, and that sees a stopped
  MeshAgent come back.
* The owner's host after each slice: a stopped MeshAgent, a stopped
  EasyPatch agent and a stopped EasyRMM agent on a real computer each
  come back without anyone signing in to it.

## Consequences

* The EasyPatch engine gains a new power: on a linked endpoint it can
  restart the EasyRMM agent and MeshAgent, and restore the EasyRMM agent.
  Today it cannot choose what code runs (operating system updates, and
  its own signed agent updates only). The restore is bounded: only the
  copy already on the computer, only with the hash EasyRMM supplies, only
  through the agent's own install command. It is added to the threat
  model.
* Agent logs are personal data in places; they are redacted, kept 14 days
  by default and behind their own permission.
* Moving a device across organizations re-enrolls its EasyPatch agent
  where automatic installs allow it, and cancels its queued runs.

## Owner decisions

The owner confirmed (2026-11-23):

1. Automatic repairs are on by default, at most 3 a day per target, and
   both default alerts open after 15 minutes.
2. Agent logs are kept 14 days by default.
3. Settings keeps its own list rather than the tree.

## Amendments

* **Amended 2026-11-23 (decided in review): alerts do not stay with the old
  organization.** Part D said alert history keeps its organization and site.
  Alerts have no organization of their own; they follow their device. Keeping
  them would show the old organization's alert history to the new one, so a
  move to another organization deletes the device's alerts, open and
  resolved. Job runs, patch history and audit records keep their organization
  and site as written. The move's pull request lists every table and tests
  each (`docs/operations/moving-devices.md`).
* **Amended 2026-11-23 (decided in review): agent logs do not stay with the
  old organization either.** For the same reason, a move to another
  organization deletes the device's agent log records and their counters. A
  device's verbose-logging setting ends with any move to another site, since
  someone with rights on the old site set it and its row names that site.
  Repair history goes with a move to another organization too: it names who
  asked and keeps the steps' output.
* **Amended 2026-11-23 (decided in review): patching tabs stay per site.** The
  patching engine has no device groups, so Patching's Updates, Jobs and
  Alerts tabs show the site of a chosen group or device and say so; the
  Devices tab narrows to the group or device.
* **Amended 2026-11-23 (decided in review): the tree has its own counts.**
  Loading a node's devices only when it opens needs counts and groups
  beforehand, so `GET /device-tree` returns them.
* **Amended 2026-11-23 (decided in review): the settings instruction.** The
  heartbeat reply carries the hash of the new site's MeshAgent settings, not
  the settings; the agent fetches them from the signed settings download,
  checks the hash and reports the hash it applied, which ends the instruction.
* **Amended 2026-11-23 (decided in review): a MeshAgent that will not stop is
  stopped by force, by exact path.** On Windows the restart and the repair
  asked the service to stop and gave up after 30 seconds, and a repair then
  failed to replace `meshagent.exe` while MeshAgent's session helpers still
  ran it. After 30 seconds the agent now terminates the service's process
  (from `QueryServiceStatusEx`) and every process whose image path is exactly
  `meshagent.exe` in EasyRMM's MeshAgent folder, matched on the full path
  case-insensitively and never by name, since the client may run another
  vendor's MeshAgent. It waits for each to exit and confirms the service is
  stopped, and logs what it ended. The repair retries a denied rename with a
  short backoff, then moves the old program aside to a dot-name in the same
  folder, moves the new one in and deletes the old one (at the next restart if
  locked), removes leftover `.meshagent-*` files, and confirms the service
  runs. Linux is unchanged.
* **Amended 2026-11-26: one Repair button.** The owner: "You have 3 different
  buttons to repair things. There should just be one repair button, and it
  should have the logic to know what to repair. If Mesh is offline but the
  agents are online, then use the agents to repair the mesh. If Patch or RMM is
  offline and there is still at least one agent running, then use the running
  agent to repair what is not working." *By hand* above is replaced: the device
  page has one **Repair** button, and the server decides.

  *What is down.* The EasyRMM agent is down when it has not checked in for 3
  minutes (`AgentFresh`). MeshAgent is down when this server runs remote access,
  the device's site has a MeshCentral group and MeshCentral does not see it
  connected. The EasyPatch agent is down when the device's organization is
  patched, its agent is linked, and the engine has not heard from it for 10
  minutes (`SilentAfter`). An agent the device is not meant to have is never
  down.

  *The decision table.* Only the EasyRMM agent and the EasyPatch agent can
  carry a repair out (MeshAgent cannot: its program and settings are signed by
  EasyRMM and carried by the EasyRMM agent).

  | Down | Runs | Repair started now | Waits |
  |---|---|---|---|
  | MeshAgent | EasyRMM agent | MeshAgent, by the EasyRMM agent | |
  | EasyPatch agent | EasyRMM agent | EasyPatch agent, by the EasyRMM agent | |
  | MeshAgent and EasyPatch agent | EasyRMM agent | both, by the EasyRMM agent, as two repairs | |
  | EasyRMM agent | EasyPatch agent (and MeshAgent or not) | EasyRMM agent, by the EasyPatch agent | |
  | EasyRMM agent and MeshAgent | EasyPatch agent | EasyRMM agent, by the EasyPatch agent | MeshAgent: once the EasyRMM agent is back, Repair (or the automatic repair) takes it |
  | EasyRMM agent and EasyPatch agent | MeshAgent only, or nothing | nothing | refused, `no_running_agent`: reinstall the EasyRMM agent on the device |
  | all three | nothing | nothing | refused, `no_running_agent` |
  | none | all | nothing | refused, `nothing_to_repair` |

  Where several are down and a running agent can repair them, they are
  repaired together, each as its own repair with its own steps. Where the
  EasyRMM agent is down, the repair that brings it back goes first and the rest
  wait for it, since only it can repair them; the dialog says so. A target
  that is being repaired already is left alone; if that is all there is, the
  press is refused (`repair_running`). A device that is leaving, one without an
  EasyRMM agent and a server that cannot sign instructions are refused with
  their own codes.

  *No new trust path.* Each repair the plan names is an ordinary repair made
  by `Request`: the same preconditions, the same signed instruction in a
  heartbeat answer (or the same engine job through patching), the
  `publishes()` check of the hash for the EasyRMM agent's repair step, the same
  `agent_repairs` record and the same steps and waits. The plan only chooses
  which targets and carriers; nothing it decides is sent to an agent.
  Permissions stay those of the repairs: `device.edit` for what the EasyRMM
  agent carries, `patch.manage` for the EasyRMM agent through patching; a press
  whose plan needs a permission the caller lacks starts nothing.

  *The endpoint.* `GET /api/v1/devices/{id}/repair-plan` says what pressing
  Repair would do (the dialog's "what will happen" line, from the server so
  that the words and the actions cannot differ); `POST /api/v1/devices/{id}/repairs`
  with an empty object decides again, starts the repairs and audits
  `device.repair_plan` with the plan's id, what was down, what waits and the
  ids of the repairs it started (each repair keeps its own `device.repair_request`
  row). The `target` field is gone from the request.

  *Automatic repairs use the same table.* The conditions of Part R still say
  when to try (how long, the limits, the organization's switch); before an
  attempt starts, the table must name the target for the device now. No new
  automatic behaviour is added, and each attempt is subject to the dev-scope
  guard (`devscope.Allowed(organization)`) once it lands; the place is marked
  in `recovery/auto.go` (`evaluateTarget`, before the plan is read).

  *Per-agent actions.* The three buttons go and no per-agent action is kept in
  the console: the table covers every state in which something can be repaired,
  and a repair of an agent that is running (a restart nobody needs) has no
  case. The service's `Request(target)` stays because the plan and automatic
  repairs build on it, not as an API.

  *Diagnostics into the Logs tab.* Slice R3 kept a step's diagnostics on
  `agent_repairs.diagnostics`, waiting for the agent log table. They now go
  into `agent_log_records` as records of the EasyPatch agent (the only carrier
  that returns diagnostics): one per non-empty line, at the time the step
  settled, level `info` (`warn` for a failed step), with the repair id and step
  as attributes, redacted whole and per line as before (the engine's agent
  redacted them first; `logredact` again here). They are the server's own
  records (sequence -1) and follow the log's retention (14 days by default)
  rather than the old column's. The column is dropped; migration `00047`
  moves what repairs hold into the log first.

  *The Logs tab's order.* The merged view was ordered by arrival, so a source
  whose batch came late appeared out of time order. It is now ordered by the
  time a record was logged, newest first, across every source, with the record
  id (the order the server stored them in) breaking ties, higher first, and the
  Logs tab shows the newest at the top. `before` pages to older records in that
  order; `after` still means "stored after this record", which is what the live
  tail needs, since a late batch can hold records older than the newest shown.
  A download is in time order, oldest first. Migration `00046` adds the index.

### Amended 2026-11-26 (decided in review), hardening guards

`hardening_guards` (migration `00049`, ADR-0054 W2) holds a device's id and no
organization or site, so a move leaves its rows alone: they follow the device,
like `device_hardening` and `device_hardening_checks`. An armed guard describes
the computer's own rollback timer, which a move does not touch; ending it or
the confirm job on a move would leave the timer to undo a change nobody saw.
The disposition test lists it as "follows the device". The other tables added
by migrations `00045` to `00053` (`agent_file_hashes`, `windows_module_settings`)
need no new row: the first holds no device, organization or site id, and the
second is already listed as owned. `device_roles` (columns on `devices`) and `step_up` (columns on `sessions`) add no
table.

### Amended 2026-11-26 (decided in review), compliance tables

The compliance library's organization tables (ADR-0078 C1, migrations
`00061` and `00062`): `compliance_packs` (an organization's own packs),
`compliance_org_packs` and `compliance_org_settings` belong to the
organization, so a device move leaves them alone; the disposition test lists
them as owned. A scan is a record of the organization that ran it:
`compliance_scans`, `compliance_scan_jobs` and `compliance_results_history`
stay with that organization after a move (listed as stays, like `job_runs`),
so evidence already shown for it is not rewritten; the device's next scan is
the new organization's.

The assessment workspace (ADR-0078 C5, migration `00076`): every table an assessment holds (`compliance_assessments`,
`_implementations`, `_objective_results`, `_attestations`, `_evidence`, `_evidence_links`, `_org_keys`, `_poam_items`,
`_poam_milestones`, `_documents`, `_document_sections`, `_score_snapshots`) is the organization's own record and is listed as
owned: a device move leaves it alone. `compliance_scope_assets` names computers: its rows stay with the assessment
(listed as stays), and a computer that has moved to another organization drops out of that organization's scope reading.
### Amended 2026-11-26 (decided in review), the registry editor's masked store

`registry_masked_values` (ADR-0067, migration `00072`) holds a copy of the
organization and site a value was read or typed at, as `job_runs` does, and
stays with that organization after a move (listed as stays): data kept for a
change's backup is evidence of what that organization's people did.

### Amended 2026-11-26 (decided in review), Quick Assist tables

ADR-0080's tables (migrations `00063` to `00065`): `quick_assist_links` and
`quick_assist_orgs` belong to their organization (owned). A session in
`quick_assist_sessions` is the record of help given under the Quick Assist
organization and stays with it when the device later moves (installed
permanently, then placed elsewhere); Quick Assist ends the session itself.

### Amended 2026-11-26 (decided in review), keystore tables

ADR-0081's tables: `keystore_org_keys` belongs to its organization (owned).
`device_encrypted_volumes` and `recovery_key_escrows` follow the device within
one organization (`moveOne` updates their `site_id`, which row-level security
reads) and end with a move to another organization: `leaveOrganization`
deletes them, with one `recovery_key.destroyed` audit event to the old
organization giving the counts and no key data. The records are sealed to the
old organization's key, and its people lose the device; the agent escrows
again to the new organization's key.

### Amended 2026-11-26 (decided in review), keystore reads

ADR-0081's slice 2 tables (migration `00068`): `keystore_alerts` and
`keystore_org_settings` belong to the organization (owned).
`keystore_notices` records a read shown to the organization at the time and
stays with it. `recovery_key_requests` follow the device's site within an
organization and end with a move to another one, as the escrow records do;
the audit log keeps every read.

### Amended 2026-11-26 (decided in review), notification channels

ADR-0053's slice 3 tables (migration `00074`): `notification_channels`,
`notification_channel_shares` and `notification_quotas` belong to their
organization (owned). A notice in `notices` was raised to the organization
of its time and stays with it when a device it names moves.

### Amended 2026-11-26 (decided in review), device alert rules

ADR-0053's slice 4 tables (migration `00077`): `notification_rules` and
its `notification_rule_orgs`, `notification_rule_sites` and
`notification_rule_groups`, and `site_maintenance_windows`, belong to
their organization or site (owned). An incident in `alert_incidents` and a
site outage in `site_outages` were raised in the organization of their
time and stay with it when a device they name moves.

## References

* `agent/meshagent/meshagent.go`, `agent/runner/runner.go`,
  `agent/easypatch/easypatch.go`, `easypatch/agent/`,
  `easypatch/backend/API/Endpoints/AgentEndpoints.cs`,
  `server/internal/easypatch/links.go`, `web/src/nav/`.

### Amended 2026-11-26 (decided in review), what agents trust

`device_tls_trust` and `device_tls_state` (migration `00080`, ADR-0055 slice
5b1) hold what a device's agent trusts and the last answer it gave. That is a
fact of the computer, not of the organization, so a move leaves the rows alone:
they follow the device, like `device_hardening`. The disposition test lists
both as "follows the device".

### Amended 2026-11-26 (decided in review), agent settings

`agent_settings` (migration `90511`, ADR-0058 slice 1) holds the settings
operators set for agents at the platform, an organization, a site or one
device. The platform's, an organization's and a site's rows are owned by that
level, so a device move leaves them alone. A row set for one device names the
organization and site the device was in, and was written by someone with
rights there, so it ends with a move to another site, as `agent_log_verbose`
does: the move deletes it (`moveOne` in `server/internal/devices/move.go`).
The disposition test lists the table as "ends", the nearest of its
dispositions; what the code does, and `docs/operations/moving-devices.md`
says, is the move to another site. ADR-0058's "enrolled devices stay in their
site" is not true after this ADR, and the device rows do not rely on it.

### Amended 2026-11-26 (decided in review), Group Policy

`gpo_org_settings` (migration `00083`, ADR-0083 slice 1) belongs to the
organization, so the disposition test lists it as owned. `gpo_backups`
(`00082`) and `gpo_change_requests` (`00083`) are records of the organization
whose domain the controller served, so they stay with it when the controller
moves. A backup is restored, and a request is used, only within the
organization that holds it (both are looked up by the device's current
organization), so neither reaches the new one.
