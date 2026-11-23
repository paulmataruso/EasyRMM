# ADR-0069: Recovering agents from either side, live agent logs, and one device tree

* Status: Accepted (2026-11-23, after an independent review). Not
  implemented.
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

## References

* `agent/meshagent/meshagent.go`, `agent/runner/runner.go`,
  `agent/easypatch/easypatch.go`, `easypatch/agent/`,
  `easypatch/backend/API/Endpoints/AgentEndpoints.cs`,
  `server/internal/easypatch/links.go`, `web/src/nav/`.
