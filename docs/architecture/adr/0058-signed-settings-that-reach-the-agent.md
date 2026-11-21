# ADR-0058: Signed settings that reach the agent

* Status: Proposed (2026-11-21). Not implemented.
* Revised 2026-11-21 after an independent review: what a longer interval
  does to monitoring and to online, a server rolled back, protocol levels
  in place of a fallback, what ADR-0057 must provide, technicians and the
  transport, storage, and tests.
* Refines: [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (a
  heartbeat every 60 seconds, l. 46–47; online within three minutes,
  l. 76) and [ADR-0019](0019-monitoring-and-alerts.md) (measurements once a
  minute, l. 6; half the expected measurements, l. 26–28): both follow
  the device's own interval. Each gains a *Refined by ADR-0058* line when
  slice 1 merges.
* Builds on: [ADR-0009](0009-agent-protocol.md) (amended, PR #52: protocol
  levels), ADR-0015 (signed requests and the heartbeat),
  [ADR-0017](0017-scripts-and-jobs.md) (the job key), the instructions
  already carried in the heartbeat answer
  ([ADR-0027](0027-agent-updates.md), [ADR-0031](0031-easypatch-agent-install.md),
  [ADR-0050](0050-removing-a-device.md)), [ADR-0052](0052-the-host-updater.md)
  (rollbacks) and ADR-0057 (proposed: rotating the job key; what this ADR
  needs from it is under *What this needs from ADR-0057*).
* Part of [the feature plan](../feature-plan.md): F1. Its first users are
  [ADR-0059](0059-the-agents-websocket-channel.md) (the transport, feature
  8) and log collection (feature 3, its own ADR).

## Context
Operators can set nothing that reaches an agent. What exists:

* **Instructions, not settings.** The heartbeat answer carries one-off
  instructions: an agent update (ADR-0027), the EasyPatch agent's install
  (ADR-0031) and an uninstall (ADR-0050). Each is signed with the job key
  under a context of its own, names the device, and expires within minutes
  (`internal/agentproto`: `update.go`, `easypatch.go`, `uninstall.go`). The
  agent refuses one for another device, an expired one, one with unknown
  fields or a bad signature.
* **The heartbeat interval is a constant**: 60 seconds
  (`agents.HeartbeatInterval`, `server/internal/agents/service.go`), sent
  unsigned in every answer as `heartbeatSeconds`. **Released agents obey
  it unbounded**: rc.4 waits exactly what the answer says, and a minute
  only for zero or less (`beat` in `agent/runner/runner.go` at
  `easyrmm-v1.0.0-rc.4`). The bound of 10 seconds to 10 minutes
  (`heartbeatInterval`, `agentproto.MinHeartbeatSeconds` and
  `MaxHeartbeatSeconds`) is one of the plan's fixes, not released yet
  (CHANGELOG, Unreleased).
* **Monitoring expects a measurement a minute.** Each heartbeat stores one
  metric sample (`RecordMetrics` in `server/internal/inventory/service.go`).
  A processor, memory or disk policy opens an alert only with at least
  `max(1, (minutes+1)/2)` samples in its window (`decide` in
  `server/internal/monitoring/evaluate.go`), as ADR-0019 says. With the
  default policies (15 minutes, so 8 samples; disk 5 minutes, so 3), no
  metric alert opens once heartbeats are more than about 100 seconds
  apart.
* **Online is fixed at three minutes**, "three missed heartbeats"
  (`devices.AgentOnlineWindow` and its SQL form `agentOnline` in
  `server/internal/devices/devices.go`, written out again as `onlineSQL` in
  `server/internal/reports/reports.go`, and used by `loadFacts` in
  `server/internal/monitoring/evaluate.go`). Offline policies may be as
  short as 3 minutes (`MinOfflineMinutes`,
  `server/internal/monitoring/policies.go`).
* **`easyrmm_touch_device` lists by name** the columns a heartbeat may
  change without moving `updated_at`
  (`server/migrations/00003_agent_enrollment.sql`); a new liveness column
  needs the function redefined.
* **The agent keeps no settings.** `agent.json` holds its enrollment: the
  server, the device ID, how MeshAgent runs and the job key pinned on first
  sight (`agent/state/state.go`).
* **Agents pin no TLS key.** They trust the system's roots or a CA file
  (`agent/client/client.go`), so a TLS-terminating proxy or an inspecting
  firewall at a customer can read and change answers. That is why every
  instruction is signed, and why MeshAgent's downloads were signed in the
  fixes the reviews found (ADR-0015, amended).
* **Two versions meet.** Agents update a few at a time (ADR-0027), and a
  server rolled back (ADR-0052) meets agents newer than itself, which its
  rollout then moves to its own build. The agent reads answers leniently
  (`callLimit` in `agent/client/client.go`). From protocol level 2
  (ADR-0009, amended, PR #52) the server ignores request fields it does
  not know and states its level in every heartbeat answer (`protocol`);
  servers of level 1 (rc.4 and earlier) refuse unknown fields with 400.
  So an agent sends a field added after level 2 only while its last
  heartbeat answer was of level 2 or higher, and a new signed instruction
  goes only to builds that reported understanding it.
* **Enrolled devices stay in their site.** Only devices discovered from
  MeshCentral, without the EasyRMM agent, follow their node to another
  site or organization (the conflict update in
  `server/internal/remote/service.go`, limited to
  `devices.agent_public_key IS NULL`); nothing moves an enrolled one.
* **No permission covers it.** The roles' permissions are in
  `server/internal/rbac/rbac.go`; `device.edit` (technicians) renames and
  tags devices, `settings.manage` is the platform's.

A setting differs from an instruction in four ways. It is **state**: it
holds until changed, so it cannot expire. An **older one must never replace
a newer one**: turning log collection off is a way to hide, so a replayed
document is an attack. It must **survive** the agent's restarts and a
server it cannot reach. And it is **set at several levels**, an MSP's
default, a customer's, a site's, one computer's.

## Decision

### What a setting is
* A **key** from a fixed catalogue compiled into the server, named
  `area.name` (`agent.transport`). Each entry has a type and its schema
  (an enumeration, an integer with bounds, a boolean; structured values
  with a JSON schema, for log collection's keys), a default, the scopes it
  may be set at, whether a higher scope may enforce it, the permission
  that sets it at each scope, and a title and one line for technicians.
  There are no free-form keys.
* **Every key in the catalogue reaches the agent.** Server-wide settings
  that agents never see (agent updates, audit forwarding, the patching
  engine, the platform's limits below) stay where they are.
* **The agent has its own catalogue**: the keys its version understands,
  with their schemas and a **built-in default that is always what the
  agent did before the key existed**. An agent that never received a
  document, or whose server has no settings, behaves exactly as its
  previous release did. **A key the agent knows that a document omits**
  (a server rolled back to a release without it, or one that retired it)
  takes the built-in default, never a value from an earlier document.

### Scopes, inheritance and enforcement
* **Four scopes**: platform, organization, site, device. Device groups and
  tags are not scopes; they are added if asked for.
* **The device scope is for enrolled devices only**: a device without the
  EasyRMM agent has nothing to receive a setting. An enrolled device's
  organization and site never change, so its rows never cross a tenant.
* **The nearest wins**: device, then site, then organization, then
  platform, then the catalogue's default.
* **Enforcement.** A value set with *Enforce* wins over everything below
  it; if several scopes enforce a key, the highest wins. A key's catalogue
  entry says whether it may be enforced; the platform, an organization and
  a site can enforce, a device has nothing below it. Below an enforced
  value nothing can be set (409 `setting_enforced`). Values set there
  earlier are kept, shown as *not in effect, enforced by …*, and apply
  again when the enforcement is lifted. The console says *Set by your MSP*
  for the platform's enforced values and *Set for* the organization or
  site for theirs.

### Who sets them
* **Each key names its permission at each scope.** The first keys use a
  new permission, `device.configure` ("change devices' agent settings"),
  given to Site Administrators and so to Organization and Super
  Administrators (`siteAdminPerms`). Log collection's keys name their own
  (feature 3).
* **One exception, from the owner's words** ("the user can choose in the
  device settings what they want to use"): `agent.transport` on one device
  needs `device.edit`, which technicians hold (`technicianPerms`). At a
  site or an organization it needs `device.configure`, like every other
  key, and every other key keeps its permission at every scope. A value
  enforced above the device still wins, so an organization or the
  platform can take the choice away.
* **Checked at the scope written**, as for scripts (ADR-0017): a site or
  one of its devices needs the permission at that site; an organization
  needs it granted organization-wide; the platform needs
  `settings.manage` (Super Administrators). Enforcing needs the same at
  the enforcing scope.
* **Reading** needs only to see the device, site or organization: its
  effective settings and where each comes from, the platform's values
  included.
* A catalogue entry may require step-up authentication; the first keys do
  not.

### Limits the platform sets
Site Administrators can reach thousands of devices. On Settings → Agent
settings, with `settings.manage`, the platform sets server settings that
never reach an agent:

* **The shortest heartbeat interval** organizations, sites and devices
  may set: 30 seconds by default, at most 300. A value set earlier below a
  raised minimum takes effect as the minimum and is shown as *Raised to
  the platform's minimum*.
* **The most live connections one organization may hold**
  ([ADR-0059](0059-the-agents-websocket-channel.md)): no limit but the
  server's own maximum by default. It arrives with ADR-0059's first
  slice, which uses it.

And for everyone:

* **Writes are rate-limited per scope**: at most 30 a minute on one
  organization, site or device, then 429 `rate_limited`, so a script
  cannot keep a fleet re-reading its settings.
* **Wakes are spread** (ADR-0059): a change that reaches more than 100
  devices, at any scope, a large site's included, wakes them at most 100
  a second per server and over at least a minute; a smaller change wakes
  at once.

### Storage
* **`agent_settings`**: one row per key and scope target, with the key,
  the scope, the organization, site and device the scope needs (held by
  check constraints), the value (JSON, checked against the catalogue on
  every write), whether it is enforced, and who set it and when.
  Row-level security as for `scripts`: the platform's rows are read by
  everyone and written at platform scope only; an organization's, a
  site's and a device's rows by whoever holds that scope. Rows go with
  their organization, site or device (foreign keys that cascade). A
  trigger refuses a device row for a device without an agent key.
* **A key a release retires** has its rows deleted by that release's
  migration, and leaves both catalogues: nothing is kept that nothing
  reads.
* **`agent_device_state`**: one row per enrolled device, deleted with it,
  with its organization and site for row-level security: the capabilities
  its agent last reported; the last document's version and hash and when
  it was issued; the version the agent last reported applying, its hash,
  when, and the problems it reported; and how many heartbeats it has sent
  since the current version was issued without reporting it applied. Not
  on `devices`, whose `updated_at` moves only for real edits.
* **Two liveness columns on `devices`**: `agent_heartbeat_seconds`, the
  interval the agent uses (below), and `agent_online_until`. The migration
  redefines `easyrmm_touch_device` to ignore both, as it ignores
  `agent_last_seen_at`; backfills enrolled devices with 60 seconds and
  `agent_last_seen_at` plus three minutes; and indexes
  `agent_online_until` for enrolled devices, as `devices_agent_seen_idx`
  does `agent_last_seen_at`.
* **`docs/architecture/database.md`** gains an entry for each table and
  column, and for the function's new form, in the slice that adds them.

### The document the agent receives
* **The device's effective settings, every key the server knows, as one
  signed document** in the heartbeat answer (`settings`): the payload
  `{"v": 1, "deviceId", "version", "issuedAt", "settings": {key: value}}`
  as base64 with an Ed25519 signature by the job key over
  `EASYRMM-SETTINGS-SIG-V1\n` + the payload, the same form as jobs,
  updates and uninstalls. The whole document is signed, so turning
  something off is as protected as turning it on.
* **Only to agents that take it.** The agent states its capabilities in
  its signed heartbeat (`capabilities`, `settings.v1` among them). The
  server issues documents only to a device whose last report lists
  `settings.v1`, as ADR-0009 (amended, PR #52) requires of a new signed
  instruction. Older agents report nothing and get nothing: no 64 KiB in
  every answer for ever. The console says on their device *This agent's
  version does not take settings: update the agent*, and Settings → Agent
  settings counts them and links to them.
* **Sent only when needed.** The heartbeat reports the version the agent
  holds (`settings.version`, 0 for none); the answer carries a document
  only when the server's is newer. A device whose settings have not
  changed receives nothing more than it does today.
* **Issued lazily, under a lock.** At each heartbeat from a device that
  takes documents, the server computes the device's effective settings
  (one indexed query over at most four rows per key) and their hash. It
  reads the device's `agent_device_state` row `FOR UPDATE`, and when the
  hash differs it issues a new version and records it in the same
  transaction, so two heartbeats at once (a wake's and the regular one)
  cannot issue one version with two contents. A change for an
  organization writes nothing per device: each picks it up at its next
  heartbeat, or at once when it holds ADR-0059's live connection (a
  `checkin` wake, spread as above).
* **Never to a device being removed.** An answer that carries an
  uninstall carries nothing else (ADR-0050); a device's state goes with
  it when it is retired.
* **At most 64 KiB**, which the catalogue's schemas keep to.

### Versions and rollback
* **Versions are integers from 1 to 2^53 − 1**, which JSON carries
  exactly.
* **A version only increases**, per device: the server issues
  `max(the time in milliseconds, the last version issued + 1, the version
  the agent reports + 1)`. The time keeps versions rising after a database
  restored from a backup; the agent's report covers a backup older than
  the agent's last document and a server clock set back. When the agent
  reports a version above the last one issued (a restore), the server
  issues a new version even if nothing changed, so the agent always ends
  on a document this server issued. A reported version above 2^53 − 1
  cannot come from an agent that follows this ADR, which refuses such
  documents: the server does not use it, issues from its own sequence,
  and shows the report on the device as a problem.
* **The agent refuses** a document with a version outside the range or
  lower than the one it applied, one with the same version and other
  content (the same document again changes nothing), one for another
  device, one with an unknown top-level field (only the `settings` object
  is open) and one whose signature does not verify. It keeps its settings
  and reports the refusal.
* **No expiry.** A setting is state; the version, not the time, keeps an
  old one from coming back.

### How the agent applies and acknowledges
* **Verify, check, save, act.** The agent verifies the document, checks
  every key against its own catalogue, saves the result as applied in
  `settings.json` in its state directory, written like `agent.json` (mode
  0600 in a directory only root can enter on Linux; on Windows a folder
  only SYSTEM and Administrators can reach, `host.Protect`), then acts on
  each key that changed. A document it cannot save is not applied; it
  reports why, and the next answer carries the document again.
* **Bound to the device.** `settings.json` holds the document as received,
  device ID included. At start the agent applies it only if that ID is the
  one in `agent.json`; an agent enrolled again as another device starts
  from its built-in defaults.
* **Restarts and outages keep the settings.** At start the agent applies
  its saved settings before its first heartbeat; a server it cannot reach
  changes nothing.
* **Acknowledgement in the next heartbeat**: `settings: {"version",
  "problems"}`, the version applied and, per key, `unknown`, `invalid` or
  `clamped` (below), or `refused` with the reason; with `capabilities` and
  `heartbeatSeconds`, the interval it uses (below). After applying a new
  document the agent sends its next heartbeat within 10 seconds, so the
  console shows the result promptly.
* **The server records** the applied version and its hash, when, and the
  problems. The console compares the device's effective settings now with
  what its agent applied: *Applied*, or *Waiting for the device*, with its
  last check-in (a change not yet issued counts as waiting).
* **Not applied.** A device whose agent has sent three heartbeats since
  the current version was issued without reporting it applied is flagged
  *Not applied*: on its Settings tab, with the version and the agent's
  report; by a filter in Devices; and in a count on Settings → Agent
  settings.

### Unknown and invalid
* **An unknown key** (a newer server's) is ignored and reported as
  `unknown`; the console says *Not supported by this agent's version;
  update the agent*.
* **An invalid value** for a known key (the wrong type, a value of an
  enumeration the agent does not know) is not applied: the agent keeps
  the value it had, from its previous document or its built-in default,
  and reports `invalid`. **An integer out of bounds** is brought within
  the agent's own bounds and reported as `clamped`. The rest of the
  document applies.
* The server checks every write against its catalogue, so an invalid value
  reaches an agent only across versions: a value a newer server allows.

### Mixed versions
Every new field follows ADR-0009 (amended, PR #52); there is no fallback
of this ADR's own, and no 400 is read as "not supported".

* **Older agents** report no `settings.v1` capability, so they get no
  document; they keep the behaviour of their release and follow the
  interval through `heartbeatSeconds`.
* **The new request fields** (`capabilities`, `settings`,
  `heartbeatSeconds`; ADR-0059's `transport`) were added after level 2, so
  the agent sends them only while its last heartbeat answer was of level
  2 or higher, and none before its first answer in a process. A server of
  level 1 never sees them; one of level 2 without settings ignores them.
* **A server rolled back to a release without delivery** (ADR-0052)
  issues no document, counts online over its fixed three minutes and
  answers `heartbeatSeconds` as it always did. The agent keeps the
  document it holds; so that a 5-minute interval in it does not make that
  server count the device offline two minutes in every five, **the agent
  heartbeats at the shorter of its document's interval and the answer's
  `heartbeatSeconds`, never below the catalogue's minimum, 30 seconds**. A
  current server answers the device's effective interval, so the two
  agree; an answer changed on the way can only make the agent check in
  more often, at most every 30 seconds.

### What this needs from ADR-0057
Settings are the first state signed with the job key that an agent keeps.
ADR-0057 (proposed, in its own review) must provide, and slice 2 does not
start until it does:

* agents report the key IDs (ADR-0057's generations) they accept, in their
  signed heartbeat;
* the server signs each device's documents, and ADR-0059's messages, with
  a key that device reported;
* the agent applies a hand-over before anything else in an answer, so a
  document in the same answer, signed with the new key, verifies;
* ADR-0059's channel opens only after a successful heartbeat in the
  agent's process;
* at a cut-over the server sends ADR-0059's `closing` (`refresh`) to live
  connections, spread over its window;
* messages that fail verification during a declared transition do not
  count as *Automatic*'s failures (ADR-0059).

The agent verifies a document once, when it arrives, and keeps what it
applied; a rotation therefore never makes its stored settings unreadable
or sends it back to its defaults.

### The first keys

| Key | Values | Default | Set at | Enforced by | Permission |
|---|---|---|---|---|---|
| `agent.heartbeat_seconds` | 30 to 300 (the platform may raise the minimum) | 60 | platform, organization, site, device | platform, organization | `device.configure` |
| `agent.transport` | `automatic`, `live`, `poll` | ADR-0059 | platform, organization, site, device | platform, organization | `device.edit` on a device; `device.configure` at a site or organization |

The platform's values are set with `settings.manage`. `agent.transport`
arrives with ADR-0059's first slice, which decides its values and what
each does. Log collection's keys (`logs.configure`, `logs.sources`,
`logs.collect`) are decided in feature 3's ADR. The agent's built-in
defaults: for the heartbeat interval, the answer's `heartbeatSeconds` as
today; for the transport, no live connection.

### The heartbeat interval, monitoring and online
* **`agent.heartbeat_seconds`**, 30 seconds to 5 minutes, 60 by default
  (today's).
* **Every agent follows it, from slice 1**: the server puts the device's
  effective interval in the answer's existing `heartbeatSeconds`. rc.4 and
  earlier obey it unbounded and later agents within their 10 seconds to 10
  minutes; the server only ever answers 30 to 300. An agent holding a
  document uses the shorter of the two (above).
* **The server keeps the interval each agent uses.** The agent reports it
  in its signed heartbeat (`heartbeatSeconds`); for an agent that reports
  none, the server keeps the interval it answered. An agent that refused a
  document, or could not save it, reports the interval it kept, so the
  server never assumes an interval the agent does not use. Kept in
  `devices.agent_heartbeat_seconds`.
* **Online is three missed heartbeats of that interval.** Each heartbeat
  sets `agent_online_until` to now plus three times the kept interval. The
  device list, its filter, reports and monitoring read it
  (`agent_online_until > now()`, or MeshAgent connected, as today) in
  place of their three copies of the fixed window. At 60 seconds nothing
  changes.
* **Metric policies expect the device's own measurements**: a window of N
  minutes expects `N × 60 / interval` of them, at least one, and opens an
  alert with at least half of them (rounded up); a window, and the
  5-minute one an alert resolves over, is never shorter than one
  interval, so a 5-minute disk policy on a 5-minute device judges its
  latest measurement. At 60 seconds this is today's rule. A change of
  interval can delay an alert by one window, never open one early.
* **Its effect is said where it is set.** The key's line in the console:
  *Measurements arrive with each heartbeat. At 5 minutes, a 15-minute
  processor alert judges 3 measurements instead of 15, and a device counts
  as offline only after 15 minutes, so a shorter Offline policy waits that
  long.* An alert policy's page lists the devices it covers whose interval
  makes it wait longer than its minutes (an Offline policy under three of
  their intervals), with how long; saving such a policy says so. Nothing
  about the longer wait is silent.

### API
* `GET /api/v1/agent-settings/keys`: the catalogue, for the console's
  editors, with the permission each key needs at each scope.
* For each scope, `GET`, and `PUT` and `DELETE` on `/{key}`:
  * platform: `/api/v1/settings/agent-settings`;
  * organization: `/api/v1/organizations/{id}/agent-settings`;
  * site: `/api/v1/sites/{id}/agent-settings`;
  * device: `/api/v1/devices/{id}/agent-settings`.
* `GET` and `PUT /api/v1/settings/agent-settings/limits`: the platform's
  limits (`settings.manage` to write).
* `GET` lists every key: the value set at this scope and whether it is
  enforced, the value inherited and where from (scope, ID, name), whether
  a higher scope enforces it, the effective value, and whether the caller
  may write it here. A device's adds the document's state: the current
  version, the applied version and when, the problems, *Not applied*, the
  agent's version and capabilities, and the interval it uses.
* `PUT` takes `{"value": …, "enforced": false}`; `DELETE` goes back to
  inheriting. Errors: 400 `setting_invalid` with the schema's reason (the
  platform's minimum included), 400 `setting_scope` for a scope the key
  cannot be set at or a device without the EasyRMM agent, 404 for an
  unknown key, 403, 409 `setting_enforced`, and 429 `rate_limited`.
* Changing a key on many devices at once is done at their site or
  organization; a bulk action on the device list is added if asked for.

### Console
* **A device's Settings tab**, beside Overview, Hardware, Software and
  Patches (`web/src/pages/devices/DeviceDetailPage.tsx`), for devices with
  the EasyRMM agent: each key with its effective value and where it comes
  from (*Default*, *Inherited from site Main Office*, *Set for this
  device*, *Set by your MSP*), an editor and **Use inherited**; above them
  the document's state (*Applied 2 minutes ago*, *Waiting for the device:
  it is offline*, *Not applied*, the problems, or *This agent's version
  does not take settings: update the agent*, with the update action where
  the caller may, ADR-0027).
* **An organization's and a site's page**: **Agent settings**, the same
  editors, with **Enforce for everything below**.
* **Settings → Agent settings** (Super Administrators): the platform's
  values and limits; the devices whose agent does not take settings and
  those *Not applied*, linking to them.
* **Devices**: a filter for *Settings not applied*.
* **Alert policies**: the devices that wait longer, as above.
* Editors only for those who may write each key at that scope (a
  technician sees one: the transport on a device); everyone else reads.

### Audit
`agent_setting.set` and `agent_setting.cleared`, with the key, the scope and
its target, the old and new value and whether it is enforced;
`agent_setting.limits_set` for the platform's limits. Agents applying
documents are not audited; the device's state shows it. A refusal reported
by an agent is logged by the server as a warning: it means a bug or an
answer changed on the way.

## Testing
* **Unit** (`internal/agentproto`, also on CI's Windows runner): signing
  and verifying; refused: another device, a lower version, a version
  outside 1 to 2^53 − 1, the same version with other content, an unknown
  top-level field, a forged signature; unknown keys ignored, invalid
  values kept, integers clamped, a known key omitted taking its default.
* **The agent** (on Linux, and its tests on CI's Windows runner): apply,
  save and act; a restart applies the saved settings before reaching the
  server; settings saved for another device ID are not applied; a server
  it cannot reach changes nothing; refusals keep the settings and are
  reported; the new fields only after an answer of level 2 or higher, and
  none to a server that states no level; the interval is the shorter of
  the document's and the answer's, never below 30 seconds.
* **Windows end to end** through the Windows harness the plan builds (the
  server built for Windows with the runner's PostgreSQL, a Windows agent
  enrolling; "Test harnesses to build"): a document applied, saved and
  kept across a service restart. Until the harness exists, the Windows
  paths are marked unverified in IMPLEMENTATION_STATUS; the agent's own
  tests on the Windows runner do not count as end to end.
* **Integration** (PostgreSQL): precedence over four scopes; enforcement
  at each scope, the 409, earlier values kept and back in effect;
  row-level security per scope and role; the permission at each scope
  (with ADR-0059's first slice, a technician setting the transport on a
  device but not at its site, and no other key anywhere); device rows refused for a device without the
  agent; the platform's minimum and earlier values raised to it; writes
  rate-limited per scope; the audit rows; versions rising, including after
  the stored versions are set back as a restore would, from the agent's
  report; a report above 2^53 − 1 ignored; two heartbeats at once issuing
  one version; documents only to devices that reported `settings.v1`; a
  change for an organization issued lazily to each device; *Not applied*
  after three heartbeats; `agent_heartbeat_seconds` and
  `agent_online_until` at 60 and 300 seconds, from the agent's report and
  for agents that report none; `updated_at` unmoved by both columns; the
  device list, its filter, reports and monitoring agreeing on online;
  **every policy kind at 300 seconds**: Offline (no alert before three
  intervals, one after), and processor, memory and disk opening on the
  measurements expected at that interval and resolving.
* **HTTP API**: every route and every error above.
* **Console**: unit tests of the tab, the editors, the filter and the
  policy page's list.
* **Bundle end to end** (host networking only):
  * an operator sets the site's heartbeat interval in the console; the
    real agent applies it, the device shows *Applied* and its heartbeats
    follow;
  * a previous release's real agent (rc.4's Linux build, checked against
    its release's `SHA256SUMS`, with agent updates set to *Off* for the
    run) keeps heartbeating, gets no document and follows the interval
    through `heartbeatSeconds`;
  * **the previous release's server**: the current agent holding a
    300-second document, then the deployment run on the previous
    release's images as an ADR-0052 rollback would (agent updates *Off*):
    the agent checks in every 60 seconds from that server's answer, the
    device stays online throughout, and a 3-minute Offline policy raises
    nothing; and against rc.4's server (level 1), which it sends no field
    added after level 2.
* **Coverage floors** in `scripts/ci/check-coverage.sh` for the new
  packages, the server's settings package and `agent/settings`, at their
  measured coverage and no lower than their neighbours'
  (`server/internal/agents` 88, `agent/runner` 90).

## Slices
Each merges, is verified on its own, and leaves nothing unused.

1. **Settings on the server, and the interval for every agent**: the
   catalogue with `agent.heartbeat_seconds`, `agent_settings`, precedence
   and enforcement, `device.configure`, the platform's minimum interval,
   the rate limit, the audit and the API; and the interval's server side:
   the effective interval in `heartbeatSeconds`, `agent_heartbeat_seconds`
   and `agent_online_until` (from the answered interval, since no agent
   reports one yet), the function redefined, the backfill and the index,
   everything that reads online and expects measurements, and the alert
   policy page's list of devices that wait longer, so the effect is never
   silent. Every agent, rc.4's included, follows the key from this slice.
   ADR-0015 and ADR-0019 gain their *Refined by* lines. Verified by unit,
   integration (the 300-second policies among them), HTTP API and console
   tests, and in the bundle by rc.4's agent following a site's interval
   set through the API. It signs nothing, so it needs nothing from
   ADR-0057.
2. **Delivery**: the signed document, versions, capabilities,
   `agent_device_state`, the agent's verify, save, apply and acknowledge,
   the interval it reports and the shorter of the two, *Not applied*.
   Verified by unit, agent and integration tests, in the bundle with the
   current and the previous release's agents and against the previous
   release's server, and on Windows as above.
3. **Console**: the device's Settings tab, the organization's and site's
   editors, Settings → Agent settings and the filter.
   Verified by console tests and in the bundle by an operator's change
   reaching the agent.

Slices 2 and 3 follow ADR-0057 (F0), whose rotation the signature relies
on, and all three come before ADR-0059's live connection, whose switch is
`agent.transport`. The plan put the first WebSocket slice before F1; this
order gives the agent something signed to decide by, and lets the owner
turn the live connection on for one device first.

## Consequences
* Operators set agent behaviour at the platform, an organization, a site
  or one device, see on each device what is in effect and why, and see
  whether the agent applied it. Technicians choose a device's transport.
* Settings are signed, versioned and kept by the agent: nothing on the way
  can change, replay or roll them back, and a restart or an outage does
  not lose them.
* Earlier agents keep working: they get no document, follow the interval
  through the unsigned field, and get every new key's behaviour only once
  updated; the console says which they are.
* Online and monitoring follow each device's interval: a device on 5
  minutes counts as offline after 15, its metric policies judge fewer
  measurements, and the console says so where the interval and the
  policies are set.
* A server rolled back keeps every agent online at its own interval.
* Adding a key is a catalogue entry in the server and in the agent, with
  its schema, default and permission at each scope, and a test of its
  effect; a key without an effect in the agent is not added.
