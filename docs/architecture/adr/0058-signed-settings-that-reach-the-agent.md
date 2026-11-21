# ADR-0058: Signed settings that reach the agent

* Status: Proposed (2026-11-21). Not implemented.
* Builds on: [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (signed
  requests and the heartbeat), [ADR-0017](0017-scripts-and-jobs.md) (the
  job key), the instructions already carried in the heartbeat answer
  ([ADR-0027](0027-agent-updates.md), [ADR-0031](0031-easypatch-agent-install.md),
  [ADR-0050](0050-removing-a-device.md)), and ADR-0057 (proposed: rotating
  the job key).
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
  unsigned in every answer as `heartbeatSeconds`. Since the fixes in the
  plan the agent keeps it between 10 seconds and 10 minutes, so that an
  answer changed on the way cannot silence it (`heartbeatInterval` in
  `agent/runner/runner.go`, CHANGELOG Unreleased).
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
  rollout then moves to its own build. The server decodes agent requests
  strictly (`decode` in `server/internal/httpapi/agentapi/agentapi.go`
  refuses unknown fields); the agent reads answers leniently (`callLimit`
  in `agent/client/client.go`). A new field in an answer is ignored by older
  agents; a new field in a request is refused by older servers.
* **Online is fixed at three minutes**, "three missed heartbeats"
  (`devices.AgentOnlineWindow` in `server/internal/devices/devices.go`,
  also written out in `server/internal/reports/reports.go` and used by
  `server/internal/monitoring/evaluate.go`).
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
  that sets it, and a title and one line for technicians. There are no
  free-form keys.
* **Every key in the catalogue reaches the agent.** Server-wide settings
  that agents never see (agent updates, audit forwarding, the patching
  engine) stay where they are.
* **The agent has its own catalogue**: the keys its version understands,
  with their schemas and a **built-in default that is always what the
  agent did before the key existed**. An agent that never received a
  document, or whose server has no settings, behaves exactly as its
  previous release did.

### Scopes, inheritance and enforcement
* **Four scopes**: platform, organization, site, device. Device groups and
  tags are not scopes; they are added if asked for.
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
* **Each key names one permission.** The first keys use a new permission,
  `device.configure` ("change devices' agent settings"), given to Site
  Administrators and so to Organization and Super Administrators
  (`siteAdminPerms`). Log collection's keys name their own (feature 3).
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

### Storage
* **`agent_settings`**: one row per key and scope target, with the key,
  the scope, the organization, site and device the scope needs (held by
  check constraints), the value (JSON, checked against the catalogue on
  every write), whether it is enforced, and who set it and when.
  Row-level security as for `scripts`: the platform's rows are read by
  everyone and written at platform scope only; an organization's, a
  site's and a device's rows by whoever holds that scope. Rows go with
  their organization, site or device, and a device's own rows follow it to
  another site.
* **A key a release retires** has its rows deleted by that release's
  migration, and leaves both catalogues: nothing is kept that nothing
  reads.
* **`agent_device_state`**: one row per enrolled device, with its
  organization and site for row-level security: the last document's
  version and hash, the version the agent last reported applying, its
  hash, when, and the problems it reported. Not on `devices`, whose `updated_at`
  moves only for real edits (`easyrmm_touch_device`).

### The document the agent receives
* **The device's effective settings, every key the server knows, as one
  signed document** in the heartbeat answer (`settings`): the payload
  `{"v": 1, "deviceId", "version", "issuedAt", "settings": {key: value}}`
  as base64 with an Ed25519 signature by the job key over
  `EASYRMM-SETTINGS-SIG-V1\n` + the payload, the same form as jobs,
  updates and uninstalls. The whole document is signed, so turning
  something off is as protected as turning it on.
* **Sent only when needed.** The heartbeat request reports the version the
  agent holds (below); the answer carries a document only when the
  server's is newer. A device whose settings have not changed receives
  nothing more than it does today.
* **Issued lazily.** At each heartbeat the server computes the device's
  effective settings (one indexed query over at most four rows per key)
  and their hash; when the hash differs from the one in
  `agent_device_state`, it issues a new version. A change for an
  organization writes nothing per device: each picks it up at its next
  heartbeat, or at once when it holds ADR-0059's live connection (a
  `checkin` wake, spread over a minute for changes at the platform or an
  organization).
* **At most 64 KiB**, which the catalogue's schemas keep to.
* **Rotation.** The document is signed with a key the agent accepts at
  that moment, as ADR-0057 (proposed) settles for every signed instruction.
  The agent verifies a document once, when it arrives, and keeps what it
  applied; a rotation therefore never makes its stored settings unreadable
  or sends it back to its defaults.

### Versions and rollback
* **A version only increases**, per device: the server issues
  `max(the time in milliseconds, the last version issued + 1, the version
  the agent reports + 1)`. The time keeps versions rising after a database
  restored from a backup; the agent's report covers a backup older than
  the agent's last document and a server clock set back. When the agent
  reports a version above the last one issued (a restore), the server
  issues a new version even if nothing changed, so the agent always ends
  on a document this server issued.
* **The agent refuses** a document with a lower version than the one it
  applied, one with the same version and other content (the same document
  again changes nothing), one for another device, one with an unknown
  top-level field (only the `settings` object is open) and one whose
  signature does not verify. It keeps its settings and reports the refusal.
* **No expiry.** A setting is state; the version, not the time, keeps an
  old one from coming back.

### How the agent applies and acknowledges
* **Verify, check, save, act.** The agent verifies the document, checks
  every key against its own catalogue, saves the result as applied in
  `settings.json` in its state directory, written like `agent.json` (mode
  0600 in a directory only root can enter on Linux; on Windows a folder
  only SYSTEM and Administrators can reach, `host.Protect`), then acts on each
  key that changed. A document it cannot save is not applied; it reports
  why, and the next answer carries the document again.
* **Restarts and outages keep the settings.** At start the agent applies
  its saved settings before its first heartbeat; a server it cannot reach
  changes nothing.
* **Acknowledgement in the next heartbeat**: `settings: {"version",
  "problems"}`, the version applied and, per key, `unknown`, `invalid` or
  `clamped` (below), or `refused` with the reason. After applying a new
  document the agent sends its next heartbeat within 10 seconds, so the
  console shows the result promptly.
* **The server records** the applied version and its hash, when, and the
  problems. The console compares the device's effective settings now with
  what its agent applied: *Applied*, or *Waiting for the device*, with its
  last check-in (a change not yet issued counts as waiting).

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
* **Older agents** ignore `settings` in the answer and keep the behaviour
  of their release.
* **The new request fields** (`settings` here; ADR-0059's `transport`) are
  sent only by an agent that holds a document, which only a server with
  settings issues. If a heartbeat carrying them is refused as
  `bad_request` (an older server after a rollback decodes strictly), the
  agent sends it again at once without them and leaves them out until
  another document arrives. Its heartbeats keep working, so that server's
  rollout can move it to its own build (ADR-0027, ADR-0052).

### The first keys

| Key | Values | Default | Set at | Enforced by | Permission |
|---|---|---|---|---|---|
| `agent.heartbeat_seconds` | 30 to 300 | 60 | platform, organization, site, device | platform, organization | `device.configure` |
| `agent.transport` | `automatic`, `live`, `poll` | ADR-0059 | platform, organization, site, device | platform, organization | `device.configure` |

The platform's values are set with `settings.manage`. `agent.transport`
arrives with ADR-0059's first slice, which decides its values and what
each does. Log collection's keys (`logs.configure`, `logs.sources`,
`logs.collect`) are decided in feature 3's ADR. The agent's built-in
defaults: for the heartbeat interval, the answer's `heartbeatSeconds` as
today; for the transport, no live connection.

### The heartbeat interval and online
* **`agent.heartbeat_seconds`**, 30 seconds to 5 minutes, 60 by default
  (today's). Its line in the console says that metrics arrive with each
  heartbeat (ADR-0018), so a longer interval means coarser monitoring and
  later offline notices.
* **Earlier agents follow it too**: the server puts the device's effective
  interval in the answer's existing `heartbeatSeconds`, which those agents
  already obey within their own 10-second to 10-minute bounds. An agent
  holding a document uses the document's value and ignores that unsigned
  field.
* **Online follows the interval**: still three missed heartbeats. The
  heartbeat records `devices.agent_online_until`, now plus three times
  the interval it answered with, a liveness column that
  `easyrmm_touch_device` ignores as it ignores `agent_last_seen_at`; the
  device list, its filter, reports and
  monitoring read it instead of the fixed three minutes. At 60 seconds
  nothing changes.

### API
* `GET /api/v1/agent-settings/keys`: the catalogue, for the console's
  editors.
* For each scope, `GET`, and `PUT` and `DELETE` on `/{key}`:
  * platform: `/api/v1/settings/agent-settings`;
  * organization: `/api/v1/organizations/{id}/agent-settings`;
  * site: `/api/v1/sites/{id}/agent-settings`;
  * device: `/api/v1/devices/{id}/agent-settings`.
* `GET` lists every key: the value set at this scope and whether it is
  enforced, the value inherited and where from (scope, ID, name), whether
  a higher scope enforces it, and the effective value. A device's adds the
  document's state: the current version, the applied version and when,
  the problems, and the agent's version.
* `PUT` takes `{"value": …, "enforced": false}`; `DELETE` goes back to
  inheriting. Errors: 400 `setting_invalid` with the schema's reason, 400
  `setting_scope` for a scope the key cannot be set at, 404 for an
  unknown key, 403, and 409 `setting_enforced`.
* Changing a key on many devices at once is done at their site or
  organization; a bulk action on the device list is added if asked for.

### Console
* **A device's Settings tab**, beside Overview, Hardware, Software and
  Patches (`web/src/pages/devices/DeviceDetailPage.tsx`), for devices with
  the EasyRMM agent: each key with its effective value and where it comes
  from (*Default*, *Inherited from site Main Office*, *Set for this
  device*, *Set by your MSP*), an editor and **Use inherited**; above them
  the document's state (*Applied 2 minutes ago*, *Waiting for the device:
  it is offline*, or the problems).
* **An organization's and a site's page**: **Agent settings**, the same
  editors, with **Enforce for everything below**.
* **Settings → Agent settings** (Super Administrators): the platform's
  values.
* Editors only for those who may write; everyone else reads.

### Audit
`agent_setting.set` and `agent_setting.cleared`, with the key, the scope and
its target, the old and new value and whether it is enforced. Agents
applying documents are not audited; the device's state shows it. A
refusal reported by an agent is logged by the server as a warning: it means
a bug or an answer changed on the way.

## Testing
* **Unit** (`internal/agentproto`, also on CI's Windows runner): signing
  and verifying; refused: another device, a lower version, the same
  version with other content, an unknown top-level field, a forged
  signature; unknown keys ignored, invalid values kept, integers clamped.
* **The agent** (on Linux and on CI's Windows runner): apply, save and
  act; a restart applies the saved settings before reaching the server;
  a server it cannot reach changes nothing; refusals keep the settings and
  are reported; a heartbeat refused as `bad_request` is sent again without
  the new fields.
* **Integration** (PostgreSQL): precedence over four scopes; enforcement at
  each scope, the 409, earlier values kept and back in effect; row-level
  security per scope and role; the permission at each scope; the audit
  rows; versions rising, including after the stored versions are set back
  as a restore would, from the agent's report; a change for an
  organization issued lazily to each device; `agent_online_until` at 60
  and 300 seconds, and the device list, reports and monitoring agreeing on
  online.
* **HTTP API**: every route and every error above.
* **Console**: unit tests of the tab and the editors.
* **Bundle end to end** (host networking only): an operator sets the
  site's heartbeat interval in the console; the real agent applies it, the
  device shows *Applied* and its heartbeats follow. A previous release's
  real agent (rc.4's Linux build, checked against its release's
  `SHA256SUMS`, with agent updates set to *Off* for the run) keeps
  heartbeating, ignores the document and follows the interval through
  `heartbeatSeconds`.

## Slices
Each merges, is verified on its own, and leaves nothing unused.

1. **Settings on the server**: the catalogue with
   `agent.heartbeat_seconds`, `agent_settings`, precedence and
   enforcement, `device.configure`, the audit and the API. No agent sees
   anything yet. Verified by unit, integration and HTTP API tests.
2. **Delivery**: the signed document, versions, `agent_device_state`, the
   agent's verify, save, apply and acknowledge, the interval through
   `heartbeatSeconds`, `agent_online_until`. Verified by unit, agent
   (Linux and Windows) and integration tests, and in the bundle with the
   current and the previous release's agents.
3. **Console**: the device's Settings tab, the organization's and site's
   editors, Settings → Agent settings. Verified by console tests and in the
   bundle by an operator's change reaching the agent.

They follow ADR-0057 (F0), whose rotation the signature relies on, and
come before ADR-0059's live connection, whose switch is `agent.transport`.
The plan put the first WebSocket slice before F1; this order gives the
agent something signed to decide by, and lets the owner turn the live
connection on for one device first.

## Consequences
* Operators set agent behaviour at the platform, an organization, a site
  or one device, see on each device what is in effect and why, and see
  whether the agent applied it.
* Settings are signed, versioned and kept by the agent: nothing on the way
  can change, replay or roll them back, and a restart or an outage does
  not lose them.
* Earlier agents keep working: they ignore the document, follow the
  interval through the unsigned field, and get every new key's behaviour
  only once updated.
* Online follows each device's interval: a device on 5 minutes counts as
  offline after 15.
* Adding a key is a catalogue entry in the server and in the agent, with
  its schema, default and permission, and a test of its effect; a key
  without an effect in the agent is not added.
