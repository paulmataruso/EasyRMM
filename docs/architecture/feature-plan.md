# Plan: the next eight features

* Status: Draft 3 (2026-11-21). Draft 1 had three independent reviews
  (security and architecture; the MSP operator's view; testing,
  feasibility and order), ADR-0051 one; Draft 2 was checked against all
  four by a fourth reviewer, who found 37 of 60 findings fully answered
  and some new problems; this draft answers the rest.
* Scope: the work the owner asked for on 2026-11-20 and 2026-11-21:
  1. Operators sign the Windows agent (ADR-0049).
  2. Hardening Linux computers (ADR-0051).
  3. Collecting logs from Windows and Linux.
  4. Upgrading EasyRMM from the console.
  5. Let's Encrypt in one step.
  6. MSI, DEB and RPM packages for the agent.
  7. Email and webhook notifications for device alerts.
  8. The agent's WebSocket channel, with a per-device choice of transport.

This page says what each feature does, what it builds on, the decisions
its ADR has to make, how it is tested, and the order of the work. Each
feature still gets its own ADR, reviewed before it is built, its own pull
requests and its own changelog entries.

## What the reviews changed

* **Trust.** The host updater no longer trusts anything the server
  writes beyond a version number, and never writes where the server can.
  Agents do not pin TLS keys, so everything new that reaches an agent
  (settings, a new address, WebSocket messages) is signed, not just sent
  over TLS. Moving agents to a new name became an ADR of its own. The job
  key can be rotated before more depends on it.
* **Destinations.** Webhooks and log forwarding owned by organizations go
  through one strict address policy (no loopback, no cloud metadata, a
  private address only when a super administrator approves that
  destination).
* **What the owner asked for.** Logging is configured by default, as asked.
  Let's Encrypt is designed around the case that needs it (an install on
  an IP address getting a name). One list of notification channels, not
  two. The transport choice is worded for technicians.
* **Order.** The updater is split: the part that keeps the test instance
  current comes early; the console and release checks come after
  notifications. Packages come before log collection.
* **Tests that could not have run** were redesigned: the webhook receiver,
  the upgrade and rollback test, hardening's machines, DNS-01, and the
  10,000-agent load.
* **Wrong statements** in Draft 1 were corrected: agents pin no TLS key;
  the install scripts pass the token in `EASYRMM_TOKEN`; a full backup is
  more than two databases; the engine's webhook policy blocks its own
  *networks*; an MSI's signature is not a PE signature; Let's Encrypt
  stopped OCSP in 2025; `Evaluate` returns the alert counts.

## How every feature is done

1. **ADR** with the decisions below, then an independent review: a
   reviewer who did not write it reads the code it touches and the ADR,
   and lists what is wrong or missing. The ADR is revised until the review
   has nothing material left.
2. **Build** in slices that each merge and are verified on their own, with
   tests at every level the slice touches: unit, PostgreSQL integration,
   HTTP API, console, contract (when the patching engine is involved),
   end to end through the release bundle when agents are involved, and on
   CI's Windows runner or in virtual machines where the feature is about
   Windows or the host. No stand-ins for what can be run for real.
   Coverage floors for new packages.
3. **Gates** before the pull request: formatting, both linters (Linux and
   Windows), vet, `go mod tidy -diff`, integration with the race detector
   and coverage floors, the contract test, the console's checks and
   build, the design detector, Markdown links, gitleaks, and from the
   first shell script on, `shellcheck`.
4. **CI green, merge, then the test instance.** Until the edge channel
   exists, a release candidate is cut and the owner's instance is upgraded
   in place, backup first. Afterwards it follows `main` through the
   updater.
5. **Docs**: the guide, IMPLEMENTATION_STATUS (what was verified and what
   was not), ROADMAP, CHANGELOG, database.md for every migration.

## Fixes the reviews found in what exists

Small, and first, because they are holes in shipped code. **Done** (#42,
and this plan's own pull request for ADR-0019):

* **MeshAgent arrived unsigned.** The agent fetched MeshAgent's binary and
  its `.msh` settings over TLS only, and agents trust the system's roots.
  The server now signs each download with the job key, over the device,
  the request and its single-use nonce, and the agent installs neither
  unless the signature verifies (ADR-0015, amended).
* **`heartbeatSeconds` had no bound** on the agent; it is clamped to 10
  seconds to 10 minutes.
* ADR-0019's reference to "ADR-0020" for notifications; overview.md's
  description of how MeshCentral reads the certificate;
  `EASYRMM_ACME_DIRECTORY` missing from `.env.example`.

## Foundations

### F0. Rotating the job key
Every signed instruction (jobs, updates, uninstalls, and since the fixes
above MeshAgent's downloads) rests on one job key that cannot be rotated
(ADR-0017, Consequences). Before the new kinds of instruction this plan
adds (settings, a new address) depend on it: a new key is signed by the current one and announced in the
heartbeat; agents that verify the hand-over accept both for a transition
period, then only the new one. A rollback of EasyRMM (F3) is refused
across a rotation's cut-over. Tested with real agents through a rotation
and with an agent that was offline across it.

### F1. Signed settings that reach the agent
Features 3 and 8 need settings an operator sets for the platform, an
organization, a site or one device.

* **Scopes**: platform, organization, site, device, with the nearest scope
  winning, unless a higher scope **enforces** the value ("set by your
  MSP"). Device groups later, if asked for.
* **Keys** are a fixed list, each with a schema, a default, the scopes it
  may be set at and the permission that sets it (`agent.transport`: Site
  Administrators and above; log collection's keys: see feature 3).
* **Delivery**: the heartbeat answer carries the device's effective
  settings as one document signed with the job key under its own context,
  with the device's ID, a hash and a version that only increases (the
  time of the change in milliseconds, at least one more than the last, so
  that a database restored from a backup still issues higher versions).
  The agent refuses a document for another device or with a lower version,
  and clamps every value to its schema. Turning something *off* is as
  sensitive as turning it on (collection off is a way to hide), so the
  whole document is signed, not just some keys.
* **Console**: on a device, each setting's effective value and where it
  comes from; editors at each scope.
* **Tests**: precedence and enforcement (integration), a forged and a
  replayed document refused (agent), an agent from the previous release
  ignoring the new field (bundle test with the previous release's real
  agent).

### F2. One notification sender
Decided in [ADR-0053](adr/0053-one-notification-sender.md), with feature 7.
In short: one list of channels, EasyRMM's (email, generic webhook signed
with `X-EasyRMM-Signature`, Slack, Teams), each owned by the platform or one
organization, the owners' rule held by the database and row-level security.
An outbox drained by one worker under the owner's scope, with the engine's
retries; delivery is at least once, with a delivery ID that stays the same.
Organizations' webhooks are checked on the dialled address: the server's
own addresses, loopback and cloud metadata never, private addresses only
once a super administrator approves them for that channel. Secrets sealed
and shown again to whoever manages the channel; the mail server in the
console, HTML and several recipients; a failing channel raises a console
alert. The engine keeps deciding when; EasyRMM collects its notifications
and monthly report emails from an outbox in the engine, moves its channels
with their IDs and secrets (not a SQL migration: the secrets are the
engine's), and its dispatcher retires. Moved channels keep sending
`X-EasyPatch-Signature` until turned off.

### F3. The updater on the host
Decided in [ADR-0052](adr/0052-the-host-updater.md), revised after review.
In short: `easyrmm-updater` on the host, run by systemd as root, verifies a
build's manifest against its Sigstore attestation (this repository's
release workflow at the release's tag, or, on the edge channel only, the
last job of `main`'s CI), stops the deployment, copies the whole data root,
runs the new `setup.sh --upgrade`, starts the new version held (answering
only its health check), and confirms, or restores the copy and starts the
previous version. A rollback after a confirmed upgrade restores that copy
too, for 24 hours, and says what it loses. The server can only ask, through
a file the updater validates, and reads the updater's status read-only.
Edge builds are published only after the whole of CI passes, with versions
that sort (`v1.0.0-rc.4.edge.<run>.<attempt>`).

## The features

### 1. Operators sign the Windows agent (ADR-0049)
**Done**: merged (#40), all checks green, `signtool` verified on CI's
Windows runner. It ships in rc.4. Left: a real certificate from a public
authority on real Windows computers, when the owner's next full test
instance is up.

### 2. Hardening Linux computers (ADR-0051)
The ADR was revised after its review: SSH works with socket activation
and RHEL 8, the firewall is EasyRMM's own input-only table that drops new
TCP and UDP only, and steps aside for hosts whose ports move; kernel
values only tighten; undo consumes its records, survives interruptions
and runs without the agent; settings that act at boot are refused where
they could stop it.

* **H1**: the script's skeleton (platform and container detection, the
  manifest and journal, the JSON result, `check` for every module), the
  server's job kind, permission, migration and API, **and the virtual
  machine harness on CI**, since the fourth module already needs it.
* **H2**: `apply` and `undo`, module by module, each with its machine
  tests before the next.
* **H3**: the console: a device's **Hardening** tab, the fleet column and
  filter, apply and undo from **Jobs**.
* **Tests**: as in the ADR: virtual machines for each tested release,
  restarted after apply; scenario machines for each guard; containers for
  the container path; `shellcheck`; a matrix test. Then the owner's
  Linux computers.

### 3. Collecting logs
**Decisions for its ADR**

* **Two switches, as the owner asked.** *Configure logging* is on by
  default: at enrolment the agent sets Windows audit policy, the Security
  log's size and PowerShell script block and module logging, and on
  Linux persistent journald and EasyRMM's auditd rules (in a file of their
  own, apart from hardening's). Nothing leaves the computer. *Collect into
  EasyRMM* is a platform switch set at install (`setup.sh
  --collect-logs`, on for new installs) and in a first-run checklist;
  installs that upgrade get both switches from the checklist, asked once,
  and agents already enrolled are configured when the switch reaches them.
  Where auditd is missing, configuring logging installs it, recorded as
  EasyRMM's, so that neither this feature nor hardening's undo removes it
  while the other still uses it.
* **Settings (F1 keys)**: `logs.configure` (on or off; organization
  administrators and above, enforceable from the platform),
  `logs.sources` (which sources and their filters; organization
  administrators), `logs.collect` (platform only, super administrators).
* **Group Policy wins.** Domain computers usually get audit policy from
  Group Policy, which applies it again every 90 minutes. The agent reads
  the effective policy, leaves subcategories Group Policy sets alone and
  shows *set by Group Policy*; domain controllers are left alone unless
  the operator chooses them.
* **Sources**: Windows Security, System, Application, Defender
  (Operational), PowerShell (Operational), Sysmon when present; Linux
  journal (authentication, sudo, sshd, systemd), auditd, Defender for
  Endpoint (`mdatp`) and ClamAV when present. Each with a default filter
  for the security-relevant part.
* **Secrets in logs.** Script block logging records the install command,
  with its token; process creation records command lines. The agent
  redacts deployment tokens (`ert_…`, `EASYRMM_TOKEN`, `-Token`, `TOKEN=`)
  before upload, and drops script block and process creation events from
  its own jobs, whose arguments ADR-0017 keeps out of the audit log. Command lines and
  script blocks need a permission of their own (`log.view_sensitive`);
  `log.view` defaults to organization administrators.
* **The collector is its own process** (`easyrmm-agent collect`), in its
  own systemd unit with `CPUQuota` and `MemoryMax`, and on Windows in a
  job object with a CPU rate limit, so that limits never slow jobs. Its
  disk buffer is capped (256 MiB by default) with a quota per source, so a
  flood in Application cannot push Security out; drops are counted and
  reported.
* **Collection**: Windows through the Event Log API (`EvtSubscribe` with
  bookmarks on disk, no cgo); Linux through the journal's cursor and
  auditd's log by inode and offset.
* **Upload**: `POST /api/agent/v1/logs`, signed, gzip, at most every 10
  seconds; the server caps the decompressed size while reading, after the
  signature, and answers how much more it will take.
* **Storage that cannot take EasyRMM down.** A database of its own,
  created by an init service (as the engine's is), partitioned by day,
  with the organization and site on each row (row-level security without
  a join). Partitions are made and dropped by functions the owner holds;
  the application reaches only the parent table. Quotas per device and
  per organization enforced by the server; a total size cap and a
  free-disk floor, past which ingest stops, agents buffer and an alert is
  raised. Retention (30 days by default) always wins, also over
  forwarding, and gaps are counted. Logs are purged with their
  organization, site or device. The updater's backups leave this
  database out unless asked, so its migrations only ever add, and an older
  server runs on a newer logs schema.
* **Before turning it on**, the page shows the measured volume per kind of
  computer (workstation, file server, domain controller) and the space
  left.
* **Forwarding**: syslog over TCP or TLS first (the audit forwarder's
  transport, through F2's address policy), with one list of syslog
  destinations for both the audit log and device logs. Destinations
  belong to super administrators by default. *Forward only, don't store*
  per organization. A cursor per destination, so one that was down
  catches up within retention.
* **Console**: **Logs** (filters by organization, site, device, source,
  event ID, level, time, text), a device's **Logs** tab, per-organization
  storage and ingest.
* **Privacy**: PRIVACY.md and the guide say what is collected and where it
  goes.

**Slices**: storage, upload and the Linux journal's sign-in events with the
device's **Logs** tab; then Windows Security; then configuring logging;
then the other sources; then forwarding; then the **Logs** page.

**Tests**: integration (partitions, retention, row-level security on the
parent, quotas, the decompression cap, the disk floor, a forwarding
destination that comes back and catches up); the agent's buffer filling
to its cap and dropping by source; Windows collection, audit policy,
script block logging (event 4104), Sysmon (installed on the runner) and
`wevtutil` on CI's Windows runner, for real; the bundle test (a Linux
agent's sign-in events reach the console and a syslog receiver); redaction
of a real install command's token; an upgrade from a release without the
logs database, and a rollback of it; a load test with `tools/agentsim`.

### 4. Upgrading EasyRMM from the console
In two parts, both in [ADR-0052](adr/0052-the-host-updater.md).

* **4a. The updater (F3) and the edge channel**, early, so that the owner's
  test instance follows `main`: `easyrmm-updater upgrade <version>` and
  `rollback` on the host; automatic upgrades on the edge channel for test
  instances; the server's `hold` and its offline rule; `setup.sh
  --upgrade`; `main`'s publishing at the end of CI; `main` and release
  tags protected. The console shows a banner when an upgrade fails or was
  rolled back (email follows with F2).
* **4b. The console**, after F2: Settings → **Updates** with the running
  version, the channel, the newest release (only if a super
  administrator allows checking: off by default, PRIVACY.md updated; the
  server asks GitHub once a day), its release notes, **Upgrade now** or
  at a time (the server writes the request then), pre-checks (running jobs, patch windows, open remote
  sessions), progress through the downtime, and **Roll back** with what it
  loses. Super administrators only; every step audited.

**Tests**: as [ADR-0052](adr/0052-the-host-updater.md#testing) lists them:
verification against real published builds; the whole upgrade, a failed
one and both rollbacks on every pull request that changes them; the
previous edge build upgraded on `main` before the `edge` tag moves; the
request directory's attacks; the updater updating itself from the second
release with one; then the owner's instance on edge.

### 5. Let's Encrypt in one step
**What exists**: `acme` mode with `autocert` for the names in `.env`
(console, MeshCentral, the patching agents' names, Authentik), HTTP-01 and
TLS-ALPN-01, renewed in the process; names are read at start.

* **5a. CertMagic, status and alerts.** CertMagic (Apache 2.0) instead of
  autocert for the same names: issued as soon as the server starts, not
  at the first connection; renewed with ACME Renewal Information; a
  managed list instead of `HostWhitelist`, never on-demand issuance; no
  OCSP stapling (Let's Encrypt ended OCSP in 2025); certificates kept in
  PostgreSQL behind an advisory lock, so several servers share them.
  `--acme-email` becomes optional. Settings →
  **Certificates** shows each name, issuer, expiry, next renewal and last
  error; an alert when a renewal fails or less than 14 days are left,
  sent through F2 (Let's Encrypt no longer emails about expiry). The ACME
  directory and its CA root become a supported setting, so a private ACME
  CA works (and Pebble in tests). The guide's recovery when the server
  will not start: `docker compose run --rm server tls reset`.
* **5b. Names from the console.** The page is built around the install that
  needs it: one on an IP address getting a name. It shows the DNS records
  to create with the server's public address, runs checks shown as ticks,
  each failure with its fix (the name resolves; ports 80 and 443 answer;
  a resolving address that is not this host's is a warning, not a
  failure, since cloud and NAT hosts only see their private address; a
  trial order against Let's Encrypt's staging service, the real test, so
  that a mistake does not use up the real service's limits), then **Get
  certificates**, then "renews automatically; next renewal on …". In
  offload mode the page says the proxy owns TLS. Adding a name needs
  step-up authentication, and a name is trusted only once this server
  holds a certificate for it obtained through HTTP-01 or TLS-ALPN-01 (proof
  that the name reaches this server) or, for DNS-01 names, once a token
  served here was fetched through the name. Only then does it become an
  origin of the console, a single sign-on redirect URI, the authenticator
  issuer, part of the install commands (rendered again), MeshCentral's
  configuration and the engine's and Authentik's addresses; the ADR lists
  every component and how each is told. A name whose renewal keeps failing
  is flagged, and stops being trusted when its certificate expires. TLS mode and trusted proxies stay in `.env`. DNS-01 with RFC
  2136 (a key scoped to `_acme-challenge`, or a CNAME to it) and
  Cloudflare; the guide recommends delegating `_acme-challenge` over
  handing EasyRMM a whole zone's token.
* **5c. Moving to a new name** (changing the console's name, or moving
  agents from an IP address to a name) is an ADR of its own: each
  computer runs three agents that hold the address (EasyRMM's, MeshAgent's
  `.msh`, the EasyPatch agent's `ServerUrl`); an agent may only move on an
  instruction signed with the job key over its device, a nonce it sent to
  the new address and that address, trusting the roots it already
  trusts; step-up authentication and a notice to every super
  administrator; a view of the devices still on the old name; old names
  kept registered and served until a cut-off. WebAuthn keys stay valid
  through Related Origin Requests (`/.well-known/webauthn`). 5a and 5b
  ship without it.

**Tests**: Pebble for HTTP-01 and TLS-ALPN-01, and for DNS-01 through RFC
2136 against a real BIND on host networking; renewal and the failure
alert; two servers sharing certificates; `tls reset`; MeshCentral
restarted with the new configuration and agents reconnecting; Cloudflare
on a real account on `main` only, or marked unverified; the staging trial
by hand; then the owner's real name.

### 6. Packages for the agent: DEB, RPM, MSI
* **The package never replaces an enrolled agent's binary.** It installs
  the agent; on first install it runs `easyrmm-agent install`, which
  copies the agent to the place the agent owns, as the install command
  does today. Later package upgrades leave the running agent alone: agent
  updates stay with the server's rollout and *Only signed builds*, and an
  Intune or package upgrade cannot get round them. A package upgrade never
  moves an agent to the address in its configuration.
* **One build** of each agent binary in the release, copied into the
  image, the release files and the packages.
* **Enrolment input.** DEB and RPM read `/etc/easyrmm-agent/install.conf`
  or `EASYRMM_SERVER` and `EASYRMM_TOKEN`; the file is deleted once the
  agent has enrolled. Without either, the package installs and waits for
  `easyrmm-agent enroll` (golden images). The MSI takes `SERVERURL`,
  `TOKEN` and `CACERT`; the token travels as hidden custom action data,
  never stored in the registry or put on a command line. Group Policy
  cannot pass properties, so **Add devices** offers a transform (MST) per
  token. Group Policy and Intune cannot keep a secret from domain users
  (transforms and preferences sit in SYSVOL), so that transform is made
  for approval tokens (a copy read from SYSVOL enrols nothing until
  someone approves it) or tokens limited in use.
* **Versions.** Programs and Features and `dpkg -l` show the package's
  version, not the agent's after it updates itself; the guide gives
  Intune detection by the service and the agent's own version.
* **Removal.** Removing the package runs `easyrmm-agent uninstall`, which
  tells the server it was uninstalled (best effort, feature 7) and leaves
  the device in the console as *Uninstalled*. A removal from the console (ADR-0050) of a packaged
  agent runs `dpkg -r`, `rpm -e` or `msiexec /x` from its transient unit or
  detached process, tells the package's script not to uninstall a second
  time, and retries while the package manager is busy. The device records
  how its agent was installed; the removal dialog warns that Intune or
  Group Policy may install it again.
* **Signing.** Under *Only signed builds* the MSI is not offered: it
  carries the unsigned agent, which WDAC and AppLocker fleets block. A
  signed MSI (an MSI reader for its Authenticode digest, and the signed
  agent inside) is a later step. DEB and RPM rely on the release's
  attestation and checksums.
* **Order**: DEB, then RPM, then MSI.

**Tests**: each package built by a reusable workflow that pull requests run
without publishing (release-only changes are otherwise untested); DEB and
RPM installed, enrolled, upgraded, removed in systemd containers; the
bundle test enrols one agent from the DEB; the MSI on CI's Windows runner
with ICE validation, then installed, upgraded and removed there; removal
from the console of a packaged agent.

### 7. Email and webhook notifications for device alerts
On F2, decided in the same [ADR-0053](adr/0053-one-notification-sender.md).
In short: rules filter by organization, site, device group (devices have
no tags yet), kind of device (from the agent's `InstallationType`, else the
operating system), severity and condition; notify on opening, optionally
after N minutes, on resolving, with reminders until acknowledged.
Maintenance windows per site; an agent's notice before a shutdown holds the
offline alert itself for a grace period; one message when a whole site goes
offline; digests of 25 for people, every alert for generic webhooks, with
stable IDs for PSA tools; *Uninstalled* from a local uninstall.
`Evaluate` gains `RETURNING` and queues in its own transaction. ADR-0052's
offline rule delays openings only. Settings → **Notifications**. Tested
in the bundle test with Mailpit and a webhook receiver in a network
namespace joined by a veth pair; Slack and Teams by hand.

### 8. The agent's WebSocket channel
On F0 and F1.

* **`GET /api/agent/v1/connect`**: the upgrade request is signed like
  every agent request today (single-use nonce), which authenticates the
  connection; there is no separate challenge that the agent would sign
  (it could be made into a signing oracle).
* **Every message is signed**: Ed25519 over a context of its own, a
  connection ID the server issues, a sequence number, the type and the
  body's hash. The sequence, kept in memory, stops replays; what is saved
  is the nonce's database write per message, not the signature.
  Connections cannot be bound to TLS (offload, NGINX), and the ADR does
  not claim they are.
* **What goes over it**: server to agent: *wake* (a job is waiting),
  signed instructions as soon as they exist, settings changes, pings;
  agent to server: heartbeats. Large uploads (job results, inventory,
  logs) stay signed HTTPS requests with their limits.
* **Limits and lifetime**: one connection per device; per-message rate and
  size limits; reconnect at least every 12 hours; closed at once when the
  device is removed or retired; pings every 30 seconds both ways; the
  server's file descriptor limit raised.
* **Several servers**: wakes and instructions through PostgreSQL
  `LISTEN/NOTIFY`, which long polling gains too.
* **The setting** (F1 key `agent.transport`, Site Administrators and
  above): **Automatic (recommended)**; **Live connection**; **Regular
  check-ins** (for networks that block live connections), each with one
  line on what it changes. Automatic falls back after three failed
  connections in 10 minutes (a connection that dies within a minute
  counts: TLS inspection does that) and tries again hourly. *Live
  connection* keeps an HTTPS heartbeat every 10 minutes, so a device whose
  connection fails can still receive the setting that would fix it.
  Devices shows the transport in use and has a filter for those that
  fell back.
* **Slices**: wake-only WebSocket beside polling; then F1 with this one
  key; then the setting and the fallback.

**Tests**: unit (framing, signatures, sequence, fallback), integration (a
job and an instruction reach a connected agent at once; NOTIFY across two
server instances; a forged and a replayed message refused; removal closes
the socket), the bundle test with agents on each transport and through
NGINX in offload mode (refusing the upgrade, to prove the fallback); a
500-agent run on CI. 2,000 and 10,000 agents are run on the owner's host
and recorded in drills.md: a CI runner (4 CPUs) cannot hold them.

## Test harnesses to build

* **Virtual machines on CI** (hardening, the updater's host path):
  cached cloud images, cloud-init, QEMU with KVM and user networking.
* **Windows end to end on CI**: the server built for Windows against the
  PostgreSQL that the `windows-2025` image carries, with a Windows agent
  enrolling (log collection, the MSI, signed agents). If that cannot be
  made to work, a self-hosted Windows machine; until one exists, Windows
  paths are marked unverified. Windows jobs pin `windows-2025`.
* **Coverage on Windows**: the Windows job writes a coverage profile with
  floors of its own for Windows-only code.
* **The bundle test split** into parallel jobs reusing images built once.

## Order

| Step | Work | Why here |
|---|---|---|
| 1 | rc.4, the owner's instance upgraded | ADR-0049 and device removal are merged |
| 2 | The fixes the reviews found | Holes in shipped code |
| 3 | Hardening (2), H1 with the machine harness | Asked for first; ADR revised |
| 4 | Updater 4a with the edge channel | The test instance follows `main` from then on |
| 5 | F2 and device alert notifications (7) | Needed by 4b, 5 and 3's alerts |
| 6 | Updater 4b: the console | Needs F2 |
| 7 | Let's Encrypt 5a, then 5b | Needs F2 for its alerts |
| 8 | Packages (6): DEB, RPM, MSI | How MSPs onboard computers; nothing depends on 3 |
| 9 | F0; the wake-only WebSocket; F1; the transport setting (8) | F1's first key is the transport |
| 10 | Log collection (3), in its slices | The largest; needs F1 and F2 |
| 11 | Moving to a new name (5c), its ADR first | Needs F0 |

Each step ends with CI green, a merge, and the test instance on the new
code.

## Risks

* **Hardening locks someone out or breaks a service**: the revised ADR's
  guards, machines for every guard, undo without the agent.
* **Logs take EasyRMM down**: a database of its own, quotas, a size cap and
  a disk floor that stop ingest before the disk fills.
* **The updater is root on the host**: it takes nothing but a version from
  the server, writes nowhere the server can, and installs only what it
  verified.
* **A stolen administrator session redirects agents**: moving names needs
  signatures over the agent's own nonce, step-up authentication, and a
  notice to every super administrator.
* **Middleboxes break WebSockets**: automatic fallback, and an HTTPS
  heartbeat kept on forced connections.
* **Packages fight self-update**: the package never replaces the running
  agent.
* **Organizations' webhooks reach into a network**: every dialled address
  checked, private ones only once approved for that channel, and the
  server's own addresses never (ADR-0053).
* **Notifications storm or go missing**: site outages, digests and the
  restart grace keep a power cut to a few messages; a failing channel
  raises a console alert (ADR-0053).
* **Windows is unverified in CI** until the Windows end-to-end harness
  exists: every Windows path says so until then.
