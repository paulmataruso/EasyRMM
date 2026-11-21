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
Patching sends its own email and webhooks from the engine (Settings →
Patching → Notifications); device alerts need a sender too. An MSP should
set up its Teams channel once.

* **One list of channels and one sender**, both EasyRMM's: email, generic
  webhook (JSON, HMAC-SHA256 signature over `t.body`), Slack, Microsoft
  Teams (Workflows webhooks, as the engine already uses). The engine keeps
  deciding *when* patching alerts are due, but hands each notification to
  EasyRMM, which delivers it like any other; the engine's own dispatcher
  and its weaker address policy are retired (ADR-0048's rule: nothing left
  that nothing reaches). Existing patching channels are moved over by a
  migration. The signature header and a transition for receivers of
  `X-EasyPatch-Signature` are settled in the ADR.
* **Ownership**: a channel belongs to the platform (super administrators)
  or to one organization (its administrators). Rules can only use
  channels of their own organization or the platform's, enforced by a
  database constraint. Delivery runs under the destination
  organization's scope, so row-level security holds.
* **Delivery** follows the engine's design, which works: a delivery table
  drained by one worker under an advisory lock, retries from 1 minute
  doubling to an hour, given up after 24 hours, one test per channel
  every 30 seconds. Errors are generic, without the response body.
* **Address policy for every destination an organization owns** (webhooks
  now, syslog destinations with log forwarding), checked on the address
  actually dialled: loopback, link-local, multicast, reserved ranges, the
  server's own addresses and every cloud metadata address (including
  `fd00:ec2::254` and `100.100.100.200`) are always refused; a private
  address only for a destination a super administrator has approved.
  Webhooks are HTTPS only, with no redirects and no proxy. The platform's
  own destinations (super administrators) may also use private addresses
  and loopback, as audit forwarding may today ("an integration often runs
  on the same host"); cloud metadata stays refused. A destination may name
  a certificate authority to trust, for receivers with a private
  certificate.
* **Secrets**: signing secrets and Slack and Teams URLs (secrets in
  themselves) sealed with `EASYRMM_SECRET_KEY`, shown again to whoever
  manages the channel (as ADR-0047 does for tokens).
* **Mail server in the console**, with a test message, instead of only
  `EASYRMM_SMTP_*` and a restart. The mailer gains HTML with a plain text
  alternative and several recipients.
* **A failing channel raises an alert in the console**: a notification
  that fails without anyone knowing is the worst outcome.
* **Content**: device names and other values that come from agents are
  escaped for HTML email, Slack and Teams.
* **Slices**: the mailer and the mail server in the console; the channel
  list, the sender and the address policy with email and generic webhooks;
  device alert rules (feature 7); Slack and Teams; patching's
  notifications through EasyRMM and the channels' migration.

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
Proposed in [ADR-0060](adr/0060-collecting-logs.md), revised after its
independent review and five checks, not accepted yet. In short:

* **Windows jobs start inside their job object first** (slice 0,
  amending ADR-0017); otherwise jobs start exactly as today, arguments
  on the command line, so exit codes and binding do not change. EasyRMM's
  copy of a job's events has its argument values replaced; the
  computer's own Security log holds them once command lines in process
  events are on, an organization setting, on by default, which the
  console explains (ADR-0017's guidance: no secrets as arguments). Linux
  jobs get a login UID of their own (slice 2), which an audit rule
  records (slice 4). Then the volumes are **measured** on real computers
  (slice 1) before the store is built.
* **The collector** (`easyrmm-agent collect`) is a process of its own
  without the device's key, network access, privileges or rights to change
  anything: on Linux its own unit (an unnamed user in the journal's group
  with no capability, auditd's log through descriptors the agent passes,
  `CPUQuota` and `MemoryMax`), on Windows a service of its own whose
  virtual account is granted read access in each collected channel's own
  access list, blocked from the network by a filtering-platform filter, in
  a job object with a CPU cap. It reads Windows'
  event logs through `EvtSubscribe` and Linux's journal and auditd log
  from positions written with the events into a capped disk spool; a
  source whose share is full pauses, since the computer's own log holds
  its events. It redacts EasyRMM's tokens; the agent seals its batches
  (marking EasyRMM's own jobs, replacing their argument values) and uploads
  them signed, paced to a bandwidth limit per site, in two streams so
  that Security and Defender come first; the server stores each exactly
  once and signs its answers.
* **Configure logging** (on by default) sets Windows audit policy from
  one table taken from Microsoft's baselines, which Windows hardening
  reports against, `SCENoApplyLegacyAuditPolicy`, command lines in
  process events, script block logging (narrowing who can read it) and
  log sizes (Security at the STIGs' 1,024,000 KB); and auditd rules,
  generated per computer, and a persistent journal on Linux. What Group
  Policy, MDM or another owner holds is left *managed elsewhere*, read
  with Windows hardening's reader, and a value whose owner that reader
  cannot tell is only reported; domain controllers only when chosen;
  undone on uninstall. On Linux each feature keeps its own rules file and
  keys, and auditd is removed by the last one out.
* **The store** is a PostgreSQL instance of its own in a directory beside
  the data root, which the updater never copies, moves or deletes, with
  its passwords set from `.env` at each start; nothing depends on it and
  the server's readiness never does, so a broken store degrades logs and
  never stops or rolls back EasyRMM. It holds compressed blocks
  of events with hourly facts (B-tree indexes, which row-level security
  can use), partitioned by retention class and day, week or month. Quotas
  per kind of computer, a storage share per organization, a size cap and
  a free-disk floor stop ingest before the disk fills, refusing the
  organizations over their share first. A removed device's logs stay
  until retention ends. At 2,000 devices and 30 days: about 150 to 210
  GB, against about 1.25 TB as a row per event.
* **Console**: **Logs** and a device's **Logs** tab, with a server-wide
  search pool and background searches; `log.view` for Site
  Administrators and above, command lines and scripts for Organization
  Administrators (`log.view_sensitive`, enforced in results, text search
  and exports); every search audited.
* **Forwarding**: one list of syslog destinations for the audit log and
  device logs, positions kept with the logs, walked up to the oldest
  running transaction so that none is skipped, gaps counted.
  **Detections**: alert policies of a new kind, `log`, carrying no event
  content, sent through F2; EasyRMM's own changes open none.

**Slices**: Windows jobs inside their job object; measuring; the store and
Linux sign-ins with the device's tab; Windows Security; configuring
logging; the other sources; forwarding; organizations' retention and
quotas; detections; the **Logs** page; organizations' own destinations.
**Tests**: CI's Windows runner and the virtual machines for real, the
bundle test with a syslog receiver on host networking, the updater's
rollbacks counting blocks, and `tools/agentsim` with recorded events,
flooding and slow devices among them.

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
On F2.

* **Rules**: which alerts reach which channels, by organization (or the
  platform), site, kind of device (server or workstation, from its
  operating system), tag, severity and condition; on opening (optionally
  only once open N minutes), on resolving, reminders every N hours while
  open and not acknowledged. Maintenance windows per site.
* **Planned restarts are not outages**: an agent tells the server when its
  computer shuts down or restarts (the service is stopped for a shutdown,
  as after a patch window or a script's restart), and offline notices for
  it wait for a grace period (15 minutes by default). One message when a
  whole site goes offline ("Site X: all 40 devices offline"), not forty.
  Digests: one message per channel per run, up to 25 alerts, with a count
  of the rest.
* **For PSA tools**: the generic payload carries a stable alert ID with
  opened, resolved and reminder events, so a ticket can be opened and
  closed.
* **No false offline alerts**: a local uninstall tells the server, best
  effort, and the device shows *Uninstalled* instead of offline forever.
* **Nothing lost or sent twice**: `Evaluate` returns the alerts it opened
  and resolved (`RETURNING`), and their notifications are queued in the
  same transaction.
* **Who**: organization administrators for their organization's rules and
  channels; super administrators for the platform's.
* **Console**: Settings → **Notifications** (channels, rules, mail server,
  tests, the delivery log); the alerts page links to it.

**Tests**: integration (rules, windows, site outages, digests, retries,
the address policy, the constraint between rules and channels, the
transaction); in the bundle test, a webhook receiver in a network
namespace of its own joined by a veth pair (no bridge) on a private range
approved as a destination, and a real SMTP server (Mailpit): a device goes
offline, the signed webhook and the email arrive, it comes back, the
resolve arrives. The bundle test is split into parallel jobs that reuse
images built once, so these waits do not lengthen the critical path.
Real delivery to Slack and Teams is checked by hand and recorded.

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
* **Logs take EasyRMM down**: a PostgreSQL instance of its own outside
  the data root, quotas per kind of computer, a share per organization, a
  size cap and a disk floor that stop ingest before the disk fills, and a
  server-wide limit on searches.
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
* **Windows is unverified in CI** until the Windows end-to-end harness
  exists: every Windows path says so until then.
