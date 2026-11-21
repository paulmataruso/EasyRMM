# Plan: the next nine features

* Status: Draft 3 (2026-11-21). Draft 1 had three independent reviews
  (security and architecture; the MSP operator's view; testing,
  feasibility and order), ADR-0051 one; Draft 2 was checked against all
  four by a fourth reviewer, who found 37 of 60 findings fully answered
  and some new problems; this draft answers the rest. Feature 9 was added
  the same day, after those reviews; its ADR (ADR-0054) is proposed, had
  one independent review, and was revised after it and after that
  review's check.
* Scope: the work the owner asked for on 2026-11-20 and 2026-11-21:
  1. Operators sign the Windows agent (ADR-0049).
  2. Hardening Linux computers (ADR-0051).
  3. Collecting logs from Windows and Linux.
  4. Upgrading EasyRMM from the console.
  5. Let's Encrypt in one step.
  6. MSI, DEB and RPM packages for the agent.
  7. Email and webhook notifications for device alerts.
  8. The agent's WebSocket channel, with a per-device choice of transport.
  9. Hardening Windows computers and servers (ADR-0054).

This page says what each feature does, what it builds on, the decisions
its ADR has to make, how it is tested, and the order of the work. Each
feature still gets its own ADR, reviewed before it is built, its own pull
requests and its own changelog entries.

## What the reviews changed

* **Trust.** The host updater no longer trusts anything the server
  writes beyond a version number, and never writes where the server can.
  One exception, decided in review: its rollback guards (ADR-0052) read a
  few integers from the database, which can only refuse a rollback.
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
(ADR-0017, Consequences), and the new kinds of instruction this plan adds
(settings, a new address) would rest on it too. Proposed in
[ADR-0057](adr/0057-rotating-the-job-key.md), revised after its review and
a second check. In
short: the keys become a ring with generations that only increase; agents
report the keys they trust in their signed heartbeats and job polls (by
ADR-0009's rule), and the server signs each device's instructions with the
newest of them. A rotation hands each agent the new key in a statement
signed by a key it trusts. A super administrator finishes a planned
rotation after at least 24 hours (ADR-0052's rollback window), confirming
a newer backup; a rotation for a compromise is cut over at once, and a
device on a compromised key is moved to it before any later key. Agents
offline across the overlap follow when they come back, since the server
keeps an old key while any device needs it. After a compromise a device
counts as moved only on its own signed report, which proves only an agent
nobody tampered with; devices that cannot be moved are re-pinned with
`easyrmm-agent trust-key`, a command with no secret, or reinstalled; a
device left on a key a restore lost moves with the next rotation. A
leaked backup set also gives the TLS identities, MeshCentral's keys, the
patching engine's notification credentials and, with Authentik, its
signing key pair and secrets, which the incident page replaces;
EasyRMM's own authority is replaced in two phases, both authorities
first, so no agent is cut off. The updater refuses a rollback
whose backup lacks a key agents were cut over to, and one while a server
on another host shares the database (ADR-0052's rollback guards, shared
with 5c); they ship with the second slice or before, and the second
slice also waits for ADR-0055's step-up. Tested with real agents on the
host's network through a rotation, one offline across it, one from before
the change, and restores across it. The first slice (agents that can
follow, and flags for keys and instructions the server never issued) can
ship before the rest of step 10.

### F1. Signed settings that reach the agent
Proposed in [ADR-0058](adr/0058-signed-settings-that-reach-the-agent.md),
not reviewed yet. In short: a fixed catalogue of keys, each with a schema,
a default, its scopes and its permission (`device.configure`, new, for
Site Administrators and above, for the first keys); set at the platform,
an organization, a site or a device, the nearest winning unless a higher
scope enforces. The heartbeat answer carries the device's effective
settings, all keys, as one document signed with the job key, only when
the agent's version is behind; versions only increase (the time, the last
issued and the agent's own report), so a restored database or a replay
cannot roll them back. The agent saves what it applied, keeps it across
restarts and outages, ignores unknown keys, keeps its value for invalid
ones, and reports what it applied in its next heartbeat; the console shows
*Applied* or *Waiting for the device*. First keys:
`agent.heartbeat_seconds` (30 seconds to 5 minutes; online becomes three
missed heartbeats of the device's own interval) and `agent.transport`
(feature 8). Slices: the server and its API; delivery and the agent; the
console, with a Settings tab on each device.

### F2. One notification sender
Decided in [ADR-0053](adr/0053-one-notification-sender.md), with feature 7,
revised after review; its departures from what follows are listed below.

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

**Where ADR-0053 departs from this**:

* **"Moved over by a migration"** becomes an export and a move at start:
  the engine's database is separate and its secrets are sealed with its
  own keys. The channels keep their IDs, so the engine's rules need no
  rewrite; a channel the engine cannot decrypt moves turned off. The
  engine's channel table and export route stay, because imports
  (ADR-0045) still bring channels.
* **Monthly report emails** move to EasyRMM too; the plan did not name
  them, and they go through the engine's SMTP client.
* **Organizations' rules** use a platform channel only once a super
  administrator shares it with that organization (decided in review).
* **The server's own networks**, whatever their kind, need approval as
  private ranges do; the server's own addresses and the deployment's names
  are always refused. The engine refused its networks outright, which on
  host networking is the customer's LAN.
* **Delivery is at least once**, with a stable delivery ID; queueing is
  exactly once, and order is kept per alert, notice and site outage.
  Permanent answers fail at once, and one message holds its channel for an
  hour at most, then only messages about the same alerts, notices and
  outages.
* **Limits**: quotas per organization counted in messages (one per email
  recipient), fair share between organizations, the mail server's own
  rate a minute and a day with account mail first, and at most one unsent
  digest per channel read by people.
* **Several recipients** each get their own copy, so no recipient sees
  another.
* **The certificate authority** for the mail server comes with slice 6,
  once the engine (which cannot trust one) no longer sends email.
* **Signing in to Microsoft 365** with an application's credentials
  (`XOAUTH2`, the client credentials grant) is a slice of its own, the
  second: Exchange Online turns SMTP password sign-in off by default for
  existing tenants at the end of December 2026, and the mailer signs in
  with a password only. It works from `.env` and `setup.sh` too, the
  secret or certificate key in a file under `secrets/`, so that mail works
  at install. A relay remains the alternative; Google can be added later.
  Slack and Teams, then patching, come before restarts and *Uninstalled*,
  so that patching's email, which the engine cannot send with an
  application, waits as briefly as it can.

### F3. The updater on the host
Decided in [ADR-0052](adr/0052-the-host-updater.md), revised after review.
In short: `easyrmm-updater` on the host, run by systemd as root, verifies a
build's manifest against its Sigstore attestation (this repository's
release workflow at the release's tag, or, on the edge channel only, the
last job of `main`'s CI), stops the deployment, copies the whole data root,
runs the new `setup.sh --upgrade`, starts the new version held (answering
only its health check), and confirms, or restores the copy and starts the
previous version. A rollback after a confirmed upgrade restores that copy
too, for 24 hours, and says what it loses; it is refused across a job key
cut-over or a name move (ADR-0052's rollback guards, shared by F0 and 5c),
unless the host overrides it. The server can only ask, through a file the
updater validates, and reads the updater's status read-only.
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
5a and 5b are decided in
[ADR-0055](adr/0055-lets-encrypt-in-one-step.md) (proposed, revised after
review). In short: every DNS name the edge serves (console, MeshCentral,
Authentik, an imported EasyPatch's) gets its own Let's Encrypt
certificate; IP addresses keep the internal authority, and there are no
wildcards. MeshCentral's `allowedOrigin`, which sessions on any
MeshCentral origin but the primary one need, is fixed separately (branch
`fix/mesh-allowed-origin`); 5b3 adds an added name to that list.

* **5a. CertMagic, status and alerts.** CertMagic instead of `autocert`:
  issued at start from a managed list, renewed by ARI, no OCSP. EasyRMM
  schedules and gates every attempt (Let's Encrypt's retry schedule,
  persisted, a failure budget per name and hour, nothing during the
  updater's hold); CertMagic's own retries are not used. Keys and
  certificates sealed in PostgreSQL; `autocert`'s account and ECDSA
  certificates imported, so the upgrade orders nothing and registers no
  account; no email unless set; a private ACME CA with its roots
  (`EASYRMM_ACME_CA_FILE`). Checks for every name, on the page and in
  `easyrmm-server tls check`. Settings → **Certificates** shows each name;
  alerts as fractions of each certificate's lifetime, and after an hour
  without a certificate, on every console origin and through F2's sender
  behind one interface. MeshCentral reads its certificate from a
  loopback listener of its own, which serves what agents get; a new one
  is applied 3 minutes after MeshCentral's last read, and within 15
  minutes of being ready.
* **5b1. Agent trust**, released first: a trust instruction signed with
  the job key carries the chain a source will serve; the agent verifies
  it on the device and widens its trust (system roots and its CA file)
  only for a move, only on that device, only if it verified. Needs
  ADR-0009's protocol levels (pull request #52).
* **5b2. Sources and moves.** A DNS name served by the authority or the
  operator's files moves to Let's Encrypt and back without a restart,
  once every device seen in 30 days that uses the name, through its
  EasyRMM agent or its EasyPatch agent, verified the chain. Account
  registration, CAA `accounturi`, a trial order against staging, then
  **Agree and get certificates**. ADR-0042's instructions carry the
  authority whenever there is one. Step-up authentication, defined there
  for this plan; `tls reset`.
* **5b3. An IP install's name**: the records to create, checks as ticks,
  **Agree and get certificates**. The added name becomes a console origin
  (never internal), the install commands' first address and the email
  links' while it is reachable (checked daily), the authenticator's name,
  WebAuthn's relying party, and an allowed origin in MeshCentral; when it
  stops being trusted, agents enrolled through it keep working. Single
  sign-on, Authentik's address and the engine's stay on the IP address
  until 5c.
* **5b4. DNS-01** through RFC 2136 (HMAC-SHA256 or stronger) or
  Cloudflare, delegation recommended, propagation checked at the zone's
  own servers.
* **5c. Moving to a new name** (changing the console's name, or moving
  agents from an IP address to a name) is an ADR of its own: each
  computer runs three agents that hold the address (EasyRMM's, MeshAgent's
  `.msh`, the EasyPatch agent's `ServerUrl`); an agent may only move on an
  instruction signed with the job key over its device, a nonce it sent to
  the new address and that address, trusting the roots it already
  trusts; step-up authentication and a notice to every super
  administrator; a view of the devices still on the old name; old names
  kept registered and served until a cut-off; single sign-on's redirect
  URIs, Authentik's address and the engine's public URL move with the
  console's name. WebAuthn keys stay valid through Related Origin
  Requests (`/.well-known/webauthn`). 5a and 5b ship without it.

**Tests**: as [ADR-0055](adr/0055-lets-encrypt-in-one-step.md#testing)
lists them: Pebble and BIND on host networking for every challenge,
renewal with a 10-minute certificate, the failure alert, restarts that
repeat no attempt, the upgrade from `autocert` and moves between sources
with real agents in the bundle test; the Windows runner for the agent's
trust, or marked unverified; a second Pebble as a flagged stand-in for
staging in CI; Cloudflare against Let's Encrypt's staging with a real
zone on `main` only, or marked unverified; a real Let's Encrypt staging
run by hand, then the owner's real name.

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
On F2. Decided in the same [ADR-0053](adr/0053-one-notification-sender.md);
its departures from what follows are listed below.

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

**Where ADR-0053 departs from this**:

* **No tag filter**: EasyRMM's devices have no tags (the engine's
  endpoints do). Rules filter by device group until devices have tags.
* **Kind of device** comes from a new agent fact (`InstallationType` on
  Windows), with the operating system's description as the fallback and
  an override at the site.
* **Generic webhooks get every alert**, in deliveries of at most 100, not
  25 and a count: a PSA tool cannot ticket an alert hidden in a count.
  People's channels keep 25 and a count.
* **The grace delays the alert itself**, not only its notice, and only
  after a shutdown; a stopped service gets none.
* **`Evaluate` gains no `RETURNING`**: triggers write a journal of every
  alert change in the same transaction, wherever it is made, and a planner
  queues the notifications in a transaction of its own. A failure in
  notifications can then never stop alerting.
* **A local uninstall** marks the device *Uninstalled* and raises a
  notice of its own, *agent removed without a request*, rather than going
  quiet; a removal report that answers no instruction the server issued
  does the same instead of deleting the device, and every instruction
  sent is recorded under its own ID, so that neither cancelling nor asking
  again forgets it (amending ADR-0050).
* **ADR-0052's offline rule** delays openings only, as pull request #51
  amends and builds it; as first written it would have resolved every
  open offline alert at each restart. A fleet-wide hold covers an EasyRMM
  that runs but that no agent can reach: while most devices are silent,
  organizations' rules send no offline openings and platform rules do.
* **The offline test stops both agents**: a device is online while
  MeshAgent is connected, so stopping the EasyRMM agent alone raises
  nothing.
* **PSA tools also get `alerts.acknowledged`** (decided in review), and
  an incident ID that survives a policy change.

### 8. The agent's WebSocket channel
Proposed in [ADR-0059](adr/0059-the-agents-websocket-channel.md), not
reviewed yet; on F0 and F1. In short: **wake-only**. `GET
/api/agent/v1/connect` is authenticated by the agent's signed upgrade
request (no URL token, no challenge to sign); the server sends only signed
`hello`, `tick` (every 30 seconds; the agent pings every 30 seconds too),
`wake` (*jobs*: poll now; *checkin*: heartbeat now) and `closing`, bound to
the connection and a sequence. Jobs, instructions and settings still come
only in answers to signed HTTPS requests, so a lost wake or connection
delays a job but never loses one; a live agent stops holding long polls
and polls on connect, on a wake and when a heartbeat says `jobsWaiting`,
and holds them again the moment the connection ends. Full delivery over
the connection, and heartbeats over it, are not planned: reconsidered
only if the 10,000-agent drill shows the HTTPS requests left limit a
server. Per device in its Settings tab (F1's `agent.transport`):
**Automatic (recommended)**, the default; **Live connection**, never
falling back; **Regular check-ins**; inheritable from the site,
organization and platform, enforceable by the platform or an
organization. Automatic falls back after three failures in 10 minutes
that happen while HTTPS works, and retries hourly. Limits: one connection
per device, upgrades per device and per second, 10,000 connections per
server by default, `nofile` raised, a memory gate in CI. Slices: the
channel beside the long poll (*Regular check-ins* by default); the live
connection replacing the held poll, *Automatic* by default; several
servers through `LISTEN/NOTIFY`. Tests: unit and Windows runner,
integration, the bundle with real agents through an idle-killing proxy,
an inspecting proxy, NGINX and a server restart, 5,000 connections and
500 agents on CI, 2,000 and 10,000 agents on a drill host (never the
host of the owner's instance, which `soak.sh` would have to stop).

### 9. Hardening Windows computers and servers (ADR-0054)
The ADR is proposed, had one independent review and was revised after it
and after that review's check. It reuses feature 2's job kind, modes,
results, permission and console; the agent does not change.

* **Basis**: values from Microsoft's security baselines for the
  computer's version and role; each setting cited by its DISA STIG rule
  ID, with whether EasyRMM's value meets the rule, differs from it on
  purpose, or is not set; no CIS numbers, titles or claims (CIS's terms
  forbid it without a paid Product Vendor Membership and certification
  before sale), nothing from Wazuh (GPL, and CIS's text). Per module,
  *Related controls*: NIST SP 800-53 Rev. 5 through DISA's CCI list, SP
  800-171 Rev. 2 (what CMMC Level 2 and DFARS use) through its Appendix D
  and Rev. 3 through its source controls, ISO/IEC 27001:2022 Annex A
  through NIST's crosswalk, never called compliance. The same for Linux is
  a follow-up to ADR-0051.
* **Script**: `windows.ps1`, Windows PowerShell 5.1, run as LocalSystem by
  the existing PowerShell jobs; registry values where Group Policy would
  write them (Defender's and attack surface reduction's included, as
  policy values), `secedit`, NetSecurity, Windows features without
  removing their payload, and the Terminal Services WMI provider; no
  LGPO.exe, whose terms forbid distributing it. Whether administrative
  template values outlive Group Policy's processing is W2's first test.
  It stops in Constrained Language Mode; under a Group Policy of
  `AllSigned` it cannot start, like every PowerShell job today. Its hash
  is published, for EDRs to allow.
* **Managed elsewhere**: one ownership reader (`internal/winpolicy`),
  built in W1 and reused by log collection, reads Group Policy (with its
  preferences and audit policy), MDM through the MDM Bridge, Defender for
  Endpoint, Configuration Manager, DSC, Azure machine configuration,
  OSConfig and Tamper Protection, and returns for each value an owner and
  its policy, none, or *cannot tell* with a reason; what an owner holds is
  reported, never written, and *cannot tell* is check only in both
  features, though undo of an earlier apply still runs. A daily check
  (a signed check-only job, one per device at most) reports owners that
  appear after apply.
* **23 modules**: `accounts` (lockout after 10, none on exposed computers
  without an option, never password expiry), `firewall` (only the
  profiles it changes, every listening port, RDP, WinRM, RPC and echo open
  first; a server's firewall only with an option and in two steps),
  `defender` (never real-time protection on a server without an option;
  SmartScreen warns), `asr` (Microsoft's three standard rules blocked, the
  rest in audit; the two reputation rules blocked only with per-rule
  exclusions for the agents' files, once the agents have restarted by
  themselves), `smb`, `ntlm`, `wdigest`,
  `lsa-protection`, `name-resolution`, `powershell`, `rdp`, `uac`,
  `autoplay`, `anonymous`,
  `winrm`, `printing`, `features`, and, not recommended, `smb-signing` and
  `tls`; report only: `audit` (against log collection's one audit table;
  log collection sets it, so the two never fight), `device-guard`,
  `bitlocker`, `laps`.
* **Guards**: RDP, WinRM and the agents stay reachable; the MSP's accounts
  are never disabled; SMB1, NTLM on domain controllers, LSA protection,
  a server's firewall and the built-in Administrator's filtering are
  judged on what the computer did, two applies apart, from an hourly
  harvest of the logs so that busy logs that wrap still count, a gap
  wherever the logging was off; its folder checked before every run, as
  the agent checks its own (PR #61); restarts
  are reported, never performed, and undo works before them; one
  hardening apply or undo at a time on a device, never
  beside a patch or software job; domain controllers need an explicit
  option; undo works without the agent.
* **Platforms**: apply and undo on Windows 11 Pro, Enterprise and
  Education versions still in service (26H1 once tested; ARM64 once the
  agent's ARM64 build is verified), Server 2019 to 2025 (also Server Core)
  and Server 2016 until January 2027; check only on Windows 10, Home
  editions and versions out of service.
* **Slices**: **W1** check, with the ownership reader, the runner matrix
  and the decision on Windows machines under KVM; **W2** apply and undo,
  module by module; **W3** the console, H3's with Windows' modules and
  the related controls.

**Tests**: PSScriptAnalyzer and a test that every cited STIG ID exists in
its release; CI's `windows-2025`, `windows-2022` and `windows-11-arm`
runners for check, apply, apply again and undo, run as LocalSystem, except
`defender` and `asr`, only checked there since the runner images turn
Defender off; Windows machines under KVM (evaluation media, in-box devices,
a serial runner, images built in each run on `main` and on a schedule,
never cached where pull requests can restore them) for restarts, a domain
with Group Policy, traffic from outside, Defender active, a non-English
image, Server 2016 and 2019, and one scenario or more per guard, or, if
W1 finds that cannot work on CI, a self-hosted runner or recorded hand
tests; then a real domain, an Intune-enrolled Windows 11, computers with
another antivirus and firewall, and a common EDR.

## Test harnesses to build

* **Virtual machines on CI** (hardening, the updater's host path):
  cached cloud images, cloud-init, QEMU with KVM and user networking.
* **Windows end to end on CI**: the server built for Windows against the
  PostgreSQL that the `windows-2025` image carries, with a Windows agent
  enrolling (log collection, the MSI, signed agents). If that cannot be
  made to work, a self-hosted Windows machine; until one exists, Windows
  paths are marked unverified. This harness pins `windows-2025`, whose
  PostgreSQL it uses; Windows hardening's tests run on `windows-2025`,
  `windows-2022` and `windows-11-arm`, and the existing *Agent tests on
  Windows* keep `windows-latest`.
* **Windows machines under KVM** (Windows hardening, 9): the same harness
  with Windows guests from Microsoft's evaluation media, devices Windows
  has drivers for, a runner on the serial port, and a small domain; the
  images built in each run by jobs on `main` and on a schedule, never
  cached where a pull request's run can restore them; W1 decides whether
  CI can run them, else a self-hosted runner or recorded hand tests.
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
| 5 | Windows hardening (9): its ADR, revised after review, then W1, W2, W3 | Most managed computers run Windows; reuses step 3's job, permission and console (H3) while that work is fresh; W1 needs CI's Windows runners, the KVM decision with its domain, and a real Intune-enrolled Windows 11; it builds the ownership reader step 11 reuses |
| 6 | F2 and device alert notifications (7) | Needed by 4b, 5 and 3's alerts |
| 7 | Updater 4b: the console | Needs F2 |
| 8 | Let's Encrypt 5a, then 5b1 to 5b4 | Needs F2 for its alerts |
| 9 | Packages (6): DEB, RPM, MSI | How MSPs onboard computers; nothing depends on 3 |
| 10 | F0; F1 (ADR-0058); the WebSocket (8, ADR-0059) | The agent learns from a signed setting whether to connect, so F1 comes first (proposed by ADR-0058) |
| 11 | Log collection (3), in its slices | The largest; needs F1 and F2; it sets the Windows audit policy that step 5 only reports, with step 5's ownership reader |
| 12 | Moving to a new name (5c), its ADR first | Needs F0 |

Each step ends with CI green, a merge, and the test instance on the new
code.

## Risks

* **Hardening locks someone out or breaks a service**: the revised ADRs'
  guards, a scenario for every guard (ADR-0051's and ADR-0054's lists,
  with those only real computers can show run on real computers before
  the feature is called complete, and any stand-in named as one), undo
  without the agent.
* **Windows hardening breaks remote support or line-of-business software**
  (scanners on SMB, NTLM-only devices, technicians elevating in a user's
  session): risky modules are not recommended and state what they break,
  RDP and UAC changes wait for tests through EasyRMM's own remote access,
  settings someone else owns are left alone, and undo works without the
  agent.
* **Windows hardening and log collection fight over audit policy**: log
  collection sets it from one table, hardening only reports against that
  table, and both use the one ownership reader; log collection raises no
  alert for the changes a hardening job made.
* **Logs take EasyRMM down**: a PostgreSQL instance of its own outside
  the data root, quotas per kind of computer, a share per organization, a
  size cap and a disk floor that stop ingest before the disk fills, and a
  server-wide limit on searches.
* **The updater is root on the host**: it takes nothing but a version from
  the server, writes nowhere the server can, and installs only what it
  verified.
* **A key rotation strands agents, or leaves a leaked key trusted** (F0):
  devices move only on their own signed reports, a device on a compromised
  key is moved to the newest cut-over key before anything else, the
  updater refuses a rollback across a cut-over, a server from before the
  ring can neither start on its database nor be running during a
  rotation, a device left on a key a restore lost moves with the next
  rotation, and `trust-key` or a reinstall covers the devices that cannot
  follow.
* **A stolen administrator session redirects agents**: moving names needs
  signatures over the agent's own nonce, step-up authentication, and a
  notice to every super administrator.
* **Middleboxes break WebSockets**: automatic fallback, the HTTPS
  heartbeat kept on every transport, and jobs only ever delivered by the
  signed poll (ADR-0059).
* **Packages fight self-update**: the package never replaces the running
  agent.
* **Organizations' webhooks reach into a network**: every connection
  checked and none shared between channels; private ranges and the
  server's own networks only once approved for that channel; the server
  itself never (ADR-0053).
* **Notifications storm, go missing or stop alerting**: site outages,
  digests, fair share and the restart grace keep a power cut to a few
  messages; a failing channel raises a notice; planning runs apart from
  `Evaluate`, so a failure in it never stops alerts (ADR-0053).
* **Windows is unverified in CI** until the Windows end-to-end harness
  exists: every Windows path says so until then.
