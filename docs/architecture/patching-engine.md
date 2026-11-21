# Patching engine

EasyRMM patches Windows and Linux computers with its built-in patching
engine, EasyPatch. The engine is a .NET API and a .NET worker that run in
every EasyRMM deployment, on loopback, next to EasyRMM's server. It keeps
the update catalog, each endpoint's update state, patch policy, patch jobs,
compliance, vulnerability data, alerts and monthly reports. It has no
console, no user accounts and no API tokens of its own: people patch from
EasyRMM's console, and EasyRMM calls the engine for them with a signed
statement per request
([ADR-0038](adr/0038-statements-to-the-patching-engine.md)).

On each managed computer the EasyPatch agent (a Windows service or a Linux
systemd service) scans for updates and installs the ones policy or an
administrator approves. EasyRMM's own agent installs it
([ADR-0031](adr/0031-easypatch-agent-install.md)), and it reaches the
engine through EasyRMM's TLS edge, on EasyRMM's name
([ADR-0039](adr/0039-agents-on-easyrmms-name.md)).

The code is in `easypatch/` of this repository. Related pages:

* [Patching](../operations/patching.md): the console, permissions, audit
  and limits.
* [The EasyPatch agent](../deployment/patching-agent.md): installing,
  running and troubleshooting the agent.
* [Docker deployment](../deployment/docker.md#patching-engine): the
  engine's services and data.

![The patching engine: EasyPatch agents reach it only through EasyRMM's address; the EasyRMM server passes their routes to the engine's API on loopback and sends it a signed statement per console request; the API and the worker share the engine's PostgreSQL database, set up by a one-shot migration, and only the worker connects out, for vulnerability feeds, mail and webhooks](../images/diagrams/patching-engine.svg)

## Components

| Service (Compose) | Image | What it does |
|---|---|---|
| `easypatch-db-init` | EasyRMM's PostgreSQL image | Creates the `easypatch` database and its roles in EasyRMM's PostgreSQL, or brings them up to date. Runs before every start |
| `easypatch-migrate` | `easypatch-server` | Applies the EF Core migrations as `easypatch_owner`, then exits |
| `easypatch-api` | `easypatch-server` | ASP.NET Core API on `127.0.0.1:18180`, as `easypatch_app`. Serves EasyRMM's calls, the agent protocol and the agent package downloads |
| `easypatch-worker` | `easypatch-server` | Background tasks ([table below](#worker-tasks)), health on `127.0.0.1:18181`. The only part of the engine that opens outbound connections |

* **Network.** Host networking, loopback only. EasyRMM's edge forwards
  the agents' paths (`/api/v1/agents/`, `/downloads/agent/`,
  `/downloads/winget/`) to the API and nothing else of it. It removes
  cookies, `Forwarded` and the statement header, sets `X-Forwarded-For`,
  and serves the answers sandboxed and never sniffed.
* **Database.** The `easypatch` database lives in the same PostgreSQL
  instance as EasyRMM's. `easypatch_owner` owns the schema; the API and
  worker connect as `easypatch_app`. Passwords are in EasyRMM's `.env`.
* **Data** under `${EASYRMM_DATA_ROOT}/easypatch/`: `keys` (ASP.NET Data
  Protection keys that encrypt the SMTP password, webhook URLs and webhook
  signing keys; the API creates and rotates them, the worker mounts them
  read-only) and `winget` (the engine's verified copy of the pinned winget
  release; the worker writes it, the API reads it).
* **Agent packages** come with the engine's image, each with its release
  signature, read-only
  ([ADR-0041](adr/0041-agent-packages-in-the-engine-image.md)). The engine
  is released with EasyRMM, built from the same commit
  ([ADR-0043](adr/0043-one-release.md)).
* **Hardening.** The .NET containers run as the non-root `app` user (UID
  1654) with a read-only root filesystem, every capability dropped and
  `no-new-privileges`. The API sends `X-Content-Type-Options: nosniff` and
  `Cache-Control: no-store` on `/api`, sets no cookies and allows no CORS.
* **Health.** API: `/health/live` (process up) and `/health/ready`
  (database reachable). Worker: `/health` (database, and a heartbeat per
  task; a task is stalled after three intervals plus two minutes). The edge
  forwards none of them.
* **Logs.** JSON to stdout, with a correlation ID on every request
  (`X-Correlation-ID`, accepted from the caller or generated, returned on
  every response and in error bodies).

### Source layout

| Path under `easypatch/` | Contents |
|---|---|
| `shared/EasyPatch.Contracts` | Wire DTOs, enums, request signing and the update classifier, shared by agent and server |
| `backend/Core` | Entities and pure domain logic: reconciliation, compliance, policy, requirement, lifecycle |
| `backend/Infrastructure` | EF Core context and migrations, services, worker tasks, notifications, reports, vulnerability feeds |
| `backend/API` | API host: endpoints, statement and agent authentication, rate limits, the `migrate` and `prepare-import` commands |
| `backend/Worker` | Worker host |
| `backend/Tests` | Unit and integration tests (Testcontainers PostgreSQL) |
| `agent/EasyPatch.Agent.Core` | Platform-independent agent runtime: scheduler, jobs, outbox, state |
| `agent/EasyPatch.Communication` | Signed HTTPS client for the agent protocol |
| `agent/EasyPatch.WindowsUpdate`, `agent/EasyPatch.Inventory`, `agent/EasyPatch.Agent` | Windows: Windows Update Agent (WUA) integration, WMI and registry inventory, the service, tray and CLI |
| `agent/EasyPatch.Linux`, `agent/EasyPatch.Agent.Linux` | Linux: apt and dnf backends, package ledger, inventory, the systemd service and CLI |
| `agent/EasyPatch.MacOS`, `agent/EasyPatch.Agent.MacOS` | macOS (experimental, not released) |
| `agent/Installer` | WiX MSI project, `.deb` and `.rpm` metadata, systemd unit |
| `tools/EasyPatch.ReleaseSigner` | Creates the release key, signs and verifies agent packages |
| `deployment/server` | The server image's Dockerfile |

## Division of work

| Concern | Owner |
|---|---|
| Organizations, sites, users, roles, general hardware and software inventory | EasyRMM |
| Update catalog, per-endpoint update state, patch policy, maintenance windows, rings, patch jobs, restarts | The engine |
| Installing and enrolling the EasyPatch agent where there is none | EasyRMM's agent, with a package from the engine and a single-use enrollment token |
| Updating the EasyPatch agent | The engine |

EasyRMM never writes `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
and has no Windows Update run or system-wide apt or dnf upgrade of its own:
its software actions install, update or remove one named package
([ADR-0028](adr/0028-software-deployment.md)). It restarts computers only
through the engine's restart jobs. Scripts can still patch a system; the
script library warns about such scripts
([Scripts and jobs](../operations/scripts-and-jobs.md#scripts-that-install-updates)).

## How EasyRMM calls the engine

### Statements from EasyRMM

Every call from EasyRMM's server carries a statement in
`X-EasyRMM-Assertion`, and the engine's administrator API accepts nothing
else ([ADR-0038](adr/0038-statements-to-the-patching-engine.md)):

* **Format.** A JWT signed with HMAC-SHA256: header `typ`
  `easyrmm-gateway+jwt`, issuer `easyrmm`, audience `easypatch`. The key is
  `EASYRMM_PATCHING_KEY` in EasyRMM's `.env` (base64, at least 32 bytes),
  which the engine reads as `EasyRmm__GatewayKey`. Without a key the API
  refuses every statement; a key that is set but unusable stops the API at
  start.
* **Claims.** Who the call is for (an EasyRMM user's id and name, or
  `service` for EasyRMM's own work), the role that call needs, the
  organizations it may touch (`"*"` or a list), and the method (`htm`) and
  request target (`htu`) it was made for.
* **Lifetime.** EasyRMM makes each statement valid for 30 seconds. The
  engine refuses one valid for longer than 60 seconds and allows 5 seconds
  of clock difference.
* **Refusals.** A request with more than one statement, or with one that
  does not verify, has expired or was made for another request, answers
  `401` whatever else it carries. A request without a statement answers
  `401`. The log records the reason, never the statement.
* **Roles.** EasyRMM checks its own permissions first and then names the
  engine role the call needs. The engine checks it again:

  | Engine role | Used for |
  |---|---|
  | `ReadOnly` | Reads |
  | `Admin` | Changes within organizations: endpoints, jobs, restarts, messages, policies, exclusions, holds, reports |
  | `SuperAdmin` | What spans the engine: the global policy, tags, server settings, alert rules, notifications, the OS lifecycle table, holds for every organization |

  A statement reaches every organization only with `"*"`. A list reaches
  those organizations; a list whose organizations were all deleted reaches
  none. Anything outside them answers `404`.
* **Audit.** The engine's audit log, and the `requestedBy` of jobs, name
  the actor as `easyrmm:<name>`; its own commands appear as `cli`.

The API also serves its OpenAPI document at `/api/openapi/v1.json` to any
statement.

### API conventions

| Topic | Rule |
|---|---|
| Versioning | Administrator and agent routes are under `/api/v1`. JSON is camelCase, enums are strings, times are ISO 8601 UTC |
| Errors | RFC 9457 `application/problem+json` with `code` and `correlationId`; validation errors (`400 validation_failed`) add `errors`. Some carry more, such as `existingJobId` on `409 duplicate_job` |
| Lists in agent requests | A list left out reads as empty; `null` for a list, anywhere in the body, gets `400 validation_failed` naming it |
| Paging | `?page=&pageSize=` (at most 200), answered as `{items, page, pageSize, totalCount}` |
| Rate limits | Enrollment 30 a minute per IP; agent routes 120 a minute per credential; downloads 60 a minute per IP; administrator routes 600 a minute per EasyRMM user and 6,000 for `service`. Over the limit: `429 rate_limited` with `Retry-After`. Configurable with `RateLimits:*` |
| Body size | At most 16 MiB (20 MiB through the edge) |

### One set of organizations

Every EasyRMM organization and site has its own in the engine, created,
renamed and archived with EasyRMM's
([ADR-0040](adr/0040-one-set-of-organizations.md)). EasyRMM pushes each
change as it happens, compares the whole set every 5 minutes, and retries
every minute while the engine refuses or is down. An endpoint belongs to
exactly one engine organization and at most one site, and cannot change
organization; EasyRMM moves endpoints between sites of one organization
only. The console side is in
[Organizations in the engine](../operations/patching.md#organizations-in-the-engine).

### Device links

EasyRMM links one of its devices to one engine endpoint, never by host
name alone:

1. The EasyRMM agent runs the EasyPatch agent's `status --json` and
   reports its server, endpoint id, key fingerprint, status and version
   with its inventory.
2. EasyRMM links the device only when the EasyPatch agent is `Active`;
   it is enrolled with this deployment's engine; the engine has the
   endpoint, active, in the organization that belongs to the device's;
   one of the endpoint's active credentials has the reported fingerprint;
   the short host names match; the serial numbers match when both are
   known; and no other device is linked to the endpoint.
3. Anything else is shown to administrators with the reason, and nothing
   is merged. Refused devices are checked again every 15 minutes and when
   their report changes; linked ones every six hours.

### Mail

The engine sends alert notifications and monthly reports through
EasyRMM's mail server, the console's or `.env`'s
([Mail](../operations/mail.md)): EasyRMM's reconciler writes it into the
engine's notification settings at start and on every change (`syncMail`,
`server/internal/easypatch/engine.go`, ADR-0053). On each pass it compares
the settings, the password included, with those it last gave, so an
unchanged mail server is not written again; a change in the console kicks
a pass at once. The engine keeps the SMTP password encrypted with its Data
Protection keys and never returns it.

## Agent protocol

The agent makes outbound HTTPS requests only. On EasyRMM's name, the edge
passes them to the API.

| Method | Route (`/api/v1/agents`) | Auth | Purpose |
|---|---|---|---|
| POST | `/enroll` | Enrollment token in the body | Registers the agent's public key. Answers `Active` with the endpoint id, credential `c_…` and config. A request that carries a code, as agents up to 1.11.1 could, gets `400 deployment_codes_retired` and uses no token ([ADR-0048](adr/0048-the-engine-keeps-what-is-reached.md)) |
| POST | `/enrollment/status` | None | Always `401 unknown_credential`. Agents up to 1.11.1 poll it while waiting for approval; the answer makes them enroll again, be refused and stop |
| POST | `/check-in` | Signed | Heartbeat and job poll in one. Sends version, boot time, restart state and reasons, held job ids, current activity, capabilities, signed-in user and tray counts, Windows Update policy status, package architecture and format, built-in release key ids and winget status. Answers server time, config, at most one newly leased job plus up to five messages and re-deliveries, job ids to cancel, `rotateCredential`, newest agent version |
| POST | `/inventory` | Signed | OS and hardware inventory; on Linux also distribution, kernel, package manager and key protection |
| POST | `/updates/scan-results` | Signed | Full scan snapshot. Idempotent by `scanId` |
| POST | `/updates/history` | Signed | Windows Update history, deduplicated on the server |
| POST | `/jobs/{jobId}/ack` | Signed | Confirms receipt; `409 job_cancelled` if it was cancelled or finished |
| POST | `/jobs/{jobId}/status` | Signed | Progress, per-update results and final status, with a per-job `sequence`; stale or repeated reports are ignored, impossible transitions answer `409 invalid_transition` |
| POST | `/credentials/rotate` | Signed with the current key | Registers a new key; the old credential stays valid for one hour |
| POST | `/unenroll` | Signed | Sent on uninstall: decommissions the endpoint and revokes its credentials |

Downloads, outside `/api/v1`, need no credential: `GET
/downloads/agent/{file}` serves an agent package, and `GET
/downloads/winget/{file}` one of the three pinned winget files (see
[Installing winget](#installing-winget)).

### Request signing

After enrollment every request carries:

| Header | Value |
|---|---|
| `X-EasyPatch-Credential` | `c_…` |
| `X-EasyPatch-Timestamp` | Unix seconds |
| `X-EasyPatch-Nonce` | 128 random bits, base64url |
| `X-EasyPatch-Content-SHA256` | Lowercase hex SHA-256 of the exact body |
| `X-EasyPatch-Signature` | ECDSA P-256 with SHA-256, IEEE P1363 format, base64 |

The signature covers these lines joined by `\n`:

```text
EASYPATCH-ECDSA-P256-SHA256
<HTTP method>
<path and query exactly as sent>
<timestamp>
<nonce>
<content sha256>
<credential id>
```

The API requires the timestamp within ±300 seconds (a refusal carries the
server time, so the agent corrects its offset), each nonce once per
credential within that window, a matching body hash, a valid signature
against the stored public key, and a credential that is neither expired
nor revoked on an active endpoint. The endpoint and organization come from
the credential, never from the body: an agent cannot name another endpoint,
and jobs are checked against the endpoint before they are acknowledged or
updated.

Refusals are `401` with `invalid_signature`, `clock_skew` (with
`serverTime`), `replayed_nonce`, `unknown_credential`,
`credential_revoked`, `credential_expired` or `endpoint_revoked`.

Signed requests rather than client certificates: mutual TLS would end at
EasyRMM's edge, which would then have to vouch for the agent, and bearer
tokens or HMAC keys would make the engine hold reusable secrets. With
per-device keys the engine holds nothing that lets anyone act as an agent.

### Agent credentials

* **Key.** The agent makes an ECDSA P-256 key pair at its first start and
  sends only the public key. Windows keeps the private key in
  `C:\ProgramData\EasyPatch\agent.key`, protected with DPAPI (LocalMachine)
  in a folder only SYSTEM and Administrators can open. Linux keeps it in
  `/var/lib/easypatch` (root only), encrypted with `systemd-creds` and the
  host key on systemd 250 and later, otherwise protected by file
  permissions.
* **Enrollment.** EasyRMM enrolls each agent with a single-use enrollment
  token it creates for that one install: valid for an hour, for the
  engine's organization and site that belong to the device's. The engine
  stores only the token's SHA-256. There is no other way to enroll.
* **Rotation.** Credentials last 365 days by default. Check-in asks the
  agent to rotate within 30 days of expiry; the agent signs the new key
  with the old one. Rotation is idempotent per key.
* **Revocation.** Revoking an endpoint revokes all its credentials at once
  and evicts them from the credential cache; the agent stops and backs
  off. It needs a new enrollment to come back.

## Data model

Organizations contain sites, and sites contain endpoints. Each
organization and site has a time zone, used for maintenance windows,
restart schedules and monthly reports.

| Tables | Notes |
|---|---|
| `organizations`, `sites` | Active flag and `archived_at`; archiving is preferred to deleting |
| `endpoints` | Identity, OS and hardware inventory, agent version and capabilities, check-in, scan and inventory times, restart state and reasons, signed-in users and trays, update source, Windows Update policy status, OS support status, denormalized compliance counters |
| `agent_credentials` | Public id `c_…`, public key only, expiry, revocation, `replaced_by` |
| `enrollment_tokens` | Token hashes with scope, uses and expiry |
| `updates` | The catalog, keyed by (`update_guid`, `revision_number`): KBs, title, classification, category, products, severity, size, restart behaviour, superseded ids; Linux package, version and source package; CVE summary |
| `endpoint_updates` | Per-endpoint state, unique by (`endpoint_id`, `update_guid`), with requirement, deferral, error, CVEs, `known_exploited` and the KEV due date |
| `update_scans`, `update_history_entries` | One row per scan (`agent_scan_id` unique per endpoint); Windows Update history, deduplicated |
| `update_exclusions`, `update_holds` | Per-endpoint exclusions; holds per organization or for every organization |
| `jobs`, `job_updates` | The durable job queue (lease and delivery tracking, `jsonb` payload and result, `sequence`, dedupe key, `xmin` concurrency token) and per-update results |
| `policies`, `tags`, `endpoint_tags`, `site_tags`, `organization_tags` | Policy rows per level; MSP-wide tags |
| `server_settings`, `os_lifecycle_entries` | One `jsonb` row of global settings; the editable lifecycle table |
| `compliance_snapshots` | Daily counters per organization |
| `vulnerabilities`, `msrc_kb_cves`, `msrc_build_fixes`, `debian_fixes`, `vulnerability_feeds` | Downloaded vulnerability data and each feed's state |
| `alert_rules`, `alerts`, `notification_channels`, `notification_settings`, `notification_deliveries` | Alert rules and alerts, channels, SMTP settings, the delivery outbox |
| `report_schedules`, `generated_reports` | Monthly report schedules and PDFs with their email state |
| `endpoint_events`, `audit_logs`, `mirror_states` | Per-endpoint activity, administrative audit trail, the winget copy's download state |

## Update catalog and scans

A scan reports the full list of missing and installed updates.
`ScanIngestionService` applies it with `UpdateReconciler`
(`backend/Core/Domain/UpdateReconciler.cs`), a pure function, so the same
report twice changes nothing.

### Update states

The endpoint layer (`endpoint_updates.state`) records what is true on the
computer. Only scans and final install results change it:

| State | Meaning |
|---|---|
| `Missing` | Applicable and not installed, per the latest scan |
| `Failed` | Missing, and the last install attempt failed (the error is kept) |
| `PendingVerification` | The agent reported a successful install; no scan has confirmed it yet |
| `PendingReboot` | Installed, but Windows needs a restart to finish |
| `Installed` | A scan listed it as installed: the only way to `Installed` |
| `Superseded` | Replaced by another applicable update |
| `NotApplicable` | Previously reported, now in neither list and not superseded |
| `Excluded` | Excluded on the endpoint or by a policy KB list |
| `Reoffered` | Windows reported a successful install without a restart, but the next scan offers the same revision again. Not counted for compliance and left out of automatic installs; a new revision makes it `Missing` |

The job layer (`job_updates.status`) records progress: `Pending`,
`Downloading`, `Downloaded`, `Installing`, `Succeeded`, `Failed`, `Skipped`
(with a reason) and `Cancelled`, with download and install percentages.
Views overlay live job progress on the endpoint layer, so a crashed job
never leaves an update stuck in "Downloading".

### Categories

`EasyPatch.Contracts.Updates.UpdateClassifier` decides, first match wins:

1. **Driver**: WUA type Driver, or the Drivers classification
2. **Feature**: the Upgrades classification, or a title starting "Feature update to"
3. **Definition**: the Definition Updates classification
4. **ServicingStack**: title contains "Servicing Stack Update"
5. **DotNet**: title or product contains ".NET"
6. **Cumulative**: title contains "Cumulative Update"
7. **Security**: the Security Updates classification
8. **Critical**: the Critical Updates classification
9. **Other**: everything else

The Microsoft classification is stored as well. A Linux package upgrade
is **Security** when apt found it in a `*-security` suite or a dnf
security advisory covers it, and **Other** otherwise; it is one catalog
entry per distribution release, package, architecture and version, so the
same upgrade on fifty servers is one update. **Application** is used only
for winget updates (see [Application updates](#application-updates-winget)),
which policy approves by package ID rather than by category.

### Required updates

`backend/Core/Domain/UpdateRequirement.cs` decides whether an update is
required on an endpoint, for scan ingestion, recomputation, the install
preview and the scheduler. It is required when its category is allowed by
policy, it is not optional (unless optional updates are on), it is not
excluded, and its rollout delay has ended. Only required updates count for
compliance.

The rollout delay has two values: security updates (Microsoft's Security
Updates classification, which includes the monthly cumulative updates, and
Linux security upgrades; 0 to 90 days) and every other update (0 to 365
days). Definition updates are never delayed. The delay counts from when
the update was first seen anywhere in the fleet; an update that replaces
an older one still outstanding on the endpoint keeps the older one's start
(`delay_basis_at`), so a monthly cumulative update does not restart the
delay each month. While the delay runs, `deferred_until` holds its end; the
worker re-evaluates deferred updates every 10 minutes. An update that fixes
a known-exploited vulnerability skips the delay unless the policy's
`knownExploitedSkipsDelay` is off. A policy or tag change recomputes the
affected endpoints at once.

## Policy

The effective policy resolves **global → organization → site → tags →
endpoint**. Scalars take the most specific non-null value; excluded KB
lists merge. Tags are MSP-wide; an endpoint has its own tags plus those of
its site and organization. When several tags carry policies they apply in
ascending priority (the highest wins; on a tie, the alphabetically first
name). Tag and endpoint policies cannot set the per-site install limit.

| Field | Global default |
|---|---|
| Check-in / scan / inventory interval | 60 s (15 s while a job is active) / 360 min / 1,440 min, each ±10 % |
| Allowed categories | All but Driver and Feature |
| Optional updates, accept EULAs | Off, on |
| Automatic installs | **Off**; installs only inside the maintenance window (days, start, length, in the site's or organization's time zone) |
| Download before the window | 0 hours (off); up to 24 |
| Scan out of date after | 48 h |
| Installs at once per site | 10 (the global limit, a server setting, is 50) |
| Rollout delay | 0 days for both |
| Tray icon, install notifications | Shown, on (Windows) |
| Restart schedule | None |
| Windows Update settings | Each group *Not configured* |
| Agent updates | Automatic |
| Application updates | Off |

**Restart schedules** set days, a time, a condition (always, or only if a
restart is pending), a restart mode and an expiry of 15 minutes to 24
hours. Every 2 minutes the worker creates at most one `Restart` job per
endpoint and occurrence, unless one is already active; it expires with the
occurrence, so a computer that was off is not restarted later.

**Windows Update settings** are resolved group by group: a level inherits,
leaves the group alone (*Not configured*), or manages it, in which case the
engine decides every value of that group under
`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`:

| Group | Registry values |
|---|---|
| Automatic Updates | `AU\NoAutoUpdate`, `AU\AUOptions`, `AU\ScheduledInstallDay`, `AU\ScheduledInstallTime` |
| Feature updates | `DeferFeatureUpdates`, `DeferFeatureUpdatesPeriodInDays`, `TargetReleaseVersion`, `ProductVersion`, `TargetReleaseVersionInfo` |
| Quality updates | `DeferQualityUpdates`, `DeferQualityUpdatesPeriodInDays`, `SetDisablePauseUXAccess` |
| Restart behaviour | `AU\NoAutoRebootWithLoggedOnUsers`, `SetActiveHours`, `ActiveHoursStart`, `ActiveHoursEnd` |

`WUServer`, `WUStatusServer` and `UseWUServer` are never written. The agent
saves a group's values before its first change, reports `Applied`, and
compares at each check-in. If another source (Group Policy, Intune, a
script) changed a value, it reports `Conflict` and stops re-applying that
group. When a group is no longer managed, on uninstall and on revocation
it restores the saved values, except those another source changed since.
The report includes whether MDM update policies are present.

## Jobs

| Type | What the agent does |
|---|---|
| `UpdateScan` | Scans and reports |
| `InventoryRefresh` | Nothing any more: the engine no longer queues it and the agent refuses one ([ADR-0048](adr/0048-the-engine-keeps-what-is-reached.md)). The type stays so earlier jobs still show in history |
| `InstallUpdates` | Fresh scan, filter by the payload, then download and install one update at a time (Linux: one apt or dnf transaction), then scan again |
| `DownloadUpdates` | Downloads, ahead of a maintenance window, what the window would install (Windows) |
| `UninstallUpdate` | Removes one installed Windows update |
| `Restart` | Restarts the computer, with the chosen warning |
| `NotifyUser` | Shows a preset message to signed-in users (Windows) |
| `AgentUpdate` | Installs a newer, release-signed agent package |
| `UninstallAgent` | Removes the agent's own package |

![A patch job's lifecycle: queued, leased to the EasyPatch agent at its next check-in, acknowledged and run; it may wait for a restart and run again, goes back to the queue when a lease expires (at most five deliveries by default), and ends completed, failed, cancelled or expired](../images/diagrams/patch-job-lifecycle.svg)

* **Durable.** Job state lives in PostgreSQL; the agent also keeps the job
  it is running in its state file and resumes it after a restart.
* **Delivery and leases.** A check-in leases the next job with `SELECT … FOR
  UPDATE SKIP LOCKED` in a transaction, so two API instances never deliver
  one job. A delivered job not acknowledged within 10 minutes returns to
  `Queued`; after 5 deliveries it fails. If an agent reconnects without a
  job the engine considers active (after a reinstall, say), the job is
  delivered again.
* **One job at a time.** Nothing new is delivered while a job is
  delivered, acknowledged or running. `NotifyUser` jobs are the exception
  (up to five per check-in). While an install waits in `WaitingForReboot`,
  scans and inventory still run but further installs wait. Queued jobs go
  in this order: scans, update removals, installs, downloads, restarts,
  agent updates.
* **Capabilities.** Agents report what they support (`restart`,
  `notify-user`, `tray`, `windows-update-policy`, `self-update`,
  `app-updates`, `uninstall`, `uninstall-updates`, `download-updates`). Jobs
  that need one are created and delivered only for agents that report it;
  otherwise the API answers `409 agent_upgrade_required`.
* **Limits.** Installs are delivered only while the global and per-site
  limits allow, checked under a transaction-scoped advisory lock. Downloads
  take no install slot but respect the per-site limit.
* **Deduplication.** A partial unique index on (`endpoint_id`,
  `dedupe_key`) over active statuses blocks duplicates (`409
  duplicate_job`, with `existingJobId`) unless the caller passes `force`.
* **Idempotency.** An install starts with a fresh scan and skips anything
  installed, so running it again after a crash is safe. Reports carry a
  rising `sequence`.
* **Timeouts and expiry.** Queued jobs expire after 7 days; scheduled
  installs when their window closes; a scheduled job (`scheduledAt`, up to
  31 days ahead) is not delivered before its time. A running job with no
  progress for 12 hours fails with `timed_out`, and a later genuine result
  still replaces that. A job in `WaitingForReboot` fails after 30 days.
  These values are server settings.
* **Restarts after installs.** `WaitingForReboot` is used only when Windows
  reports `RebootRequiredBeforeInstallation`; the job continues after the
  restart. When installs succeed but need a restart to finish, the job
  completes with `reboot_required`. Installs never restart the computer.
* **Retry and cancel.** A finished job can be retried as a new job with the
  same parameters (`DownloadUpdates` cannot). Cancelling is immediate for
  queued, delivered or waiting jobs; a running install stops before the
  next update.

### Restart jobs

| Mode | What signed-in users see |
|---|---|
| `Immediate` | Nothing |
| `Countdown` | A countdown of 1 to 60 minutes (default 5); they can only restart sooner |
| `PromptWithDeadline` | *Restart now* or *Postpone* (1 hour, 4 hours, 1 day, never past a deadline of 15 minutes to 7 days, default 4 hours); then a 5-minute countdown |
| `PromptNoDeadline` | The same without a deadline; fails with `restart_not_performed` after 7 days |

With the *only if pending* condition the agent checks the restart state
when the job starts and completes without restarting if none is pending.
A computer nobody is signed in to restarts at once. Without a tray, a
countdown uses the operating system's own shutdown warning. The agent asks
Windows to restart (`InitiateShutdown`, planned "Operating System: Hot
fix" reason) or runs `shutdown -r +N` on Linux, and completes only when it
sees a new boot time; otherwise the job fails with `restart_not_performed`
30 minutes after the request plus any warning. A restart job expires if
the computer has not picked it up within its expiry (default 2 hours).
"Restart all that need it" on an organization or site restarts only the
confirmed endpoints that still report a pending restart, always with *only
if pending*.

### Agent update jobs

An `AgentUpdate` job carries the package's file name, version,
architecture, size and SHA-256, the release key id and the signature from
the package's `.sig` file. The engine never signs anything. An Operator
starts one, or the worker task `agent-updates` does every 2 minutes for
online endpoints whose *Agent updates* policy is Automatic: it picks the
newest package for the agent's architecture and format that is newer than
the installed agent and signed with a key the agent reported, runs at most
`EasyPatch:AutomaticAgentUpdateConcurrency` (default 25) at once, waits 6
hours after a failure and stops after 3 failures of a version. The agent's
checks are in [Agent release signing](#agent-release-signing).

After an upgrade, EasyRMM's host updater holds automatic agent updates for
24 hours ([ADR-0052](adr/0052-the-host-updater.md)): it writes the time
they may start again, in RFC 3339 (`2026-11-22T07:00:00Z`), to
`agent-updates-held-until` in its status directory, which the worker reads
at `EasyPatch:UpdaterStatusPath` (default `/run/easyrmm-updater`,
read-only; the worker's user, UID 1654, must be able to read both). Until
that time the task queues nothing, and logs when a hold begins, changes
and ends. Without the file or the directory, or once the time has passed,
nothing is held. A file the worker cannot read, or that holds anything but
one time, holds updates and is logged as an error at every run until it
is corrected or removed. Updates an Operator starts, and retries of
finished agent update jobs, are not held.

### Update removal jobs

`UninstallUpdate` removes one installed Windows update (agent capability
`uninstall-updates`). The payload is the update id, title, KB number
(digits only) and category. The agent uses Windows Update's own uninstall
when the update allows it, otherwise DISM (`/Get-Packages`,
`/Get-PackageInfo`, `/Remove-Package /NoRestart` for the KB's package, or
for a cumulative update the `Package_for_RollupFix` matching its build).
It never restarts: a removal that needs a restart completes with
`reboot_required`. It fails with `update_not_removable` (permanent
packages, most definition updates), `update_still_installed`, a DISM exit
code, or `dism_failed`. By default the update is also excluded on the
endpoint. A scan follows; the update's state changes only through scans.

### Downloads before the window

With automatic installs and *Download before the window* above 0, the
worker task `pre-downloads` (every 10 minutes) queues one `DownloadUpdates`
job per endpoint and window when the window opens within that many hours
and at least 15 minutes from now. It lists what the window would install,
without held updates, and expires when the window opens; items not reached
are skipped with `WindowStarted`. Downloads change no update state,
compliance or rollout guard counts.

### Uninstall jobs

`UninstallAgent` has no payload. The agent removes its own package and
nothing else: `msiexec /x` of the product found by the MSI's fixed upgrade
code, or `apt-get remove easypatch-agent` / `rpm -e easypatch-agent` in the
transient unit `easypatch-agent-uninstall`. The package's removal step runs
`unenroll`, and the job completes when that unenrollment arrives: the
endpoint becomes decommissioned and its other open jobs are cancelled.

## Compliance

`backend/Core/Domain/ComplianceCalculator.cs` gives every active endpoint
one status, from its last successful scan and restart state; the first
match wins:

| # | Status | Condition |
|---|---|---|
| 1 | `NeverScanned` | No successful scan yet |
| 2 | `ScanStale` | The last successful scan is older than the policy's *scan out of date after* (default 48 hours) |
| 3 | `FailedUpdates` | A required update is `Failed` |
| 4 | `MissingUpdates` | A required update is `Missing`, `Failed` or `PendingVerification` |
| 5 | `RebootRequired` | A restart is pending, or an update is `PendingReboot` |
| 6 | `Compliant` | None of the above |

Old or missing data is never compliant, a failure ranks above a missing
update, and an update is not counted as secured until its restart is done.
Being offline does not change compliance by itself; an endpoint that stays
offline becomes `ScanStale`. The worker re-checks staleness every minute.
`Superseded`, `NotApplicable`, `Excluded` and `Reoffered` updates and
updates inside their delay never count (deferred ones are counted
separately).

* **Percentage** = compliant ÷ active endpoints × 100, one decimal;
  revoked and decommissioned endpoints are excluded.
* **Snapshots.** Every 30 minutes the worker writes, per organization and
  UTC date, the count per status, the number offline and the missing
  required updates. The day's last write stands. Snapshots are kept as
  long as the audit log (default 365 days).
* **OS support status** is separate from compliance: `Supported`,
  `ExtendedSecurityUpdates` (past end of servicing, covered by an ESU the
  agent detected or an administrator set; for Ubuntu, Ubuntu Pro ESM),
  `Unsupported`, or `Unknown` (not in the lifecycle table).
  `LifecycleEvaluator` matches Windows by product, edition group and build,
  and Linux by distribution and major release (Ubuntu by `YY.MM`), against
  the editable `os_lifecycle_entries`, seeded with the vendors' published
  dates.

## Vulnerability data

The worker task `vulnerability-feeds` runs hourly and downloads what is
due (`VulnerabilityFeedService`):

| Feed | Interval | Stored as |
|---|---|---|
| CISA Known Exploited Vulnerabilities (`www.cisa.gov`, fallback `raw.githubusercontent.com/cisagov/kev-data`) | 6 hours | `vulnerabilities.kev`, dates, ransomware flag |
| MSRC CVRF documents of the last 12 months (`api.msrc.microsoft.com`) | Daily; only documents whose `CurrentReleaseDate` changed | `vulnerabilities` (title, severity, CVSS, exploited), `msrc_kb_cves`, `msrc_build_fixes` |
| Debian Security Tracker (`security-tracker.debian.org`, streamed) | Daily while Debian 12 or 13 endpoints exist; sooner (at most every 6 hours) when they report new source packages | `debian_fixes`, for the releases and source packages in use |

`VulnerabilityMatcher` sets `cve_ids`, `known_exploited` and `kev_due_date`
on open endpoint updates during scan ingestion and recomputation, before
the requirement flags. Windows updates get the CVEs of their KB numbers,
and the security cumulative update also those MSRC fixed in later
revisions of the endpoint's build. Debian upgrades get the CVEs fixed in
their source package between the installed and the offered version.
RHEL-family and Fedora upgrades keep the CVEs the agent read from dnf
advisories. Ubuntu upgrades get none yet. At most 200 CVEs are kept per
update. Only the CISA catalog marks an update known-exploited.

The hosts are built in; requests are plain GETs over HTTPS without
credentials or endpoint data, with no redirects and normal certificate
validation. Documents are parsed as data with size limits (32 MB for KEV
and the MSRC list, 128 MB per MSRC document, 512 MB for the Debian
tracker); MSRC document ids and CVE ids are validated. A failure is stored
as host and HTTP status, the previous data stays in use, and the feed is
retried after an hour. New data recomputes every active endpoint. A server
setting turns the downloads off.

## Holds and the rollout guard

A hold keeps an update out of automatic installs, in one organization or
in every organization (`update_holds`, at most one active hold per update
and scope). The install preview leaves held updates out of "install all"
jobs (skip reason `Held`); maintenance-window jobs do not list them, and a
scheduled job left with nothing is cancelled. An update an administrator
selects by hand is still installed, with a warning. The *Update on hold*
alert opens while an organization's endpoints still miss a held update.

The worker task `rollout-guard` (every 5 minutes, on by default) looks at
install jobs on Windows endpoints over the last 7 days, without
application updates, and takes each endpoint's latest result per update.
When an update failed on at least 3 endpoints and at least 20 % of those
that tried it, it holds the update for every organization, stating the
counts. Results from before a release of such a hold are not counted
again. The four values are server settings. The guard works best with a
pilot ring: a tag or site with a shorter rollout delay installs first.
Holds for every organization are placed and released by super
administrators only. Holding and releasing are audited.

## Reports

* **Compliance trend**: the daily snapshots for a period.
* **Installations**: one row per update of each install job (result, skip
  reason, error, restart, requester), paged.
* **Monthly reports**: a PDF per organization and calendar month (UTC
  dates), built by `MonthlyReportDataBuilder` and laid out by
  `ReportPdfRenderer` with PDFsharp/MigraDoc 6.2.4 (MIT) and the embedded
  Liberation Sans font, which covers Latin, Greek and Cyrillic. It holds a
  summary, the month's trend, a table per site, the 15 most widely missing
  required updates and, optionally, every endpoint (up to 5,000). PDFs are
  stored in `generated_reports` and deleted after the report retention
  (default 24 months). The worker task `monthly-reports` (every minute)
  makes scheduled reports from the organization's chosen day (1 to 28, in
  its time zone) and emails them with the PDF attached, only over STARTTLS
  or TLS, retrying for 24 hours. Reports over 15 MB are not emailed.

## Alerts and notifications

The worker evaluates the enabled rules every 2 minutes (task `alerts`) and
sends queued notifications every 30 seconds (task `notifications`).

| Rule type | Opens when | Default severity and threshold |
|---|---|---|
| `EndpointOffline` | No check-in for longer than the threshold | Warning, 24 hours (1 to 720) |
| `InstallFailed` | Updates whose last install attempt failed | Warning |
| `SecurityUpdateMissing` | A required security update still missing this many days after it became required | Critical, 14 days (0 to 365) |
| `ScanStale` | No successful scan within the policy's *scan out of date after* | Warning |
| `RestartPending` | A restart pending longer than the threshold | Info, 7 days (1 to 90) |
| `OsUnsupported` | The OS is out of support, or its support ends within the threshold | Warning, 30 days (0 to 365) |
| `KnownExploitedMissing` | An allowed update fixing a known-exploited vulnerability is missing (required or still deferred) | Critical |
| `UpdateHeld` | An update the organization's endpoints still miss is on hold (per organization) | Warning |

* **Rules.** The migrations seed one rule of each type, enabled and
  without channels. A rule can be limited to one organization and, for
  endpoint rules, to a tag. Rules of the same type work independently.
* **Lifecycle.** One unresolved alert per rule and subject (a partial
  unique index on `dedupe_key`). An alert resolves after two consecutive
  evaluations without a match; a match within an hour of resolving reopens
  it without a new notification. Offline endpoints raise only the offline
  alert. Disabling, deleting or rescoping a rule, archiving an organization
  or removing an endpoint closes alerts without notifications.
  Acknowledged alerts get no reminders.
* **Outbox.** Each evaluation writes at most one delivery per channel and
  kind (opened, resolved, reminder), listing up to 25 alerts. Failures are
  retried after 1, 2, 4… minutes, at most an hour apart, for 24 hours
  (tests: 3 attempts). Errors are stored without URLs or secrets.
* **Messages.** Subjects start with `[EasyRMM]`. Links lead into EasyRMM,
  whose address is the engine's public URL: an endpoint's alert to
  `/go/from-easypatch/endpoints/<id>`, an organization's to
  `/go/from-easypatch/alerts/<id>`, and the message to
  `/patching?tab=alerts`.
* **Channels.** Email (up to 20 recipients) or an `https://` webhook in
  Slack, Microsoft Teams Workflows (Adaptive Card) or generic JSON format.
  Webhook URLs and signing keys are encrypted at rest and never returned;
  the console shows the host only.
* **Generic webhooks.** `POST` JSON with `X-EasyPatch-Event`
  (`alerts.opened`, `alerts.resolved`, `alerts.reminder`, `test`),
  `User-Agent: EasyPatch/<version>` and `X-EasyPatch-Signature:
  t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">`, keyed with the
  channel's signing secret. The body has `event`, `deliveryId` (the same
  on retries), `sentAt`, `subject`, `summary`, `alerts[]` (`id` stable
  from open to resolve, `severity`, `title`, `organization`, `details`,
  `url`, `at`), `moreCount` and `consoleUrl`. Any `2xx` counts as
  delivered; other answers, timeouts (30 seconds) and redirects are
  retried. Receivers should compare the HMAC in constant time and reject
  old timestamps.
* **Egress guard.** Webhook requests follow no redirects, use no proxy and
  send no cookies. The handler resolves the host itself and checks every
  address it connects to, so DNS rebinding does not get through. Loopback,
  link-local (cloud metadata included), multicast, reserved, documentation
  and unspecified addresses and the server's own interface networks are
  always refused; IPv4-mapped, NAT64 and 6to4 addresses are checked as
  their IPv4 address. Private ranges are refused unless *Allow webhooks to
  private network addresses* is on.

## Application updates (winget)

Off by default. Policy `applicationUpdates` (`{enabled, approvedApps[]}`,
at most 100 winget package IDs) is resolved as a whole, like the restart
schedule. While it is on, the check-in config carries the list and every
install job carries it in `ApprovedApplications`; the agent's install
filter decides Application updates by that list in every mode.

* **Agent (Windows).** After a successful Windows Update scan, the agent
  runs `winget list --id <ID> --exact --source winget` for each approved ID
  and reports an update when winget offers a newer version. The update
  GUID is derived from the lower-cased ID and the version, so the next scan
  after an upgrade marks it installed. Installs run `winget upgrade --id
  <ID> --exact --version <version> --silent` with the community source
  only, as an argument vector; never `--force`, `--ignore-security-hash` or
  installer overrides. An upgrade counts only when `winget list` shows the
  new version afterwards (`not_verified` otherwise). The agent finds
  `winget.exe` in the newest `Microsoft.DesktopAppInstaller` package under
  `%ProgramFiles%\WindowsApps`, caps output at 4 MB and kills the process
  tree on timeout (60 minutes per upgrade).
* **Server.** `ScanIngestionService` drops application updates whose ID or
  version is malformed or whose GUID does not match them. When the
  application check failed, the existing rows are kept rather than aged
  out; when application updates are off, they become `NotApplicable`.
  Approved application updates are required, with the *other updates*
  rollout delay, and carry no CVE data.

### Installing winget

Windows agents make sure a machine-wide winget 1.6 or newer exists
(`WingetSetupService`), whether or not application updates are on. The
release is pinned in `EasyPatch.Contracts.Agent.WingetDistribution`
(version, file names, sizes and SHA-256 of the App Installer bundle, the
dependency archive and the license file). Three to six minutes after start
and then daily (after a failure: 30 minutes, 2 hours, 6 hours, then
daily), the agent checks for 1.5 GB of free space, downloads each file from
GitHub or else from the engine (`GET /downloads/winget/{file}`), accepts a
file only with the pinned size and SHA-256, takes only the
`<arch>/<name>.appx|.msix` entries of the dependency archive, waits for any
running job (at most 2 hours), and runs `dism.exe /Online
/Add-ProvisionedAppxPackage … /NoRestart`. Builds below 17763 and
architectures other than x64 and ARM64 are reported as unsupported.

The engine serves only the three pinned names, and only after
`WingetMirrorService` has verified size and SHA-256. Without a verified
copy it answers `503` with `Retry-After: 900`, records the request (at
most every 10 minutes), and the worker task `winget-mirror` (every 5
minutes) downloads the files from GitHub, retrying after 15 minutes, 1
hour, 6 hours, then daily. The API has no egress.

## Agent release signing

The engine is not trusted to decide what code runs on endpoints. It relays
agent packages and their signatures; the agent checks them against public
keys built into it. The release key, an ECDSA P-256 key pair, and who may
sign with it are described in the
[code signing policy](../../CODE_SIGNING.md); the public key is
`easypatch/keys/easypatch-release-key.pub.pem`.

* **What is signed.** The build writes `<package>.sig` beside each MSI,
  `.deb` and `.rpm`: a signature over the file name, version,
  architecture, size and SHA-256, with a fixed domain prefix, so it cannot
  be reused for another file, version or architecture.
* **What the agent checks**, in order: the key id is one of its built-in
  keys and the signature verifies; the package is newer than itself (never
  a downgrade) and for its architecture and format; the download has
  exactly the signed size and SHA-256, checked again right before the
  installer starts with the file held open (Windows) or in a root-only
  directory (Linux).
* **What it runs.** Windows: `msiexec.exe /i <package> /qn /norestart
  /l*v <log>` with no properties, so the server URL and identity are kept.
  Linux: `apt-get install` or `dnf --disablerepo=* install` of the package
  in the transient unit `easypatch-agent-update`. The job completes when
  the new version reports; a failed or rolled-back install is reported by
  the old version with the installer's exit code.
* **Rotating the key.** The agent accepts several public keys. Release a
  version that carries the new key beside the old one, signed with the old
  one, then sign with the new key only.

An agent built with another key accepts only packages signed with that
key. How to build one is in
[Building the agent](../deployment/patching-agent.md#building-the-agent).

## Worker tasks

Each task runs under a PostgreSQL advisory lock.

| Task | Interval | Work |
|---|---|---|
| `job-maintenance` | 30 s | Lease expiry and redelivery, job expiry, running-job timeouts |
| `presence-monitor` | 60 s | Online and offline transitions (offline after 10 minutes without a check-in by default, counting every endpoint as seen no earlier than 15 minutes after the worker started, the agents' longest backoff), scan staleness |
| `scheduled-installs` | 2 min | Install jobs inside open maintenance windows |
| `pre-downloads` | 10 min | Downloads before a window |
| `deferral-expiry` | 10 min | Updates whose rollout delay ended |
| `scheduled-restarts` | 2 min | Restart jobs from restart schedules |
| `agent-updates` | 2 min | Automatic agent updates, none while the host updater holds them |
| `rollout-guard` | 5 min | Holds for updates that fail too often |
| `compliance-snapshots` | 30 min | Daily compliance counters |
| `vulnerability-feeds` | 1 h | KEV, MSRC and Debian downloads |
| `alerts` | 2 min | Alert evaluation |
| `notifications` | 30 s | Notification delivery |
| `monthly-reports` | 1 min | Scheduled reports and report emails |
| `winget-mirror` | 5 min | The engine's copy of winget |
| `retention` | 6 h | Deletes events, audit entries, jobs, scans, history and reports past their retention |

## Known limits

* The nonce replay cache is in memory, so the deployment runs one API
  instance; several would need a shared nonce store.
* A compromised engine can choose which signed, newer agent release an
  agent updates to, and when, but cannot install anything unsigned or
  older.
* The Linux `.deb` and `.rpm` packages are not GPG-signed: the release
  signature and the SHA-256 in EasyRMM's install instruction check them.
* On Linux, root can read the agent's private key; on systemd older than
  250 it is protected by file permissions only. No TPM is used.
* The Data Protection keys and the database are unencrypted on the host;
  anyone with root there can read the SMTP password and webhook secrets.
* Consumer Windows 10 ESU (through a Microsoft account) cannot be
  detected; volume-licence ESU keys are, and administrators can set ESU by
  hand.
