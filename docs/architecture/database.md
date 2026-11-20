# Database

PostgreSQL 18. Schema migrations live in `server/migrations/` and are applied
automatically at server start-up (goose, advisory-locked).

## Roles

| Role | Login | Purpose |
|---|---|---|
| `easyrmm_owner` | yes | Owns all objects; used only to run migrations |
| `easyrmm_app` | yes | Runtime role: `SELECT/INSERT/UPDATE/DELETE` on application tables, `SELECT` on `audit_log`, `EXECUTE` on audit functions. Cannot alter tables or disable row-level security |

The Docker deployment creates both roles and the database on first start
(`docker/postgres/init/`). For an external PostgreSQL, run the same script as
a superuser.

## Tenant isolation (row-level security)

`organizations`, `sites`, `device_groups`, `audit_log` (and every later
tenant table) have RLS enabled **and forced**. Policies call:

* `easyrmm_scope_all()` — `easyrmm.scope_all = 'on'`
* `easyrmm_scope_ids('easyrmm.scope_orgs')` — organizations with full access
* `easyrmm_scope_ids('easyrmm.scope_sites')` — individual sites
* `easyrmm_scope_ids('easyrmm.scope_read_orgs')` — organizations readable
  because the user holds a site inside them

The settings are transaction-local (`set_config(…, true)`) and are written by
`database.DB.InTx/ReadTx`. With no settings, queries return nothing.

## Core tables (migration 00001)

| Table | Notes |
|---|---|
| `organizations` | Unique name (case-insensitive) |
| `sites` | `(organization_id, id)` unique, used by composite foreign keys |
| `device_groups` | `(organization_id, site_id)` → `sites` |
| `users` | Lower-case e-mail, Argon2id hash, sealed TOTP secret, lockout counters |
| `user_recovery_codes` | SHA-256 of single-use codes |
| `role_assignments` | Role + optional organization/site, scope checks enforced by constraints |
| `sessions` | SHA-256 token hash, state, idle/absolute expiry, revocation |
| `password_reset_tokens` | SHA-256 token hash, expiry, single use |
| `settings` | Platform key/value |
| `audit_log` | Append-only hash chain (see ADR-0007) |

## Remote access (migrations 00002 and 00010)

| Table | Notes |
|---|---|
| `devices` | Managed endpoints, enrolled by the EasyRMM agent (migration 00003) or discovered from MeshCentral: `mesh_node_id` links the row to a MeshCentral node, `remote_online` and `last_seen_at` follow MeshAgent's connection. Site-scoped row-level security like the tenancy tables; `(organization_id, site_id)` → `sites` with `ON DELETE RESTRICT`, so a site with devices cannot be deleted |
| `mesh_sites` | The MeshCentral device group of each site (`mesh_id`) and the name last written to it. Platform scope only: written by the synchronizer, never by user requests |
| `remote_grants` | One row per remote session launched from the console: SHA-256 of the one-time launch token and, once redeemed, of the gateway cookie; the EasyRMM session, user, device and kind: `desktop`, `terminal` or `files`, and since migration 00010 `rdp`, the only grant for which the gateway admits MeshCentral's web RDP relay (ADR-0026). The grant is valid only while that session is. Rows whose session has ended, and launch links never opened, are deleted after a day. Platform scope only |

The MeshCentral keys EasyRMM shares with MeshCentral (the login-token key and
MeshCentral's session key) are stored sealed with `EASYRMM_SECRET_KEY` in
`settings` under `meshcentral.secrets`, and written to MeshCentral's
`config.json` at start-up.

## Agent enrollment (migration 00003)

| Table / column | Notes |
|---|---|
| `enrollment_tokens` | Deployment tokens: site, optional device group, name, SHA-256 of the token, expiry, optional `max_uses` and the `uses` count, creator, `revoked_at`. Since migration 00024 the token itself is also kept, sealed (`token_sealed`). Tenant row-level security like the tenancy tables |
| `devices.agent_public_key` | The enrolled agent's Ed25519 public key, unique. A row with a key is an enrolled device; one without is discovered from MeshCentral only (`devices_enrolled_has_key` keeps `enrolled_at` and the key together) |
| `devices.agent_version`, `agent_arch`, `agent_last_seen_at`, `enrolled_at`, `enrollment_token_id` | What the agent last reported, and how it enrolled. `devices_agent_seen_idx` serves the online filter |
| `agent_nonces` | Nonces of signed agent requests until they could no longer be replayed; deleted when they expire. Platform scope only |

`easyrmm_touch_device()` updates `devices.updated_at` only when something
other than liveness changed (`last_seen_at`, `agent_last_seen_at`,
`remote_online`), so heartbeats do not rewrite it every minute.

## Scripts and jobs (migration 00004)

The script library, jobs that run a script on devices, and one run per
device with its output (ADR-0017).

| Table | Notes |
|---|---|
| `scripts` | A script in the shared library (no organization), an organization's, or one of its sites': name (unique per level, ignoring case), description, shell, body (up to 64 KiB), timeout (up to 4 hours, 5 minutes by default), who wrote it and who last changed it. `shell` is `sh`, `bash` or `python3`, and since migration 00007 also `powershell` or `cmd`. `updated_at` moves only for edits, not when the author is deleted. The shared library is read everywhere, an organization's scripts in it and its sites, a site's in that site; writing needs the level itself: platform scope, the organization or the site |
| `jobs` | A snapshot of a script run on devices: the script (NULL once it is deleted) and its name, shell, body and the body's SHA-256, arguments (up to 32), timeout, expiry, and who started it, by id and by name as it was then. A job spans tenants when its devices do, so it has no organization: it is read through the runs the caller can see. It is written once, with its runs, in the caller's transaction; `easyrmm_app` cannot update it. Removed at platform scope once it is older than `EASYRMM_JOB_RETENTION` (90 days by default) and none of its runs is open. Migration 00012 adds `kind` and `software` |
| `job_runs` | One device's part of a job, one per job and device: status (`queued`, `sent`, `running`, then `succeeded`, `failed`, `timed_out`, `canceled`, `expired` or `lost`), how many times it was delivered, when it was sent, started and finished and its deadline, exit code, the first and last 128 KiB of stdout and stderr with a flag where each was cut, an error, and cancellation (who asked, when, and when it was sent). A run is open exactly while `finished_at` is NULL. Runs no device picked up before `expires_at` become `expired`, running ones past `deadline_at` become `lost`; partial indexes serve these sweeps and each device's open runs. Carries the device's organization and site, with tenant row-level security like the tenancy tables; removed with its job or its device |

## Inventory and telemetry (migration 00005)

What each device's agent reports (ADR-0018). These tables are read through
the device's row-level security and written only at platform scope, by the
agent API and maintenance. Their rows go with the device.

| Table | Notes |
|---|---|
| `device_inventory` | One row per device: the latest inventory its agent uploaded (`data`, JSON), without the packages; the SHA-256 of the upload as sent (`hash`), which the agent compares with its own to decide whether to upload again; where the packages came from (`dpkg`, `rpm`, `apk` or `pacman`, and since migration 00007 `windows`) and how many there are (up to 20,000). `data->'easyPatch'` is what the device's EasyPatch agent says about itself; the device's link to the patching engine (`easypatch_devices`) is checked from it |
| `device_software` | Installed packages: name, version and architecture (and publisher, since migration 00007), replaced as a whole with each upload. A name can appear more than once (RPM keeps several kernels). Indexed by device and by lower-case name |
| `device_metrics` | One row per device: the latest measurements and when they were taken: processor use, memory and swap (total and used), load averages, uptime, process count, and the filesystems (JSON) |
| `device_metric_samples` | One sample per device and heartbeat, keyed by device and time, for charts and alerts: processor, memory, swap and disk use in percent (disk is the fullest filesystem's) and the one-minute load. BRIN index on the time. Removed after `EASYRMM_METRICS_RETENTION` (7 days by default) |

## Monitoring and alerts (migration 00006)

Alert policies at the shared, organization and site levels, and the alerts
they raise on devices (ADR-0019). The server evaluates the policies every
minute, at platform scope.

| Table | Notes |
|---|---|
| `alert_policies` | A condition watched on the devices of its level: every device (shared), an organization's, or a site's. `kind` is `offline`, `cpu`, `memory` or `disk`; all but `offline` have a percentage `threshold`; each is held for `minutes` (`offline` at least 3); severity `warning` or `critical`; enabled. Name unique per level, ignoring case. The migration adds four shared policies: device offline, disk almost full, high memory use and high processor use. Read and written like `scripts` |
| `alerts` | One policy's condition on one device. It keeps the policy's name, kind, threshold, minutes and severity as they were, so it reads the same after the policy changes or goes (`policy_id` becomes NULL). Status `open`, `acknowledged` or `resolved`; the value that raised it and the latest (percent, or minutes without a check-in for `offline`); who acknowledged or resolved it, by e-mail as it was then (empty when the server resolved it); and the resolution (`cleared`, `manual`, `not_covered`, `policy_off`, `policy_changed` or `policy_deleted`). `seq` orders alerts and pages through them. At most one unresolved alert per policy and device (partial unique index). Read, acknowledged and resolved through the device's row-level security (the service checks `alert.manage`); raised and removed only at platform scope. Resolved alerts are removed after `EASYRMM_ALERT_RETENTION` (90 days by default) |

## Windows devices (migration 00007)

PowerShell and cmd scripts, Windows' installed programs as a package
source, and a program's publisher (ADR-0020).

| Table / column | Notes |
|---|---|
| `scripts.shell`, `jobs.shell` | `powershell` and `cmd` join `sh`, `bash` and `python3` |
| `device_inventory.package_manager` | `windows` joins `dpkg`, `rpm`, `apk` and `pacman`: the programs Windows lists as installed |
| `device_software.publisher` | A program's publisher, up to 200 characters; empty by default |

## Audit forwarding (migration 00008)

| Table | Notes |
|---|---|
| `audit_forwarding` | At most one row (`id` is always true): the syslog collector (transport `udp`, `tcp` or `tls`, host, port, and RFC 5424 facility, 13 by default), for TLS a CA certificate and a client certificate with its key sealed with `EASYRMM_SECRET_KEY`, whether forwarding is on, and who changed it and when. Then how far it has got: the last audit record handed to the collector (`last_id`), the record it still delivers up to after being turned off (`drain_until`, so the record of turning it off is the last the collector receives), when it last sent, and the latest error. Platform scope only (ADR-0023) |

Audit records are appended under an advisory lock, so their ids become
visible in order. The migration also changes `easyrmm_purge_audit()`: while
forwarding is on, or still delivering its last records after being turned
off, retention keeps the records the collector has not received yet.

## Enrollment with approval (migration 00009)

An install command that is not tied to a site: agents installed with it
wait until someone approves them in the console and chooses their site
(ADR-0024). Both tables are platform scope only, because a waiting device
belongs to no organization yet; the service lets only callers who hold
`enrollment.manage` everywhere manage approval tokens and decide requests.

| Table | Notes |
|---|---|
| `approval_tokens` | Approval tokens: name, SHA-256 of the token (unique), expiry, optional `max_uses` and the `uses` count, creator, when last used, `revoked_at`. Unlike a deployment token it names no site. Since migration 00024 the token itself is also kept, sealed (`token_sealed`). `easyrmm_app` cannot delete them. Platform scope only |
| `enrollment_requests` | A device that asked to enroll with an approval token: the agent's Ed25519 public key (unique; the agent keeps asking with it until the request is decided), hostname, operating system, platform, agent version and architecture, the address it asked from, and state: `pending`, `approved` (with the device the approval created in the chosen site) or `rejected`; who decided and when, and when the agent last asked. Removed with its device. The server forgets pending requests whose agent has not asked for 7 days, rejected ones after 30 days, and approved ones once the agent has picked up its device; at most 10,000 wait at once. Platform scope only |

## Agent updates (migration 00011)

The server rolls the agent build it serves out to devices whose agent runs
another, a few at a time (ADR-0027). The rollout's mode (`automatic`,
`manual` or `off`) and how many devices may update at once are kept in
`settings` under `agent_updates`.

| Table / column | Notes |
|---|---|
| `devices.agent_sha256` | The SHA-256 of the agent's executable, as the agent reports it in its heartbeat. Agents from before self-update report none and cannot update themselves |
| `agent_updates` | One row per device being updated: the target build by SHA-256 and its version, the version it updates from, and state: `queued` (waiting for its turn or its next attempt), `sent` (the agent was told to update, with the attempt's id and when) or `failed` (no further attempts until someone asks); whether someone asked for it in the console, so that it goes out in manual mode too, and who; attempts, when to retry, and the last error. Removed once the device runs the target build, or when there is no longer an update to make. `agent_updates_sent_idx` finds the updates in flight, which the rollout's limit counts. Read and changed through the device's row-level security; heartbeats run at platform scope |

## Software actions (migration 00012)

Installing, updating and removing packages through a device's package
manager, as jobs that run one of EasyRMM's own scripts with the package as
an argument (ADR-0028).

| Column | Notes |
|---|---|
| `jobs.kind` | `script` (a library script someone chose; the default) or `software` (a software action). `jobs_kind_created` lists the jobs of a kind, newest first |
| `jobs.software` | Set for software actions only (`jobs_software_kind`): a JSON object with the action, package manager, package and version, for people and filters to read. The job's body and arguments are what runs |

## Patching engine links (migrations 00013 and 00023)

| Table | Notes |
|---|---|
| `easypatch_connection` | Dropped by migration 00023, when the patching engine became part of every deployment (ADR-0046). It held a separately run EasyPatch server's address and its API token, sealed. On an upgrade that still finds one, migration 00023 deletes the links, installs, removals and forgotten rows, which name that server's ids, and records the deletion in the audit log. The patching engine's address and key come from `.env` |
| `easypatch_organizations` | Which of the patching engine's organizations an EasyRMM organization is: one each way (`easypatch_id` is unique), with the engine's name for it. The reconciler makes, updates and removes these links (ADR-0040), as does the import of a standalone EasyPatch (ADR-0045); neither sets `linked_by`. Read through the organization's row-level security; written with platform scope only |
| `easypatch_devices` | A device's link to its endpoint in the patching engine: `pending`, `linked` (with the endpoint and when) or `unlinked` (with the reason), the key fingerprint it was checked with, and when. A linked endpoint belongs to one device (partial unique index). Migration 00020 adds where the endpoint is. Read through the device's row-level security; written with platform scope only |

No patch data is stored: the console reads it from the patching engine
(ADR-0030, ADR-0038).

## EasyPatch agent installs (migration 00014)

| Table | Notes |
|---|---|
| `easypatch_organizations.auto_install` | Whether EasyRMM installs the EasyPatch agent on the organization's devices that have none, by itself (ADR-0031) |
| `easypatch_installs` | One row per device: the latest EasyPatch agent install, `waiting`, `sent` (with the attempt id sent to the agent, when, and the id of the patching engine's enrollment token for it, never the token), `succeeded` or `failed` (with the reason); whether it was automatic, who asked, attempts, and a note while it waits (an agent too old to install it). Read through the device's row-level security; written with platform scope only |

## Security keys and passkeys (migration 00015)

Reached only through the authentication service, at platform scope, like
`users`, `sessions` and `user_recovery_codes` (ADR-0032).

| Table | Notes |
|---|---|
| `user_webauthn_credentials` | One row per registered security key or passkey: its owner, credential id (unique across all users), the name its owner gave it (unique per user), the credential as go-webauthn records it (public key, signature counter, flags, transports, AAGUID), when it was added and last used. Removed with the user, by the owner, or by an administrator's second-factor reset |
| `webauthn_challenges` | A ceremony in progress: what the server asked the browser for, keyed by its challenge, for five minutes. Registration and the sign-in step belong to a session (and go with it); passkey sign-in has none yet. Each is deleted when answered; expired ones are deleted when the next one starts |

## Sign-in hardening (migration 00016)

| Column | Notes |
|---|---|
| `users.mfa_failed_attempts` | Wrong authenticator or recovery codes in a row, across sign-ins. Ten lock the account like wrong passwords do; a correct second factor, a password reset or an unlock clears it |
| `sessions.reauth_failures` | Wrong passwords entered to confirm a change from this session; the fifth ends it |

See `docs/security/sign-in.md`.

## Passkey offer (migration 00017)

| Column | Notes |
|---|---|
| `users.passkey_prompt_after`, `users.passkey_prompt_declined_at` | When the offer of a passkey after sign-in may come again ("Not now", 30 days), and when the user declined it for good (ADR-0032) |

## Single sign-on (migration 00018)

Single sign-on with OpenID Connect (ADR-0034). Like the other
authentication tables, these have no row-level security and are reached
only through the single sign-on service, at platform scope.

| Table | Notes |
|---|---|
| `identity_providers` | Single sign-on providers: name (unique), issuer, client id, the client secret sealed with `EASYRMM_SECRET_KEY` (additional data: the provider's id), allowed email domains, whether its addresses count as verified and whether it is trusted for MFA, enabled. Set up by super administrators, except the provider the deployment sets up (`managed`, migration 00021) |
| `user_identities` | A provider's account (provider and ID token `sub`) linked to a user, with the email it had when linked and when it was last used. One per user per provider; removed with the user, the provider, or by the user (unlink) |

## EasyRMM as an OpenID provider (migrations 00019 and 00022)

Migration 00019 made EasyRMM the OpenID provider of a separately run
EasyPatch, which signed people in with their EasyRMM session (ADR-0036).
Migration 00022 dropped the provider's tables once the patching engine ran
in every deployment and took EasyRMM's statements instead (ADR-0046,
ADR-0038); the session columns stay. The tables had no row-level security
and were reached only through the authentication and provider services.

| Table / column | Notes |
|---|---|
| `sessions.amr` | How the session signed in, as OpenID Connect `amr` values (RFC 8176): `pwd`, `fed` (single sign-on), `otp`, `hwk`, `rc` (a recovery code) and `mfa`. Sessions from before the migration have none. Kept by migration 00022: EasyRMM's sign-in still records it, but nothing decides on it any more |
| `sessions.authenticated_at` | When the session became active. Kept by migration 00022, like `amr` |
| `idp_clients` | Dropped by migration 00022. It held the one client, EasyPatch: client id, SHA-256 of its secret, the redirect URI matched exactly, who created it and who last rotated its secret, and when. At most one row |
| `idp_signing_keys` | Dropped by migration 00022. ID token signing keys (ES256) by key id, sealed with `EASYRMM_SECRET_KEY` (additional data: the key id) |
| `idp_codes` | Dropped by migration 00022. Authorization codes, stored as SHA-256: single use, valid 60 seconds, bound to the client, redirect URI, session, user, nonce and PKCE challenge |

## One set of organizations (migration 00020)

With the patching engine in the deployment, a reconciler makes the
engine's organizations, sites and endpoints follow EasyRMM's (ADR-0040).

| Table / column | Notes |
|---|---|
| `organizations.timezone` | The time zone the patching engine is given for the organization: its monthly reports, and the maintenance windows of the engine's endpoints that have no site (an imported endpoint can lack one; EasyRMM's devices always have a site). `UTC` by default; sites have had one since migration 00001 |
| `easypatch_devices.easypatch_org_id`, `easypatch_site_id` | Where a linked device's endpoint is in the patching engine: the organization link it was checked against, and its site as last read or placed. A device whose site has moved no longer matches, and the reconciler moves its endpoint; one whose organization has changed has its EasyPatch agent removed (`easypatch_removals`), since the engine cannot move an endpoint between organizations |
| `easypatch_sites` | Which of the patching engine's sites an EasyRMM site is, as `easypatch_organizations` is for organizations: one each way (`easypatch_id` is unique), with the engine's name for it and when it was linked. Read through the site's row-level security; written with platform scope only |
| `easypatch_forgotten` | Organizations and sites EasyRMM deleted that the engine still has: kind, the engine's id and name, when, and the last error. The reconciler renames each to free its name, archives it, and removes the row. Inserted by the delete triggers below, whatever the deleting transaction's scope; read and changed with platform scope only |
| `easypatch_removals` | An endpoint whose EasyPatch agent is to be removed, because its device was deleted (`deleted`), opted out of patching (`opted_out`) or moved to another organization (`moved`): the device while EasyRMM still has it, hostname, state `pending` (the uninstall job is not sent yet) or `uninstalling` (sent, with the engine's job id and when), attempts and the last error. If the agent has not removed itself 7 days after the job was sent, the endpoint is revoked instead. The row goes when the endpoint is no longer active. Any scope may insert one (the device delete trigger runs in the deleting transaction); read through the device's row-level security while there is a device; changed with platform scope only |
| `easypatch_opt_outs` | Devices patching is stopped for, when and by whom. EasyRMM removes their EasyPatch agent and installs none, automatically or on request, until patching is allowed again, which deletes the row; an agent someone installs on the computer by hand is left alone. Read through the device's row-level security; written with platform scope only |

Three `BEFORE DELETE` triggers record what the engine must undo, whoever
deletes: deleting an organization or a site adds its link to
`easypatch_forgotten`, and deleting a device whose link is `linked` adds its
endpoint to `easypatch_removals` with the reason `deleted`.

## Authentik (migration 00021)

Authentik in the deployment, when `setup.sh --with-authentik` chose it
(ADR-0044).

| Table / column | Notes |
|---|---|
| `identity_providers.managed` | A provider the deployment sets up from its configuration rather than a super administrator. Settings shows it locked: it is changed in the server's configuration and cannot be deleted. When the deployment no longer has it, it is kept, disabled and no longer managed, so that a super administrator can delete it |
| `recovery_links` | One-time sign-in links that `easyrmm-server recover` prints for a super administrator, for when single sign-on is down: SHA-256 of the token, the user, when it was made, when it expires (15 minutes later) and when it was used. Deleted a day after they expire. No row-level security: reached only through the authentication service, like `password_reset_tokens` |

## Tokens shown again (migration 00024)

Deployment and approval tokens can be shown again (ADR-0047). A new
token's secret is kept sealed with `EASYRMM_SECRET_KEY`, bound to the
token's id, beside the hash agents are checked against. Tokens made before
keep only their hash and cannot be shown again.

| Column | Notes |
|---|---|
| `enrollment_tokens.token_sealed` | A deployment token's secret, sealed (additional data: `enrollment_token:` and the token's id); NULL for tokens made before. The service shows it only while the token is active, after checking it against `token_hash`, and audits every reveal |
| `approval_tokens.token_sealed` | The same for an approval token (additional data: `approval_token:` and its id) |

## Backups

See `docs/operations/backup-restore.md` (written with the Docker deployment).
