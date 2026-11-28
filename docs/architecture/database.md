# Database

PostgreSQL 18. Schema migrations live in `server/migrations/` and are applied
automatically at server start-up (goose, advisory-locked).

## Roles

| Role | Login | Purpose |
|---|---|---|
| `easyrmm_owner` | yes | Owns all objects; used only to run migrations |
| `easyrmm_app` | yes | Runtime role: `SELECT/INSERT/UPDATE/DELETE` on application tables, `SELECT` on `audit_log`, `EXECUTE` on audit functions. Cannot alter tables or disable row-level security, and since migration 00029 cannot create temporary tables. Since migration 00028 it cannot select `job_runs.stdout`, `job_runs.stderr` or `jobs.args`: their other columns are granted one by one, so **a column added to `job_runs` or `jobs` later needs its own `GRANT SELECT (column)`** |

The Docker deployment creates both roles and the database on first start
(`docker/postgres/init/`). For an external PostgreSQL, run the same script as
a superuser.

**`easyrmm_owner` must be able to create tables in the `public` schema.**
Every migration that adds a table needs it. Since PostgreSQL 15, `public`
belongs to `pg_database_owner`, so only the database's owner, or a role
granted it, may create there. Two ways:

* **`easyrmm_owner` owns the database** (recommended; the Docker
  deployment's `docker/postgres/init/10-easyrmm.sh` creates it so):
  `ALTER DATABASE easyrmm OWNER TO easyrmm_owner;` as a superuser.
* **Another role owns it**, and `easyrmm_owner` is granted `CREATE` on
  `public`: as that owner or a superuser, connected to the database,
  `GRANT USAGE, CREATE ON SCHEMA public TO easyrmm_owner;`.

Without either, the first migration that creates a table fails with
`permission denied for schema public`, and the server does not start.

**`easyrmm_owner` should own the database** in any case: migration 00029
revokes `TEMPORARY` from `easyrmm_app` and `PUBLIC`, which only the
database's owner can do. Under any other owner it skips the revoke and
the server logs a warning, `database migration: database … is not owned
by easyrmm_owner`, whose hint gives the statements to run as a superuser:
`REVOKE TEMPORARY ON DATABASE easyrmm FROM PUBLIC, easyrmm_app;` and
`ALTER DATABASE easyrmm OWNER TO easyrmm_owner;`. When `easyrmm_app` still
holds `TEMPORARY` after the revoke, through a grant by another role or a
role it belongs to, the warning says so and how to find and revoke it.
The server starts either way: under another owner with `CREATE` on `public`
granted, every migration runs, and 00029 warns with the statements to run.

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
| `devices.agent_heartbeat_seconds`, `agent_online_until` | The interval the device's agent uses (10 to 600 seconds; the server answers 30 to 300) and when the device stops counting as online: three of those intervals after its last heartbeat. The database sets the second from the first whenever `agent_last_seen_at` changes and the writer does not set it (`easyrmm_device_online_until`, trigger `devices_online_until`), so the heartbeat, enrollment and Quick Assist agree. `devices_agent_online_idx` serves the online filter. Neither moves `updated_at` (ADR-0058) |
| `agent_settings` | One row per setting key and target: `scope` (`platform`, `organization`, `site`, `device`) with the organization, site and device it needs (check constraints; a device row also names the organization and site the device is in, and `easyrmm_agent_setting_device_check`, a definer function, refuses one for a device without the EasyRMM agent), the `value` (JSON; checked against the server's catalogue on every write), whether it is `enforced` (never on a device), and who set it and when. One row per key at the platform, per organization, per site and per device (partial unique indexes). Row-level security as for `scripts`: the platform's rows are read by everyone and written at platform scope only; an organization's by whoever holds the organization, a site's and its devices' by whoever holds the site. Rows go with their organization, site or device; a move of a device to another site deletes its own rows (ADR-0069) |
| `agent_device_state` | One row per enrolled device, written lazily by its heartbeats (migration 90611, ADR-0058 slice 2): the `capabilities` its agent last reported and the build that reported them (`capabilities_build`: its SHA-256, or `version:<v>` for an agent that sends none; NULL after a change of build without a report); the last settings document issued (`doc_version`, `doc_hash`, `doc_issued_at`, `doc_catalog_version`); what the agent reported applying (`applied_version`, `applied_hash`, `applied_at`, `problems`); `not_applied_heartbeats` (three flag the device); and `heartbeat_signed_at`, the signed time of the latest heartbeat processed. Read `FOR UPDATE` when a document is issued, so two heartbeats at once issue one version. Row-level security reads through `devices`; written by the system scope. Goes with the device (cascade) and follows it in a move (it holds no organization or site) |
| `agent_nonces` | Nonces of signed agent requests until they could no longer be replayed; deleted when they expire. Platform scope only |

`easyrmm_touch_device()` updates `devices.updated_at` only when something
other than liveness changed (`last_seen_at`, `agent_last_seen_at`,
`agent_heartbeat_seconds`, `agent_online_until`,
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
| `jobs.kind` | `script` (a library script someone chose; the default) or `software` (a software action); `hardening` since 00027. `jobs_kind_created` lists the jobs of a kind, newest first |
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

## Removing devices (migration 00025)

A device's removal waits for its agent to confirm; a device removed is
remembered for 90 days, so that its agents still clean up if the computer
comes back (ADR-0050).

| Table | Notes |
|---|---|
| `device_removals` | One row per device whose removal waits for its agent: the removal's id (named in the signed instruction and the agent's report), when it was asked and by whom, when a heartbeat answer first carried the instruction, and when the agent reported that it could not remove itself, with why (up to 500 characters). Asking again replaces the row with a new id; cancelling deletes it; it goes with its device. Read and changed through the device's row-level security; heartbeats run at platform scope |
| `retired_devices` | A device deleted in the last 90 days that had an agent key or a MeshAgent node: its id, organization, site and name; the agent's Ed25519 public key while the agent has not confirmed removing itself (an agent signing with it is answered with the uninstall instruction only), its report; the MeshCentral node, until a device enrolled since in the same site reports it, and the cleanup of that node: when last tried, how many times its MeshAgent was asked to uninstall itself, when the node was removed, and the last error. Deleted when they expire. Any scope may insert one (the removal runs in the caller's scope); read, changed and deleted with platform scope only |
| `retired_agent_nonces` | Nonces of signed requests from removed devices' agents, as `agent_nonces` for enrolled ones. Platform scope only |

## Signed Windows agents (migration 00026)

Windows agent builds an operator signed with their own certificate and
uploaded (ADR-0049). Kept in the database so that backups keep them.

| Table | Notes |
|---|---|
| `signed_agent_builds` | One row per architecture (`amd64`, `arm64`) and version: the signed file (up to 64 MiB), its SHA-256 and that of the release's build it was made from, the signer's subject, issuer and SHA-1 thumbprint, the certificate's validity, whether the signature has a timestamp, and when and by whom it was uploaded. For each architecture the server keeps the build of its own version and the newest older one. Platform scope only; the service allows Super Administrators (`settings.manage`) |

## Hardening Linux computers (migration 00027)

Jobs that run EasyRMM's own hardening script, and what the last check found
on each device (ADR-0051).

| Table or column | Notes |
|---|---|
| `jobs.kind`, `jobs.hardening` | `hardening` joins `script` and `software`. `jobs.hardening` is set for hardening jobs only (`jobs_hardening_kind`): the mode, the modules and the options, for people and filters to read; the job's body and arguments are what runs |
| `jobs.body` | Up to 512 KiB, for EasyRMM's own scripts; a library script stays at most 64 KiB |
| `device_hardening_checks` | One row per device a hardening job reported on: the platform as the script read it (distribution, version, family, container, and whether apply is supported there), the job and when it ran. Kept from the run that started last. Goes with its device |
| `device_hardening` | One row per device and module: its state (`in_place`, `partly`, `not_in_place`, `not_applicable`, `managed_elsewhere`, `not_supported`, `half_applied`, `failed`), the finding (a reason, what is missing, what apply would change, and the firewall's ports; after an apply or undo, its outcome, why, what it did, whether it first recovered the package database, and whether EasyRMM's record of applying the module is on the computer), the job and when it ran. A later job that covers the module replaces it. Read through the device's row-level security; written from job results at platform scope |

## Who sees job output and arguments (migration 00028)

A run's output and a job's arguments can hold secrets; they are read only
with `job.view_sensitive`, each read audited, and output is kept for less
time than the job (ADR-0063).

| Table, column or function | Notes |
|---|---|
| Column privileges | `easyrmm_app` holds `SELECT` on every column of `job_runs` but `stdout` and `stderr`, and on every column of `jobs` but `args`. A query that names them, selects `*`, refers to the whole row or returns them is refused (`42501`). `INSERT` and `UPDATE` are unchanged, so starting a job, a result and the purge still write them |
| `job_runs.stdout_bytes`, `stderr_bytes` | The size of each stream in bytes, so a run says whether it printed anything without reading what. Set by the `job_runs_sizes` trigger (`easyrmm_job_runs_sizes()`) on every insert and on updates of the output or the sizes, whatever the statement says |
| `job_runs.output_stored_at` | When the output arrived; NULL while there is none. Retention counts from it. Backfilled from `finished_at` for output kept before |
| `job_runs.output_removed_at` | When the output was removed, by retention or by a person; set only on runs that had output (`job_runs_output_removed`: never both set). A result that arrives later for such a run (a *No result* run reporting late) records its status but stores no output |
| `jobs.arg_count` | How many arguments the job has, set the same way by the `jobs_arg_count` trigger (`easyrmm_jobs_arg_count()`). The migration fills in the sizes and counts of existing rows with one `UPDATE` each instead of rewriting the tables |
| `job_runs_output_stored_idx` | Partial index on `output_stored_at` for the hourly purge, which empties output older than `EASYRMM_JOB_OUTPUT_RETENTION` |
| `easyrmm_job_run_output(…)` | `SECURITY DEFINER`. Given a run, what is downloaded (`download`: `stdout`, `stderr` or `json`, or NULL for the console's page; since migration 00032), the caller's `job.view` and `job.view_sensitive` scopes and who asks, it checks access, appends the audit record (`job_run.output_view`, with `download` in its details, or `denied`) in the caller's transaction, and returns the output. Answers `not_found`, `forbidden`, `run_open`, `output_removed`, `empty` or `ok` |
| `easyrmm_job_output_zip(…)` | `SECURITY DEFINER` (migration 00032). For a job's output archive: locks the runs the caller sees in the order canceling a job does (device name, then run), appends one `job_run.output_view` record with `download` `zip`, dated by the database's clock (`clock_timestamp()`), for each finished run the caller may read whose output is there and not empty, and returns those runs with their record's id, and the empty ones without one. A caller who sees runs and may read none is refused, recorded as `denied` within `easyrmm_job_refusal`'s bound. Answers `not_found`, `forbidden` or `ok` |
| `easyrmm_job_run_output_recorded(…)` | `SECURITY DEFINER` (migration 00032). Returns one run's output for the archive, in a short transaction of its own, only against the record `easyrmm_job_output_zip` wrote: a successful `zip` read of that run by the same caller, at most a day old and at most 5 minutes ahead by the database's clock (`clock_timestamp()`, which dated the record; it takes no time from the server, and the 5 minutes allow for that clock being set back). It checks the caller's scopes again and records nothing. Answers `not_found`, `forbidden`, `output_removed` or `ok` |
| `easyrmm_job_arguments(…)` | The same for a job's arguments: one `job.arguments_view` record per organization of the runs the caller may read (under the site when they share one) |
| `easyrmm_job_delivery_args(device, runs)` | `SECURITY DEFINER`, platform scope only: the arguments of a device's runs being delivered, for the agent's poll. Not audited: the device is the one that runs them |
| `easyrmm_job_refusal(…)` | Appends a refused read as `denied`, at most once per caller, action, target and organization in 10 minutes and 20 per caller in 10 minutes, so a refused caller cannot flood the log. After 20, a caller's further refusals in those 10 minutes are not recorded. Serialized per caller with a transaction advisory lock, so the bound holds across server processes. Called only by the read functions: `easyrmm_job_run_output`, `easyrmm_job_arguments` and `easyrmm_job_output_zip` |

The functions check the scopes and the caller that the server passes them,
so they guard against mistakes in the server's code, not against a
compromised server, which holds the owner's credentials anyway.

## Structured jobs: inputs and results (migrations 00072 and 00073, ADR-0067)

A job may run a builtin of the agent instead of a script (`jobs.executor`,
`jobs.builtin`, `jobs.lane`), and its kind (`registry_query`,
`registry_change`) is tied to it by constraints; such a job holds no script
(`shell` and `body` empty) and is hidden from the Jobs list without its
filter. Its input is in `job_inputs` (one row per job, `input` emptied with
the results) and its result in `job_runs.result`, a `jsonb` array of the
lines the builtin wrote. The runtime role cannot select either, nor
`registry_masked_values.data`; it reads them through
`easyrmm_job_run_result` and `easyrmm_job_input`, which check
`job.view_sensitive`, the kind's permission and, for a query, that the
caller asked, and which run as their owner with a fixed `search_path`. The
poll reads inputs through `easyrmm_job_delivery_inputs`, and the result path
checks a result against its input through `easyrmm_job_run_input_system`,
both only under the system scope. `jobs.signed_bytes` is the size of the
signed job, bounded at creation; `job_runs` keeps the version and build that
ran it. The retention sweep empties a kind's input, results and masked
values together, after the kind's time counted from its last run's end.

## Functions that run as their owner (migration 00029)

Every `SECURITY DEFINER` function sets `search_path = pg_catalog, public,
pg_temp`. Without `pg_temp` named last, a session's temporary schema is
searched first for tables and types, and a caller could have its own code
run as `easyrmm_owner`. 00029 changes the three earlier ones
(`easyrmm_audit_append`, `easyrmm_audit_verify`, `easyrmm_purge_audit`);
the functions of 00028 are created that way.
`server/internal/database/definer_integration_test.go` reads every such
function from the catalog and fails when one does not end with `pg_temp`,
so **a new `SECURITY DEFINER` function must end its `search_path` with
`pg_temp`**. 00029 also revokes `TEMPORARY` on the database from
`easyrmm_app` and `PUBLIC` (see Roles for when it cannot): the server never
creates temporary tables, and the install scripts no longer grant it.
Warnings a migration raises reach the server's log with their hints.

## The mail server in the console (migration 00030)

The mail server super administrators set in the console, and the limits on
the mail EasyRMM sends through whichever mail server is in force
(ADR-0053, [Mail](../operations/mail.md)).

| Table | Notes |
|---|---|
| `mail_server` | Always one row (`id` is always true), so the limits hold before anyone sets them. The console's mail server, if any (an empty `host` means none): port, security (`starttls`, `tls`, or `none`, which the service allows only to loopback), how it signs in (`none` or `password`), the user name, the password sealed with `EASYRMM_SECRET_KEY` (additional data: the column), the sender's address and name, and who changed it and when. The limits, 30 a minute and 9,000 a day by default, with who changed them and when; and when the last test message went (one every 30 seconds). `.env`'s mail server is never stored. Platform scope only |
| `mail_sends` | One row per message sent, or being sent, in the last 24 hours: when, and its `kind`: `reset` for a password reset the person asked for, which may use the whole day's limit; `admin` for an invitation or a password link an administrator sent (`sent_by`), which stops at 90% of it; `other`, which stops at 80%. Invitations and password emails record the `account_id` they went to and its `organization_id` (null for none or several, and for admin mail when a super administrator sent it), which the limits per account, per organization and per administrator count ([Mail](../operations/mail.md#limits-on-invitations-and-password-emails)). Taken under an advisory lock across servers; a message the mail server refuses is removed again, and rows older than 24 hours are deleted. No foreign keys: a row outlives a deleted user or organization for at most a day. `easyrmm_app` cannot change a row. Platform scope only |
| `mail_engine_given` | One row: an HMAC-SHA-256 of the mail server the patching engine is given, keyed by a key derived from `EASYRMM_SECRET_KEY`, by the one of EasyRMM's servers that gives it (under a session advisory lock), and when it was recorded; never the mail server or its password. The other servers compare theirs with it. Since migration 00035, one digest per secret key. Platform scope only |
| `mail_waits` | One row per message to someone's own account waiting for room under the minute's limit, on any server, until when it gives up: other mail stands back while one waits. Removed when the wait ends; a row a stopped server leaves runs out at `until` and is deleted. Platform scope only |

## Disk health (migration 00031)

What agents read from each disk every 30 minutes, judged by the server's
rules, and disk health alerts with one alert per disk (ADR-0065).

| Table, column or function | Notes |
|---|---|
| `device_disk_health` | The latest reading of each disk a device reported, keyed by device and `disk_key`. The reading's own `state` (`healthy`, `warning`, `failing`, `unknown`, `unsupported`, `unavailable`), `reason` code and `detail`, when the agent read it and when the server received it; `protocol`, `route`, the judged `facts` and ATA `attributes` (JSON arrays) from the latest reading that read the disk (`facts_at`), so a sleeping disk keeps its last values; `judged_level`, `judged_reason`, `judged_detail` and `judged_at` from the last reading that read the drive's verdict, which later readings that could not tell do not overwrite; `missing_since`, set by a report that leaves the disk out and cleared by one that lists it. `unstable`: the identity comes from the name, for want of a serial. Read through the device's row-level security; written at platform scope by the agent API and the evaluator. Goes with its device |
| `device_disk_health_samples` | One row per disk and reading: the state, whether the verdict was read (`judged`), temperature and the drive's limit, wear, reallocated, media error, pending, uncorrectable and drive error counts, and power-on hours. BRIN index on the time. Readings older than `EASYRMM_METRICS_RETENTION` are thinned hourly to one `daily` row per disk and UTC day (the day's worst state, highest temperature, last counts and wear), kept for `EASYRMM_HARDWARE_RETENTION` (730 days by default). Samples outlive a disk's row when it is gone, until their retention; they go with their device |
| `agent_log_records` | An agent's log records (ADR-0069): the device, the agent's sequence number (unique per device from 0; -1 marks a record the server wrote to say that records were dropped or refused), source (`agent`, `easypatch`, `meshagent`), the agent's time, the time received, level, message and attributes as JSON. Indexed by device and id (the console's cursor) and by the time received, which retention counts. Read through the device's row-level security; written and deleted by the server only. Deleted in batches of 5,000 past `EASYRMM_AGENT_LOG_RETENTION_DAYS` |
| `agent_log_days` | How many records a device stored on a UTC day (the cap is 200,000) and how many it was refused |
| `agent_log_verbose` | Verbose logging on a device or a device group until a time; ends by itself and is deleted a day later. Visible to the tenants of its organization and site |
| `agent_log_follow` | Until when someone watches a device's logs, which makes its agent send every 2 seconds |
| `easyrmm_disk_key(name, model, serial)` | A disk's identity: the first 16 bytes of the SHA-256 of `disk\nmodel\nserial`, in hex, or of `name\nname` without a serial. The agent API computes every reported disk's identity with it, so the definition is kept in one place, beside the data |
| `easyrmm_disk_state(missing_since, state, judged_level, judged_at)` | What the console shows for a disk: `unknown` when missing; the latest reading's `unsupported` or `unavailable`; the last judged `failing` or `warning`, however old; `healthy` when judged so within 2 hours; else `unknown`. The Devices list sums it per device |
| `alert_policies.check_name` | The disk health check (`failing`, `errors`, `pending`, `wear`, `temperature`) of a `disk_health` policy, NULL for the other kinds. `failing` takes no threshold, `temperature` may take none (each drive's own limit), the others need one; a `disk_health` policy watches at least 30 minutes, the reading interval, and a `temperature` one at least 60, so that its window holds two readings. The migration adds five shared policies, only *Disk failing* enabled; a name already taken at platform level is tried once with " (disk health)" appended |
| `alerts.check_name`, `subject`, `subject_label`, `detail` | The check, the disk's identity, its name for people (never the serial) and what holds. `subject` is `''` for the other kinds; the partial unique index `alerts_active_key` is now on (policy, device, subject), so each disk has its own alert and the other kinds still have one per policy and device. Resolution `subject_gone`: the disk has been missing for 14 days, so no hardware report since has listed it; its `device_disk_health` row goes with it |

## PowerShell 7 (migrations 00033 and 00034)

The `pwsh` shell, the program each run used, and what each device's agent
and inventory say of PowerShell 7 (ADR-0064).

| Table or column | Notes |
|---|---|
| `scripts.shell`, `jobs.shell` | Gain `pwsh` |
| `scripts.pwsh_fallback`, `jobs.pwsh_fallback` | Whether a `pwsh` script may run in Windows PowerShell 5.1 where no usable PowerShell 7 is found; only a `pwsh` row may set it. A job keeps its script's |
| `jobs.requires` | The capabilities an agent's poll must list for the job to be sent to it (`job.pwsh` for `pwsh`); at most 32, no NULLs |
| `job_runs.program_*` | The program the agent started, as it read it: `Desktop` or `Core`, version (64), `x64`, `arm64` or `x86`, path (520), and whether it fell back |
| `devices.agent_accepts`, `agent_accepts_build` | The last list the agent's poll reported, with the build that reported it; another build's list counts as not reported |
| `devices.powershell7`, `powershell7_blocked` | What the device list says of PowerShell 7, written with each inventory: whether it lists a usable install (NULL when it lists no PowerShell), and, where none is usable and one is blocked, why a run fails (at most 500 characters, only with `powershell7` false) |

00033 adds every check `NOT VALID`, so it changes the tables under their
exclusive lock briefly without reading their rows; new and changed rows are
checked at once. 00034, in a transaction of its own, validates them (`SHARE
UPDATE EXCLUSIVE`, which lets the server read and write the tables
meanwhile) and fills `powershell7` and `powershell7_blocked` from the
inventories already stored, as the server writes them with each inventory:
an agent sends its inventory only when it changes, and 00033's down drops
the columns while the inventories stay. It reads each stored inventory once,
in one statement, rewrites no table, and writes and locks only the devices
whose flags change; on an upgrade from before 00033 no inventory lists
PowerShell, and it writes nothing. 00034's down leaves the
checks validated; 00033's down removes them with the columns and deletes
`pwsh` scripts and jobs.

## Signing in to Microsoft 365 for mail (migration 00035)

A Microsoft 365 application as the console's mail server's sign-in, and two
follow-ups from slice 1's review (ADR-0053, slice 2;
[Mail](../operations/mail.md#microsoft-365)).

| Table or column | Notes |
|---|---|
| `mail_server.sign_in` | Takes `microsoft365` too. Then `tenant_id` (a GUID or a domain name, at most 253 characters), `client_id` (a GUID) and `client_credential` (`secret` or `certificate`) are set, and the others are empty; `security` is never `none` |
| `mail_server.client_secret_sealed`, `client_key_sealed` | The client secret, or the certificate's private key, sealed with `EASYRMM_SECRET_KEY` (additional data: the column). Set exactly when `client_credential` says so; never returned by the API |
| `mail_server.client_certificate` | The certificate (PEM, with any chain after it), not secret: the console shows its subject, thumbprint and dates. At most 64 KiB |
| `mail_engine_given.digests` | Replaces `digest`: a JSON object of hex HMAC-SHA-256 digests keyed by secret key ID, one for each key the recording server has (`EASYRMM_SECRET_KEY` and `EASYRMM_SECRET_KEYS_PREVIOUS`), so that during a rotation servers compare under a key they have in common. The migration drops the old digest; the server that gives the engine its mail server records the new ones at its next pass |
| `mail_account_buckets` | One row per account whose password emails have left `mail_sends`: when its bucket of 3 at once, then one every 20 minutes, is full again (`full_at`). Rows leaving `mail_sends` are folded into it under the same advisory lock, so the account's limit holds exactly however old its emails are; a row more than a day past is deleted. No foreign key, as for `mail_sends`. Platform scope only |

Down removes a console mail server that signs in with an application, as
**Remove** does, keeping its limits, and makes `mail_engine_given` as
migration 00030 did.

## The customer record (migration 00036)

An organization's contact information, sites' addresses, business hours,
contacts and places within a site (ADR-0066, slice 1; the
[guide](../operations/customer-record.md)). Goose applies migrations in
order, so 00036 follows 00032 to 00035.

| Table, column or index | Notes |
|---|---|
| `organizations.main_phone`, `main_email`, `website`, `after_hours_note` | Text, empty by default, at most 50, 254, 2,000 and 2,000 characters. The server checks the rest (a digit in a phone number, one email address, an `http` or `https` website) |
| `organizations.business_hours`, `sites.business_hours` | JSON object or NULL for none: up to four `{start, end}` periods (`HH:MM`) for each of `monday` to `sunday`, checked and sorted by the server; at most 8 KiB. A site's NULL uses its organization's |
| `sites.address_line1`, `address_line2`, `city`, `region`, `postal_code`, `country_code`, `after_hours_note` | Text, empty by default, at most 200, 200, 100, 100, 20 and 2,000 characters; `country_code` two capitals or empty (the server keeps to the 249 assigned ISO 3166-1 codes). `sites.address` stays, the free text |
| `site_places` | A building, floor, room, rack or other within a site: `organization_id`, `site_id`, `parent_id` (NULL at the top), `depth` 1 to 4, `kind`, `name` (1 to 200 characters). The foreign key `(site_id, parent_id, parent_depth)` → `(site_id, id, depth)`, with the generated `parent_depth = depth - 1`, keeps a parent in the same site and exactly one level up, so no cycle can form, and refuses to delete a place with places inside (a move updates a place and the places inside it in one statement, so the key holds at its end). `site_places_name_key`: names unique, ignoring case, among one parent's places (`NULLS NOT DISTINCT`, the top included). Goes with its site |
| `contacts` | `organization_id`, `site_id` (NULL for the organization's own) through the composite key to `sites`, `name` (1 to 200 characters), `job_title`, `email`, `office_phone`, `mobile_phone`, `note` (up to 2,000), `priority` (`primary`, `secondary` or `none`), `emergency`. `contacts_primary_org_key` and `contacts_primary_site_key`: one primary for the organization and one per site. Goes with its organization or site |
| Policies `site_places_tenant`, `contacts_tenant` | `sites_tenant`'s, without `scope_read_orgs`: site-scoped people see their sites' rows, not the organization's own contacts. Enabled and forced |

## Notification channels, the outbox, notices and their journal (migration 00074, renumbered by the integrator)

ADR-0053, slice 3. Every table has row-level security enabled and forced, on
`easyrmm_scope_all()` and `easyrmm_scope_ids('easyrmm.scope_orgs')`. The nil
UUID is the platform's owner key.

| Table | Notes |
|---|---|
| `organizations` | Gains `CHECK (id <> nil)` (`organizations_id_not_nil`) |
| `notification_channels` | `owner` never NULL, equal to `organization_id` or the nil UUID (`notification_channels_owner`); `organization_id` is never the nil UUID; `kind` email or webhook; name 1 to 100 characters, unique per owner ignoring case (`notification_channels_name`); unique `(id, owner)` for the composite keys. Read: platform scope, the owner's own, and a platform channel in the scope of an organization it is shared with; written by the owner's scope |
| `notification_channel_shares` | `owner` fixed to the nil UUID, composite foreign key `(channel_id, owner)`: platform channels only. Written at platform scope only |
| `notification_channel_details` | Recipients (up to 20), webhook host and port, the sealed URL and signing secret, trusted authority, the `X-EasyPatch-*` switch, failing state and last error, the transport's generation. Its own policy on its own `owner`: no `EXISTS` on channels, no exception for platform rows |
| `notification_channel_approvals` | One row per channel: host, port, proposed addresses, approved prefixes, state `requested` or `approved`. An organization's scope may insert `requested` rows and delete; updating (approving) is platform scope only |
| `notification_deliveries` | The outbox. `charged_org` the organization charged (nil for the platform's own); `about` the organizations it concerns, `CHECK` that an organization's delivery is about that organization only (`notification_deliveries_owner_about`, `_owner_charged`); composite key `(channel_id, owner)` with `ON DELETE SET NULL (channel_id)`. An organization's scope inserts only its own tests |
| `notification_delivery_recipients` | Each recipient's outcome (a webhook has one row, `(webhook)`); follows its delivery |
| `notification_quotas` | Platform scope only; absent means the defaults (20 channels, 50 rules, 20 tests an hour, 600 messages an hour) |
| `notices` | Raised and resolved at platform scope; read, and acknowledged, in the owner organization's scope (or the site's); one open notice per organization, kind and subject (`notices_open`) |
| `notification_events` | The journal. Inserted only by `easyrmm_notice_journal()` (`SECURITY DEFINER`, owned by `easyrmm_owner`, policy `FOR INSERT TO easyrmm_owner`) on `notices` insert and on a change of resolution or acknowledgement; the runtime role has no `INSERT` and may update only `status`, `planned_at`, `failed_runs` and `error`, at platform scope |

The down migration drops them all, the triggers and the function, and the
constraint on `organizations`.

## Device alert rules, incidents, windows and the fleet-wide hold (migration 00077, renumbered by the integrator)

ADR-0053, slice 4. Every table has row-level security enabled and forced.

| Table | Notes |
|---|---|
| `devices` | Gains `agent_role` (what the agent reported), `role` and `role_set_by` (what someone with `monitoring.manage` set; wins), and `agent_uninstalled_at` (set from slice 7) |
| `notification_rules` | `owner` the organization or the nil UUID; `source` alerts or notices; `orgs_mode`, `sites_mode`, `groups_mode` any or list; `device_kinds`, `severities`, `conditions`, `checks` arrays (NULL is any, an empty array matches nothing); wait 0 to 1,440 minutes; reminders 0 to 720 hours; `ignore_windows` only for the platform's. Unique `(id, owner)`, name unique per owner. Read and written in the owner's scope |
| `notification_rule_orgs`, `_sites`, `_groups` | The lists. Sites as `(organization_id, site_id)` and groups as `(site_id, device_group_id)` with composite keys that cascade; `CHECK` that an organization's rule lists only its own organization |
| `notification_rule_channels` | `(rule_id, owner)` and `(channel_id, channel_owner)` composite keys; `channel_owner` is the rule's owner or the nil UUID. A trigger refuses a platform channel not shared with the organization and a twenty-first channel; unsharing deletes the links (`easyrmm_unshare_links`) |
| `site_maintenance_windows` | Weekly (`days`, `start_local`, up to 24 hours) or once (`starts_local`, up to 7 days), as the site's clock reads it; `active` is what the planner last saw. Read with the site, written in the organization's or site's scope |
| `alert_incidents`, `alert_incident_alerts` | An incident: the first alert's ID, the alert as it opened (device, site, names cleaned and clipped), its status (open, acknowledged, held after a policy change, resolved). No foreign keys, so a deletion takes nothing with it. Platform scope only |
| `alert_notifications` | Per subject (incident, site outage or notice) and channel: the rule's settings as they were when it matched, when the opening is due, what was told, folded into which outage. Foreign key to the channel only. Platform scope only |
| `site_outages` | A site's outage and when it ended; read with the site, written at platform scope |
| `fleet_silences` | The fleet-wide hold: start, end, the devices counted, who ended it. One open at a time. Platform scope only |
| `notification_events` | Gains the alert triggers: `easyrmm_alert_journal()` (`SECURITY DEFINER`) on `alerts` insert, on a change of status or acknowledgement, and on delete of an unresolved alert, with the deletion's reason (`merged`, or `device_removed`) from the transaction-local setting `easyrmm.alert_delete_reason` that the heartbeat's merge sets around its `DELETE` |

The down migration drops them, the triggers and functions, the alert rows of
the journal, and the columns of `devices`.

## What agents trust (migration 00080)

ADR-0055, slice 5b1. Both tables follow `devices`: read by whoever may see the device (row-level security enabled and forced), written with platform scope only. Neither holds a key or a secret: chains are public certificates.

| Table | Notes |
|---|---|
| `device_tls_trust` | One row per device, `scope` (`agent`: the EasyRMM agent's own trust; `easypatch`: the EasyPatch agent's, checked by the EasyRMM agent against the system's roots), `host` and `purpose` (`served`, `fallback`, `target`): the chain asked about (`chain`, DER in base64, leaf first, and `chain_digest`), the certificates a move adds (`add_certs`), the instruction's `chain_id` and `request_id`, the `state` (`pending`, `passed`, `failed`) with the agent's error (300 characters at most) and when it was requested, sent and checked. A different digest replaces the row and asks again |
| `device_tls_state` | One row per device that announced the capability: the `origin` its requests arrive at, its build's hash, whether it understands trust instructions, what it says it trusts (`system`, `ca-file`, `system+ca-file`; informational only), whether a move widened it, and the last refusal with the instruction it was for |

The down migration drops both tables.

## The job key ring and what agents report of it (migrations 00085 and 00086, ADR-0057 slice 1)

The server's job key moves out of the `settings` row `jobs.signing_key` into a ring, on the first start with this version, in one transaction under an advisory lock: the same seed and public key become generation 1, sealed again under the additional data `easyrmm:job_key:<generation>` and recorded as cut over to. The `settings` row becomes a **tombstone**, a JSON string that names the ADR, which a server from before the ring cannot read into its stored key, so it refuses to start against the migrated database instead of making a key of its own. A fresh install makes generation 1 and writes the tombstone too. The migration numbers are the builder's; the integrator renumbers them.

Written by the server with the platform scope. `job_keys`, `server_instances` and `server_restores` are the deployment's: row-level security allows the platform scope only. The four tables that hold a device's id follow the device, and are read by whoever may see the device.

| Table | Notes |
|---|---|
| `job_keys` | One row per key the server ever made: its `generation` (only increases, even across a restore), `public_key`, `sealed_seed` (NULL once the seed is deleted, with `seed_deleted_at`), why (`reason`: `initial`, `planned`, `moving`, `compromised`, `lost_replacement`), when, by whom and through what it was made, and when it was cut over to, marked compromised or lost |
| `server_instances` | One row per server process sharing the database: its version, when it started and last reloaded the ring, whether the updater holds it, and when it was last seen. A server removes its row when it stops; rows not seen for a day are purged |
| `issued_instructions` | Everything the server signed for a device: `kind`, `instruction_id`, `device_id`, the `generation` of the key that signed it and when. Appended in the transaction that signs; never updated; no foreign key, so removing or deleting a device keeps it; kept 90 days |
| `device_unknown_keys` | A key a device reports that this server never held ("Trusts an unknown key"): fingerprint, public key, the generation the device reported, first and last seen. Cleared when the device stops reporting it |
| `device_instruction_log` | One row per device whose agent sends its instruction log: the last sequence this server recorded, and, when the device claimed the server had acknowledged more than that, when and both sequences, with `not_checked_before` |
| `device_instruction_flags` | An entry of a device's log that matched nothing the server issued ("Ran instructions this server never issued"): its sequence, kind, ID, signer fingerprint and time, and when it was withdrawn |
| `server_restores` | When the server was restored from a backup: `incident` (the host command `easyrmm-server incident restored`, which applies to every device) or `suspected` (devices claimed more than the database recorded; the devices are listed, and it changes nothing for any other until an incident record confirms it) |

The migration also adds columns to `devices`: the last report of the keys the device trusts (`job_keys_report`, each key with its generation) with the signed request's time, the build it came with and when it first sent one; the generation enrollment gave it (`job_key_given_generation`, NULL for devices from before the ring); the cut-over the server sent it (`job_key_cutover_generation`, `job_key_cutover_at`, written by slice 2); and the SHA-256 of each certificate in the `ca.pem` its agent loaded (`agent_authorities`). `retired_devices` keeps the same report columns for a removed device, written when the device is removed. The settings tombstone, the report columns and the last restore are the only places the slice leaves state besides these tables.

The down migrations drop the tables and the columns. A server from before the ring cannot run against the migrated database whatever the down migration does, until the tombstone is replaced by the key: restoring the key means restoring the backup that holds it.

## Backups

See `docs/operations/backup-restore.md` (written with the Docker deployment).
