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

## Remote access (migration 00002)

| Table | Notes |
|---|---|
| `devices` | Managed endpoints, enrolled by the EasyRMM agent (migration 00003) or discovered from MeshCentral: `mesh_node_id` links the row to a MeshCentral node, `remote_online` and `last_seen_at` follow MeshAgent's connection. Site-scoped row-level security like the tenancy tables; `(organization_id, site_id)` → `sites` with `ON DELETE RESTRICT`, so a site with devices cannot be deleted |
| `mesh_sites` | The MeshCentral device group of each site (`mesh_id`) and the name last written to it. Platform scope only: written by the synchronizer, never by user requests |
| `remote_grants` | One row per remote session launched from the console: SHA-256 of the one-time launch token and, once redeemed, of the gateway cookie; the EasyRMM session, user, device and kind. The grant is valid only while that session is. Rows whose session has ended, and launch links never opened, are deleted after a day. Platform scope only |

The MeshCentral keys EasyRMM shares with MeshCentral (the login-token key and
MeshCentral's session key) are stored sealed with `EASYRMM_SECRET_KEY` in
`settings` under `meshcentral.secrets`, and written to MeshCentral's
`config.json` at start-up.

## Agent enrollment (migration 00003)

| Table / column | Notes |
|---|---|
| `enrollment_tokens` | Deployment tokens: site, optional device group, name, SHA-256 of the token, expiry, optional `max_uses` and the `uses` count, creator, `revoked_at`. Tenant row-level security like the tenancy tables |
| `devices.agent_public_key` | The enrolled agent's Ed25519 public key, unique. A row with a key is an enrolled device; one without is discovered from MeshCentral only (`devices_enrolled_has_key` keeps `enrolled_at` and the key together) |
| `devices.agent_version`, `agent_arch`, `agent_last_seen_at`, `enrolled_at`, `enrollment_token_id` | What the agent last reported, and how it enrolled. `devices_agent_seen_idx` serves the online filter |
| `agent_nonces` | Nonces of signed agent requests until they could no longer be replayed; deleted when they expire. Platform scope only |

`easyrmm_touch_device()` updates `devices.updated_at` only when something
other than liveness changed (`last_seen_at`, `agent_last_seen_at`,
`remote_online`), so heartbeats do not rewrite it every minute.

## EasyPatch connector (migration 00013)

| Table | Notes |
|---|---|
| `easypatch_connection` | At most one row: the EasyPatch server's https URL, its API token sealed with `EASYRMM_SECRET_KEY` (associated data `easypatch_connection.token_sealed`), an optional CA certificate, and what the last check found (version, public URL, capabilities, whether the token can act, last error). Platform scope, and the owner role for migrations |
| `easypatch_organizations` | Which EasyPatch organization patches an EasyRMM organization: one each way (`easypatch_id` is unique). Read through the organization's row-level security; written with platform scope only |
| `easypatch_devices` | A device's link to its EasyPatch endpoint: `pending`, `linked` (with the endpoint and when) or `unlinked` (with the reason), the key fingerprint it was checked with, and when. A linked endpoint belongs to one device (partial unique index). Read through the device's row-level security; written with platform scope only |

No patch data is stored: the console reads it from EasyPatch (ADR-0030).

## EasyPatch agent installs (migration 00014)

| Table | Notes |
|---|---|
| `easypatch_organizations.auto_install` | Whether EasyRMM installs the EasyPatch agent on the organization's devices that have none, by itself (ADR-0031) |
| `easypatch_installs` | One row per device: the latest EasyPatch agent install, `waiting`, `sent` (with the attempt id sent to the agent, when, and the EasyPatch enrollment token's id, never the token), `succeeded` or `failed` (with the reason); whether it was automatic, who asked, attempts, and a note while it waits (an agent too old to install it). Read through the device's row-level security; written with platform scope only |

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

## Backups

See `docs/operations/backup-restore.md` (written with the Docker deployment).
