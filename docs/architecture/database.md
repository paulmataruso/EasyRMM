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

## Backups

See `docs/operations/backup-restore.md` (written with the Docker deployment).
