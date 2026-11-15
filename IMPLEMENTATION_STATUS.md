# Implementation status

Statuses:

* **Not started**
* **In progress** — work has begun.
* **Implemented** — code exists, but tests or other layers are missing.
* **Tested** — automated tests cover the behavior, but not every layer is
  done (e.g. backend only, no UI).
* **Complete** — backend, frontend, permissions, error handling and tests all
  exist.

A visible interface alone never counts as Implemented.

Last updated: 2026-11-15.

## Platform foundation

| Feature | Status | Notes |
|---|---|---|
| Secret sealing (AES-256-GCM, key rotation) | Tested | `server/internal/secrets` (94% coverage) |
| Password hashing and policy (Argon2id, NIST 800-63B) | Tested | `server/internal/auth/password.go` |
| RBAC model (5 roles, platform/organization/site scopes, escalation guard) | Tested | `server/internal/rbac` (93% coverage) |
| Database schema, migrations, split owner/app roles | Tested | `server/migrations/00001_core.sql` |
| Tenant isolation through PostgreSQL row-level security | Tested | Integration tests cover reads, writes, moves and inserts across tenants |
| Audit log (append-only, hash-chained, tamper detection) | Tested | Backend only; no API or UI yet |
| Sessions (idle/absolute expiry, rotation, revocation) | Tested | Backend service only; no HTTP endpoints yet |
| Password login, lockout, rate limiting | Tested | Backend service only |
| TOTP MFA, replay protection, recovery codes | Tested | Backend service only |
| Password change and reset (e-mail and admin-issued links) | Tested | Backend service only; SMTP mailer not implemented |
| WebAuthn / passkeys | Not started | Planned additional factor |
| HTTP API, CSRF, security headers | Not started | |
| First-run setup | Not started | |
| Organizations, sites, device groups | In progress | Schema and RLS done; service, API and UI not started |
| User and role management | In progress | Model and escalation rules done; API and UI not started |
| Configuration and TLS edge (ACME/manual/offload) | Not started | |
| Docker Compose deployment (host networking) | Not started | |
| Web UI foundation (Impeccable) | Not started | |
| CI pipeline | Implemented | Lint, unit and integration tests, coverage floors, gitleaks, govulncheck, licences, Trivy, CodeQL, dependency review |

## Remote access (MeshCentral)

| Feature | Status |
|---|---|
| MeshCentral deployment and configuration | Not started |
| Control-channel client and user/group sync | Not started |
| Edge gateway and session launch | Not started |
| Remote desktop / terminal / files embedding | Not started |

## Endpoint

| Feature | Status |
|---|---|
| Go agent: enrollment, identity, protocol | Not started |
| MeshAgent install and correlation | Not started |
| Windows MSI / EXE / PowerShell | Not started |
| Linux DEB / RPM / script | Not started |
| Coordinated updates and uninstall | Not started |

## Core RMM

| Feature | Status |
|---|---|
| Inventory and telemetry | Not started |
| Monitoring and alerting | Not started |
| Scripts and jobs | Not started |
| Software deployment | Not started |
| Reporting | Not started |

## EasyPatch

| Feature | Status |
|---|---|
| Required EasyPatch changes | Not started (documented in `docs/integrations/easypatch.md`) |
| Connector and native patch UI | Not started |
