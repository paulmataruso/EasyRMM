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
| Secret sealing (AES-256-GCM, key rotation) | Tested | `server/internal/secrets`; infrastructure, no UI by design |
| Password hashing and policy (Argon2id, NIST 800-63B) | Complete | Server policy plus instant feedback in every password form |
| RBAC model (5 roles, platform/organization/site scopes, escalation guard) | Complete | Enforced by the API; the console hides what a role cannot do and shows the server's refusal otherwise |
| Database schema, migrations, split owner/app roles | Tested | `server/migrations`; infrastructure |
| Tenant isolation through PostgreSQL row-level security | Complete | Go integration tests across tenants; browser end-to-end test shows a technician cannot see another organization |
| Audit log (append-only, hash-chained, tamper detection) | Complete | API with organization/area/user filters and keyset paging; console Audit log tab; chain verification for super administrators |
| Sessions (idle/absolute expiry, rotation, revocation) | Complete | Account page lists sessions and signs them out |
| Password login, lockout, rate limiting | Complete | Sign-in page; locked users shown and unlockable on the user page |
| TOTP MFA, replay protection, recovery codes | Complete | Enrollment at first sign-in (QR and key), verification, recovery codes, new codes from the Account page, administrator reset |
| Password change and reset (e-mail and admin-issued links) | Complete | SMTP mailer (STARTTLS or implicit TLS); without SMTP the console shows a one-time link to pass on |
| WebAuthn / passkeys | Not started | Planned additional factor |
| HTTP API, CSRF, security headers | Complete | Strict JSON, error envelope, CSRF token bound to the session, Fetch Metadata/Origin checks; the console refreshes a rotated CSRF token once |
| First-run setup | Complete | One-time token from the data directory; console setup page; covered end to end |
| Organizations, sites, device groups | Complete | API and console (list with live filter, detail pages, create/edit/delete with typed confirmation) |
| User and role management | Complete | Invitations, role editor, disable/enable, unlock, MFA reset, password links, delete; last super administrator protected |
| Configuration and TLS edge (ACME/manual/offload) | Tested | Configured through environment variables; no UI by design |
| Docker Compose deployment (host networking) | Tested | Compose smoke test defined in CI; run locally, not yet on GitHub |
| Web console foundation (EasyPatch design system, ADR-0013) | Complete | Sign-in flows, shell, dashboard, organizations, settings, account; dark and light themes; Vitest unit tests and Playwright end-to-end tests |
| CI pipeline | Implemented | Go, frontend (typecheck, unit, build, design detector, Playwright) and Docker workflows plus security scanning. Not yet run on GitHub: pushing workflow files needs a token with the `workflow` scope |
| Licence clearance for EasyPatch-derived styles and logo | Not started | Owner action before a public release (ADR-0013) |

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
