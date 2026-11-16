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

Last updated: 2026-11-16.

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
| Configuration and TLS edge (ACME/manual/internal/offload) | Tested | Configured through environment variables; no UI by design |
| Access by IP address (ADR-0016) | Complete | IP access beside the DNS name (on by default, `EASYRMM_IP_ACCESS=false` turns it off) or an IP-only deployment; routing by host and port; the server's own certificate authority (sealed in the database, renewed with a stable key); key-pinned install commands; CA fingerprint and download on **Devices → Add devices**. Unit tests (including curl against the pin), an integration test of the stored authority, and a check on the preview over IP only: enrollment of a Linux test device with the pinned install, sign-in at `https://<ip>` and a terminal session through `https://<ip>:4443` running a command on the device. In a DNS deployment, MeshAgent still uses the MeshCentral name |
| Docker Compose deployment (host networking) | Tested | Compose smoke test defined in CI; run locally, not yet on GitHub |
| Web console foundation (EasyPatch design system, ADR-0013) | Complete | Sign-in flows, shell, dashboard, organizations, settings, account; dark and light themes; Vitest unit tests and Playwright end-to-end tests |
| CI pipeline | Implemented | Go, frontend (typecheck, unit, build, design detector, Playwright) and Docker workflows plus security scanning. Not yet run on GitHub: pushing workflow files needs a token with the `workflow` scope |
| Licence clearance for EasyPatch-derived styles and logo | Not started | Owner action before a public release (ADR-0013) |

## Remote access (MeshCentral)

| Feature | Status | Notes |
|---|---|---|
| MeshCentral deployment and configuration | Tested | Pinned MeshCentral 1.3.1 container (host networking, loopback only, read-only, no capabilities); `config.json` written by the server; service account bootstrap; restart on configuration change. Integration tests run against the real container. No UI by design |
| Control-channel client | Tested | One `control.ashx` connection as the service account, request correlation, reconnect with backoff, keepalive, events; login token never logged |
| Device groups and accounts in step with EasyRMM | Complete | A group per site, an account per user with remote rights, rights per site from RBAC; event-driven plus every five minutes; repairs drift, adopts lost groups, removes stale ones. Status under **Settings → Remote access** |
| Edge gateway on the MeshCentral hostname | Tested | Agent/browser split, grant cookie, blocked features, revocation of open sessions within 15 s (ADR-0014); relays limited to EasyRMM's session types on granted devices, no TCP or UDP tunnels, the control channel inspected message by message (ADR-0022). Verified end to end with a real MeshAgent, including each known way of asking for a tunnel; no UI by design |
| Devices list and device page | Complete | Enrolled and MeshCentral-discovered devices; filters by organization, site, status and name; row travel with j/k; agent version, enrollment and remote-access state; recent remote sessions from the audit log. The sidebar shows a device tree on the devices pages (organization › site › device with online counts, filter, keyboard navigation, quick connect) that narrows the list or opens a device; organizations, alerts, scripts, jobs and settings have trees of their own (ADR-0021). Listed with remote access turned off too. Moving, renaming and retiring devices are not available yet |
| Remote desktop / terminal / files | Complete | Started from a device's page into a full-window embedded session, in the same tab or a window of its own (one per device, reused); each start is authorized and audited; reconnect, switch between kinds, full screen; quick connect from the devices tree and the dashboard's recent connections. Covered by Go integration tests with a live terminal session through the relay, Vitest page tests and a browser end-to-end test of the error paths. The desktop and files views are MeshCentral's, embedded; they are not exercised by an automated test with a graphical session |

## Endpoint

| Feature | Status | Notes |
|---|---|---|
| Deployment tokens | Complete | Per site and optional device group, expiry, device limit, revocation; shown once, stored hashed; audited. Console **Devices → Add devices** creates, lists and revokes them (ADR-0015) |
| Go agent: enrollment, identity, heartbeat | Complete | `easyrmm-agent` for Windows and Linux: Ed25519 device key, signed requests with replay protection, heartbeat every minute with backoff, `status` command. Device online state and facts in the console. Integration tests run the real agent binary in a container against a real server and MeshCentral |
| MeshAgent install and correlation | Complete | The agent fetches MeshAgent and its site's settings from MeshCentral through EasyRMM, runs it under systemd (or as a child process without systemd), and reports its node id; the server links the node within the device's site, merges a discovered duplicate, and audits it. Covered end to end, including a remote session to the enrolled device and offline detection |
| Linux install script | Complete | `curl … /api/agent/v1/install.sh \| sudo sh -s -- --token …`, checksum-verified download, HTTPS only; agents for x86-64, ARM64, ARMv7 and x86 built into the Docker image. Tested by the browser end-to-end test (token to enrolled device) and the integration tests; not yet run on a range of distributions |
| Uninstall | Tested | `easyrmm-agent uninstall` removes the agent, MeshAgent and their state; the device stays listed as offline. No console action to remove a device yet |
| Windows agent and PowerShell install | Verified on Windows Server 2025 | `easyrmm-agent.exe` for x64 and ARM64 as the **EasyRMMAgent** service (LocalSystem, automatic, restarted on failure), MeshAgent as **EasyRMMMeshAgent**, state folders readable by SYSTEM and Administrators only, a log file; `install.ps1` per server address with a PowerShell one-liner on **Devices → Add devices** (Windows first), pinned to the server's key by IP address; PowerShell and cmd scripts in a job object; Windows inventory (SMBIOS, processors, disks, adapters, Windows edition and build, installed programs with publishers) and health (ADR-0020). Verified: unit tests; the installer parsed by PowerShell 7.6 and its key pin matched against .NET's own computation and the live server; the agent built for Windows enrolled with the preview server under Wine and reported inventory, programs and health, and ran a cmd job with arguments through the console; a cmd timeout ended the script's children. On a real Windows Server 2025 machine (2026-11-16) the PowerShell one-liner installed and enrolled the agent, which reported its inventory, and remote desktop, terminal and files worked. **Not yet verified on real Windows**: PowerShell and cmd jobs, the state folders' access lists and the service's recovery settings (the Windows CI job, `windows-latest`, covers the unit tests). MSI and code signing not started |
| Linux DEB / RPM packages | Not started | The install script covers Linux for now |
| Coordinated agent updates | Not started | Reinstalling with the script updates the binary today |

## Core RMM

| Feature | Status |
|---|---|
| Inventory and telemetry | Complete for Linux; built for Windows (ADR-0020, see the Windows agent row): hardware (system, firmware, processor, memory, disks), operating system, network interfaces, gateways and DNS, and installed packages (dpkg, RPM, apk, pacman), sent when they change; processor, memory, swap, load, uptime, processes and filesystem use with every heartbeat, kept for charts (`EASYRMM_METRICS_RETENTION`). Device page tabs for health with charts, hardware and software (the fleet-wide Software page was removed in ADR-0021; the API remains). Tested by unit tests, PostgreSQL integration tests, an HTTP API test and the real agent in a container (ADR-0018). Inventory history (what changed when) is not kept yet |
| Monitoring and alerting | Complete for alerts in the console: policies at shared, organization and site level for offline (any agent), processor, memory and disk use held for a number of minutes, with four shared policies on new installations; evaluated every minute under an advisory lock; alerts open, acknowledged and resolved (on their own or by hand), with audit and retention (`EASYRMM_ALERT_RETENTION`). Alerts page with policies, a device card, dashboard and menu counts. Tested by unit tests, PostgreSQL integration tests, an HTTP API test and vitest (ADR-0019). E-mail and webhook notifications are not built yet; processor, memory and disk need the EasyRMM agent (Windows or Linux) |
| Scripts and jobs | Complete for Linux (Bash, sh, Python 3); PowerShell and cmd for Windows built (ADR-0020): script library at shared, organization and site level; jobs on up to 500 devices with arguments, timeout and an offline wait; Ed25519-signed delivery over a long poll; per-device status, exit code and output (head and tail, 256 KiB per stream); cancel; retention; audit. Console pages for the library, jobs and runs, and on the device page. Tested by unit tests, PostgreSQL integration tests, an HTTP API test and the real agent in a container (ADR-0017). A shell runs only on its platform, enforced by the server and the console. Output is not streamed while a script runs; no schedules yet |
| Software deployment | Not started |
| Reporting | Not started |

## EasyPatch

| Feature | Status |
|---|---|
| Required EasyPatch changes | Not started (documented in `docs/integrations/easypatch.md`) |
| Connector and native patch UI | Not started |
