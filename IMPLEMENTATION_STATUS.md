# Implementation status

What works today, and how each part was verified. How a feature works is in
the guide or decision record linked from its row
([decision records](docs/architecture/adr/README.md)).

Statuses:

* **Not started**
* **In progress** — work has begun.
* **Implemented** — code exists, but tests or other layers are missing.
* **Tested** — automated tests cover the behavior, but not every layer is
  done (e.g. backend only, no UI).
* **Complete** — backend, frontend, permissions, error handling and tests all
  exist.

A visible interface alone never counts as Implemented.

Last updated: 2026-11-21.

Where things were verified, besides the automated tests:

* **The real deployment**: installed from the published 1.0.0-rc.1 release
  bundle on a Linux host with two DNS names and Let's Encrypt certificates,
  then upgraded in place to 1.0.0-rc.2 and 1.0.0-rc.3 (patching engine
  1.12.0). Two Windows Server 2025 and two Linux computers are enrolled; on
  each upgrade their agents and EasyPatch agents updated themselves and
  kept reporting.
* **Real Windows machines**: Windows Server 2025 machines, in a test
  deployment and in the real deployment.
* **A test deployment**: one addressed by IP, with Linux test machines
  (Debian 13 and Rocky Linux 9 with systemd) in containers.
* **The bundle, contract, import and Authentik tests**: end-to-end tests that
  run in CI on GitHub
  ([Continuous integration](docs/development/README.md#continuous-integration)).
  The bundle test brings up the deployment a release ships, addressed by IP,
  and sets up a Debian machine through the console: install command,
  EasyPatch agent, a scan and an update installed. The contract test drives
  every call EasyRMM makes to the patching engine against the engine built
  from the same commit.

## Platform and security

| Feature | Status | Verified | Not yet verified |
|---|---|---|---|
| Organizations, sites and device groups, created, edited and deleted in the console | Complete | PostgreSQL integration and HTTP API tests; a browser end-to-end test builds an organization, site and device group. | — |
| Users, roles and permissions: five roles granted at platform, organization or site scope, with an escalation guard; invitations, disable, unlock, MFA reset; the last super administrator protected ([roles](docs/security/rbac.md)) | Complete | Unit tests of the role model; PostgreSQL integration tests; a browser end-to-end test invites a technician to one organization, who enrolls and sees only it. | — |
| Tenant isolation by PostgreSQL row-level security, with split owner and application roles (ADR-0002) | Complete | Go integration tests across tenants; a browser end-to-end test shows a technician cannot see another organization. | — |
| Database schema and migrations ([database](docs/architecture/database.md)) | Tested | Every integration test runs on a freshly migrated database; the real deployment's upgrade applied the new migrations. | — |
| Secret sealing (AES-256-GCM, key rotation); no UI by design | Tested | Unit tests. | — |
| Audit log: append-only and hash-chained, with filters and chain verification for super administrators (ADR-0007) | Complete | PostgreSQL integration tests (chain, tampering, deletion, concurrent writers); a browser end-to-end test checks the records and verifies the chain. | — |
| Audit forwarding to syslog (RFC 5424 over TLS, TCP or UDP), in order and resumable ([guide](docs/operations/audit-forwarding.md), ADR-0023) | Complete | Unit tests; PostgreSQL integration tests against loopback collectors over every transport, with and without client certificates; HTTP API and console tests; by hand against rsyslog 8.2504 over TLS, TCP and UDP. | — |
| Passwords: Argon2id and a NIST 800-63B policy with feedback in every form; change, and reset by email or an administrator's one-time link ([sign-in](docs/security/sign-in.md#password-reset)) | Complete | Unit tests of hashing and policy; PostgreSQL integration tests of change, reset and its limits; mail client unit tests. | A reset email through a real mail server. |
| Sign-in, lockout, rate limiting and sessions: idle and absolute expiry, rotation, sign-out from the **Account** page ([sign-in](docs/security/sign-in.md), ADR-0006) | Complete | Unit tests of rate limiting; PostgreSQL integration tests; a browser end-to-end test keeps a deep link through sign-in and the second factor. | — |
| Authenticator app (TOTP) with replay protection and recovery codes, enrolled at first sign-in; administrator reset | Complete | Unit and PostgreSQL integration tests; browser end-to-end tests enroll an authenticator at first sign-in. | — |
| Security keys and passkeys (WebAuthn) as a second factor or for passkey sign-in; not available on IP-only deployments ([sign-in](docs/security/sign-in.md#security-keys-and-passkeys), ADR-0032) | Complete | PostgreSQL integration tests drive a software authenticator through registration, sign-in and refusals; HTTP API and console tests; one run in Chromium with its virtual authenticator against the real server and console on localhost. On the first real deployment (a DNS name, Edge on Windows), a Bitwarden passkey worked as the second factor and for sign-in without a password. | A physical security key, and a platform passkey (Windows Hello, iCloud Keychain). The Chromium run is not part of CI. |
| Single sign-on with OpenID Connect, providers set up by super administrators ([guide](docs/security/single-sign-on.md), ADR-0034) | Complete | End to end against Dex in a container, in CI: service tests through Dex's real login form and an HTTP test through the whole server; console tests. | Entra ID, Google, Okta or Keycloak themselves. |
| Authentik as an option: `setup.sh --with-authentik` runs it behind EasyRMM's edge on its own name, invitation-only, with a second factor; `easyrmm-server recover` for a one-time sign-in link ([guide](docs/deployment/docker.md#sign-in-with-authentik), ADR-0044) | Complete | Config and compose tests; PostgreSQL integration tests; unit tests of the hairpin client and proxy; console tests; the Authentik test (an install addressed by IP). | A deployment with a real DNS name: ACME for Authentik's name, the hairpin through a real public address. WebAuthn as Authentik's factor; an Authentik upgrade in place. |
| HTTP API: strict JSON, an error envelope, a CSRF token bound to the session, Fetch Metadata and Origin checks, security headers | Complete | Unit tests of the middleware; HTTP API integration tests. | — |
| First-run setup with a one-time token from the data directory | Complete | A browser end-to-end test. | — |
| Technician console: navigation by section with trees, dashboard, dark and light themes ([development](docs/development/web-console.md), [design](DESIGN.md), ADR-0021) | Complete | Vitest unit tests and Playwright browser end-to-end tests. | — |
| Security review of sign-in, the agent channel and endpoints, remote access and integrations, and tenant isolation ([review](docs/security/security-review.md), [threat model](docs/security/threat-model.md)) | Findings fixed or documented | One high, four medium and several low findings, each fixed with a test that fails without the fix; three documented, not changed. | The gateway changes with a Windows MeshAgent (checked with a Linux one). No outside penetration test. |

## Remote access

| Feature | Status | Verified | Not yet verified |
|---|---|---|---|
| MeshCentral 1.3.1 in the deployment: a pinned, read-only container on loopback, configured by EasyRMM, reached over one control channel as a service account; no UI by design ([deployment](docs/deployment/docker.md#remote-access-meshcentral), ADR-0004, ADR-0005) | Tested | Unit tests; integration tests against the real container. | — |
| MeshCentral groups and accounts in step with EasyRMM: a group per site, an account per user with remote rights, drift repaired; status under **Settings → Remote access** | Complete | PostgreSQL integration tests against the real MeshCentral container. | — |
| Remote-access gateway on the MeshCentral name: sessions granted and revoked by EasyRMM, relays limited to the granted session types, no TCP or UDP tunnels; no UI by design (ADR-0014, ADR-0022, ADR-0033) | Tested | Unit tests; end to end with a real MeshAgent, including each known way of asking for a tunnel. | — |
| Remote desktop, terminal and files, embedded in the console; each start authorized and audited; quick connect | Complete | Go integration tests with a live terminal session through the relay; console tests; a browser end-to-end test of the error paths. On real Windows machines, remote desktop, terminal and files worked. | The desktop and files views are not exercised by an automated test with a graphical session. |
| Remote session latency: session view tuning, compression, small socket queues and pacing (ADR-0025) | Tested | Console tests against a stand-in MeshCentral page; Go tests of the socket options, pacing and pressure; measured with a Linux device. | The gains on a Windows device. |
| RDP sessions to Windows devices through MeshCentral's web RDP client, with their own permission, grant and audit record; credentials never stored (ADR-0026) | Complete | Go tests of the relay check, unit and through the gateway; console tests; on a test deployment, up to the TLS handshake with an RDP server (xrdp does not accept MeshCentral's RDP client). | **End to end against a Windows device.** |

## Endpoints (EasyRMM agent)

| Feature | Status | Verified | Not yet verified |
|---|---|---|---|
| Deployment tokens per site and optional device group: expiry, device limit, revocation; install commands shown again while a token is active ([guide](docs/deployment/agents.md#1-create-a-deployment-token), ADR-0015, ADR-0047) | Complete | A browser end-to-end test enrolls a device with a token; PostgreSQL integration and HTTP API tests, including showing commands again; console tests. | — |
| Install with approval: one command for every computer; devices wait under **Devices → Waiting for approval** and are approved into a site and device group, or rejected ([guide](docs/deployment/agents.md#one-command-for-every-computer-approval-tokens), ADR-0024) | Complete | Agent unit tests; PostgreSQL integration tests (long poll, limits, cleanup, permissions); an HTTP API test with the real agent client; console tests. On the real deployment, Linux computers enrolled with an approval token and were approved in the console. | On Windows. |
| EasyRMM agent for Windows and Linux: Ed25519 device key, signed requests with replay protection, a heartbeat every minute, `status` command (ADR-0009) | Complete | Integration tests run the real agent binary in a container against a real server and MeshCentral; Windows and Linux agents report to the real deployment. | — |
| Linux install script: one `curl … \| sudo sh` line, a checksum-verified download over HTTPS; agents for x86-64, ARM64, ARMv7 and x86 ([guide](docs/deployment/agents.md#3-install-on-linux)) | Complete | Browser end-to-end and integration tests; run as the console shows it on a Debian 13 machine with systemd and on the real deployment's Linux computers. | A range of distributions. |
| Windows agent and PowerShell install: `easyrmm-agent.exe` (x64, ARM64) as a service with MeshAgent beside it, state folders for SYSTEM and Administrators only, `install.ps1` pinned to the server's key ([guide](docs/deployment/agents.md#2-install-on-windows), ADR-0020) | Complete | Unit tests, also on a Windows CI runner; the Windows build enrolled, reported and ran a cmd job under Wine. On real Windows machines: the PowerShell one-liner installed and enrolled the agent; inventory; PowerShell and cmd jobs; installing again kept the device's identity; the folders' access lists; the service restarting after a failure. | A cmd timeout ending the script's children (seen under Wine); ARM64. |
| MeshAgent install and correlation: the agent installs MeshAgent with its site's settings and the server links the node to the device; a node no device claims waits two minutes before it is listed as discovered | Complete | End to end, including a remote session to the enrolled device and offline detection; the two-minute wait by an integration test. | The wait on real machines (it keeps an approved device from showing twice). |
| Coordinated agent updates: a few devices at a time (**Settings → Agent updates**) or one device from its page; signed instructions naming the build's SHA-256; rollback when a new build crashes or cannot reach the server ([guide](docs/deployment/agents.md#updating-agents), ADR-0027) | Complete | Unit, integration and console tests; on a test deployment, two Linux agents updated one at a time, and a crashing build was undone and reported. On real Windows machines, two agents updated within two minutes, with MeshAgent and the EasyPatch agent still running. On the real deployment's upgrade, all four agents (Windows and Linux) updated within minutes and kept reporting. | A crashing build undone on Windows. |
| Windows agents signed with the operator's own code signing certificate: download the server's builds, sign them with your own tools, upload them; the server checks the Authenticode digest is its own build's and the signature verifies, then hands the signed build out and updates agents to it; *Only signed builds* ([guide](docs/deployment/agents.md#signing-the-windows-agent), ADR-0049) | Complete | Unit tests of the Authenticode reader against programs signed by `osslsigncode` (RSA, ECDSA, nested, both kinds of timestamp) and refused files; on CI's Windows runner, the Windows agent signed by `signtool` and read back; PostgreSQL integration tests of uploads, refusals, serving, *Only signed builds*, upgrades and pruning; HTTP API and console tests. Real agents built for x86-64 and ARM64, signed by `osslsigncode`, verified and matched to their unsigned builds; a changed byte refused. | A certificate from a public certificate authority, and signed agents installed and updated on real Windows computers. |
| Uninstall: `easyrmm-agent uninstall` removes the agent, MeshAgent and their state; the device stays listed as offline ([guide](docs/deployment/agents.md#uninstalling)) | Tested | Agent unit tests. | — |
| Removing a device: **Remove** on its page has its agents uninstall themselves with a signed instruction and deletes the device when the agent confirms; a failure shows why, with **Ask again**, **Remove anyway** and **Keep the device**; a device removed by force that comes back within 90 days still cleans itself up; MeshCentral forgets its node; **Remove** for endpoints only the patching engine has ([guide](docs/deployment/agents.md#removing-a-device), ADR-0050) | Complete | Unit tests; PostgreSQL integration and HTTP API tests (permissions, cancelling, failure reports, forced removal and a returning agent, replays); the real agent in a container removed itself and MeshAgent on the instruction and the device was deleted; a real MeshAgent's node removed from MeshCentral and kept out of the device list when it returned; the bundle test removes the Debian machine from the console, after which EasyRMM's agent, MeshAgent and the EasyPatch agent's package are gone from it; console tests. | On Windows; on the real deployment. |
| Devices list and device page: enrolled and MeshCentral-discovered devices, filters, a device tree by organization and site with quick connect, recent remote sessions | Complete | Console tests; a browser end-to-end test shows devices and remote access honestly when MeshCentral is not running. | — |

## Monitoring and automation

| Feature | Status | Verified | Not yet verified |
|---|---|---|---|
| Inventory and health: hardware, operating system, network and installed software, sent when they change; processor, memory, disk, load and processes with every heartbeat, kept for charts ([guide](docs/operations/inventory.md), ADR-0018) | Complete | Unit, PostgreSQL integration and HTTP API tests; the real agent in a container; Windows inventory reported by real Windows machines. | — |
| Monitoring and alerts: offline, processor, memory and disk policies at shared, organization and site level, evaluated every minute; alerts acknowledged and resolved in the console ([guide](docs/operations/alerts.md), ADR-0019) | Complete | Unit, PostgreSQL integration, HTTP API and console tests. | — |
| Scripts and jobs: Bash, sh and Python 3 on Linux, PowerShell and cmd on Windows; a library at shared, organization and site level; signed jobs on up to 500 devices, with each device's output ([guide](docs/operations/scripts-and-jobs.md), ADR-0017) | Complete | Unit, PostgreSQL integration and HTTP API tests; the real agent in a container; PowerShell and cmd jobs on real Windows machines; jobs on 500 simulated devices in the soak drill. | — |
| Software deployment: install, update and uninstall through winget or Chocolatey on Windows, and apt-get, dnf, yum or zypper on Linux ([guide](docs/operations/software.md), ADR-0028) | Complete for Linux; built for Windows | Unit tests (the Linux script against stand-in package managers, including names that try to run commands); PostgreSQL integration, HTTP API and console tests; on a test deployment, a Debian agent installed and uninstalled a package through the console. | **The winget and Chocolatey scripts on a Windows machine.** |
| Reports: device inventory, installed software, device health and alert history, in the console and as audited CSV downloads ([guide](docs/operations/reports.md), ADR-0029) | Complete | Unit tests (CSV output and its injection guard); PostgreSQL integration tests for every report, filter and role scope; HTTP API and console tests. | — |

## Patching

Patching runs on the patching engine inside every deployment, with the
EasyPatch agent on each computer ([patching guide](docs/operations/patching.md),
[the EasyPatch agent](docs/deployment/patching-agent.md)).

| Feature | Status | Verified | Not yet verified |
|---|---|---|---|
| The patching engine in every deployment: its API and worker on loopback with their own database; EasyRMM calls it with a signed statement per request and keeps its organizations and sites in step ([patching engine](docs/architecture/patching-engine.md), ADR-0038, ADR-0040, ADR-0043) | Complete | Compose, contract, bundle and import tests; the bundle test also checks that the engine refuses missing, forged, altered, expired, replayed and out-of-scope statements. On the real deployment, the engine ran the images the release manifest names and was upgraded in place. | — |
| **Settings → Patching engine**: the engine's version and status, organizations in step, **Install automatically**; devices linked by what the EasyRMM agent reads from the local EasyPatch agent, checked against the engine ([guide](docs/operations/patching.md#setting-it-up)) | Complete | Client unit tests; PostgreSQL integration tests (links and every refusal reason, roles, audit); HTTP API, console and bundle tests. On real Windows machines enrolled with a separate EasyPatch server, the link was refused with that reason. | — |
| Devices, scans and installs: **Patching → Devices** and a device's **Patches** tab; scan and install on one device or many, now or at a set time; cancel; every action audited per device ([guide](docs/operations/patching.md#devices)) | Complete | PostgreSQL integration, HTTP API, contract, console and bundle tests (an update installed on a Debian machine from the **Patches** tab). On the real deployment, two Windows Server 2025 machines and an Ubuntu machine scanned; the Windows machines were compliant, and an install job on both completed with nothing to install. | **A real Windows update installed through EasyRMM.** |
| More on a device's **Patches** tab: install preview, excluding and including an update, removing an installed Windows update, messages to signed-in users, an EasyPatch agent update ([guide](docs/operations/patching.md#excluding-and-removing-updates)) | Complete | PostgreSQL integration, HTTP API, contract, console and bundle tests (exclude, preview, include and install on a Debian machine). | Removal, messages and the tray icon on a real Windows machine; an EasyPatch agent update that goes through. |
| Overview, updates across devices and holds: what needs attention worst first, including open patching alerts; the update catalogue with CVEs, CISA KEV and exploitation; install or remove an update across devices; hold it in an organization or everywhere ([guide](docs/operations/patching.md#overview)) | Complete | PostgreSQL integration, HTTP API, contract, console and bundle tests (the overview, an update's page, hold and release on a Debian machine). | Removal across devices on a real Windows machine. |
| Patch jobs: filters by type, status, trigger and time; progress, items and events; cancel; **Retry** for jobs that did not do everything ([guide](docs/operations/patching.md#jobs)) | Complete | PostgreSQL integration, HTTP API, contract, console and bundle tests. | — |
| Restarts: a countdown, a prompt with or without a deadline, or at once; only if a restart is pending, or always; servers only when ticked by name; now or up to 31 days ahead ([guide](docs/operations/patching.md#restarts)) | Complete | PostgreSQL integration, HTTP API and console tests; the contract test (restart options delivered to a simulated agent); the bundle test (a restart planned, nothing sent). | A real machine restarted through EasyRMM; the prompt modes on a Windows machine with someone signed in. |
| Patch policies and tags: one editor for the default, organization, site, tag and device layers, each value inherited with its source or overridden ([guide](docs/operations/patching.md#policies)) | Complete | PostgreSQL integration, HTTP API, console and bundle tests (each layer shown in a Debian machine's policy in effect); the contract test (every field round trip). | Policy changes applied by a real Windows machine. |
| Patch reports: **Patch compliance** with its trend and **Patch installations** under **Reports**, with CSV; monthly PDF reports per organization, downloaded or emailed, also on a schedule ([guide](docs/operations/reports.md#patch-reports)) | Complete | PostgreSQL integration, HTTP API, contract, console and bundle tests (rows, CSV and a PDF from a Debian machine; the message when no mail server is set). | A report emailed through a real mail server, or made from a real Windows fleet. |
| **Settings → Patching**: the engine's settings, vulnerability feeds, OS lifecycle, agent packages and the engine's audit log ([guide](docs/operations/patching.md#engine-settings)) | Complete | PostgreSQL integration, HTTP API, contract, console and bundle tests. | — |
| Patching alerts, alert rules and notifications: alerts acknowledged in the console; nine rule types; email and Slack, Teams or generic webhook channels ([guide](docs/operations/patching.md#alerts)) | Complete | PostgreSQL integration, HTTP API, contract and console tests; the bundle test (the engine raised an alert for a Debian machine, acknowledged in the console and queued for an email channel). | Real email or webhook delivery. |
| The EasyPatch agent installed by EasyRMM: on chosen devices, or automatically per organization; a signed instruction with a single-use enrollment token; msiexec, apt-get or dnf; **Stop patching** for a device removes it ([guide](docs/operations/patching.md#installing-the-easypatch-agent), ADR-0031) | Complete | Unit tests, with stand-in package managers for Linux; PostgreSQL integration, HTTP API, console and bundle tests. On test machines: apt-get on Debian 13, dnf on Rocky Linux 9, and a machine without systemd refused with the reason; on real Windows machines that already ran an EasyPatch agent, refused with that reason. On the real deployment: msiexec on two Windows Server 2025 machines (about a minute each) and apt on Ubuntu, each enrolled and scanned. | ARM64; **Install automatically** on real machines; Windows with EasyRMM's own certificate authority (deployments addressed by IP). |
| Further names for EasyPatch agents (`EASYRMM_PATCHING_AGENT_HOSTNAMES`), on which the edge forwards only the engine's agent paths ([deployment](docs/deployment/docker.md#patching-engine)) | Complete | Unit and integration tests; the import test serves an imported agent on its old name. | — |
| A warning on scripts that install updates themselves, line by line, in the script editor, on the script's page and in the run dialog; it refuses nothing ([guide](docs/operations/scripts-and-jobs.md#scripts-that-install-updates)) | Complete | Unit tests per shell; console tests. | — |
| Importing a standalone EasyPatch server (1.4 to 1.10) with `deploy/scripts/import-easypatch.sh`, into a deployment whose engine patches nothing yet ([guide](docs/operations/import-easypatch.md), ADR-0045) | Complete | The engine's integration tests on a 1.4-schema database; Go integration tests; the import test (EasyPatch 1.10.0 with a real Linux agent, which then checks in and scans through EasyRMM on its old name). An EasyRMM agent linking to an imported endpoint: integration tests only. | Versions 1.4 to 1.9 (accepted, untested); a Windows agent; a real server with a DNS move. |
| The macOS EasyPatch agent: experimental and not released; EasyRMM does not install it ([the EasyPatch agent](docs/deployment/patching-agent.md#macos)) | In progress | Built and install smoke-tested in CI (x64 and arm64). | Patching a real Mac. |

## Deployment, operations and releases

| Feature | Status | Verified | Not yet verified |
|---|---|---|---|
| Docker Compose deployment on host networking, every listener but the edge on loopback, set up with `setup.sh` ([guide](docs/deployment/docker.md)) | Tested | Unit and compose tests; CI's Compose smoke test; the drills and the bundle test deploy with `setup.sh`. The real deployment, installed from the published bundle: every container healthy, running the images the release manifest names. | — |
| Configuration and TLS edge: ACME, manual certificates, an internal certificate authority, or TLS offload behind NGINX, set through environment variables; no UI by design ([TLS modes](docs/deployment/docker.md#tls-modes), [NGINX](docs/deployment/nginx.md)) | Tested | Unit tests; Let's Encrypt certificates for two DNS names on the real deployment; the internal authority in the bundle test. | — |
| Access by IP address, beside the DNS name or alone: the server's own certificate authority and install commands pinned to its key ([without DNS](docs/deployment/docker.md#without-dns), ADR-0016) | Complete | Unit tests, including curl against the pin; an integration test of the stored authority; the bundle test; on a test deployment over IP only, a Linux device enrolled with the pinned install, then sign-in and a terminal session. | — |
| Upgrading in place, backup first ([guide](docs/operations/upgrading.md)) | Tested | The real deployment upgraded from 1.0.0-rc.1 to 1.0.0-rc.2 by the guide: migrations applied, and every agent updated itself and kept reporting. | — |
| Backup and restore ([guide](docs/operations/backup-restore.md), [drill](docs/development/drills.md#backup-and-restore)) | Tested | The drill backs up a server with a real agent, deletes it and restores onto a new checkout, then checks TLS, the same password and authenticator, the audit chain, the agent reconnecting without reinstalling and running a job, MeshCentral's identity, and the patching engine's organizations and keys. Passed on 16 November 2026, and on 19 November with the patching engine. | MeshAgent reconnecting (the drill's device has none); restoring onto a newer release. |
| Load and soak ([drill](docs/development/drills.md#load-and-soak)) | Tested | 2,000 simulated agents for an hour against a Compose deployment: no errors, heartbeat p99 136 ms, jobs on 500 devices in a median 6.0 s, server memory steady near 480 MiB. | More than 2,000 devices; a server on separate hardware from the simulator. |
| Continuous integration: Go, console and engine builds and tests (Windows agent tests on a Windows runner), integration tests with PostgreSQL, MeshCentral and Dex, the contract, bundle, import and Authentik tests, coverage floors, actionlint, and security scanning (CodeQL for Go, C# and JavaScript, gitleaks, Trivy, govulncheck) ([guide](docs/development/README.md#continuous-integration)) | Tested | Runs on GitHub; pull requests ran it in full before merging. | — |
| Releases: `release.yml` on `easyrmm-v*` tags runs every check again, then publishes EasyRMM's and the patching engine's images (amd64, arm64; scanned, with SBOM, provenance and attestations), EasyPatch agent packages signed with the release key, the deployment bundle with the engine pinned by digest, a manifest and `SHA256SUMS` ([guide](docs/development/releasing.md), [code signing](CODE_SIGNING.md), ADR-0043) | Tested | Published 1.0.0-rc.1 and 1.0.0-rc.2 (patching engine 1.11.0 and 1.11.1) on GitHub, with MSI, deb and rpm agent packages for x64 and arm64; rc.1's checksums and attestations checked from outside; the bundle builds reproducibly; the real deployment installed from rc.1's bundle. | — |

## Not built

Not started, so that nobody assumes them:

* Devices: moving, renaming and retiring devices; removing a device from the
  console.
* EasyRMM agent packages: a Windows MSI and code signing; Linux DEB and RPM
  packages (the install script covers Linux).
* Monitoring: email and webhook notifications for monitoring alerts (patching
  alerts have them).
* Inventory history (what changed when).
* Scripts: schedules, and output streamed while a script runs.
* Software deployment: a package catalog, private installers, "keep
  installed" policies.
* Device, software, health and alert reports: scheduled, emailed, PDF or
  custom reports.
* Sign-in: SAML, just-in-time accounts, group-to-role mapping, required
  single sign-on.
* Audit forwarding over RELP.
* Patching: removing and holding an update in one step; forcing a restart;
  giving or taking a tag from many devices at once.
