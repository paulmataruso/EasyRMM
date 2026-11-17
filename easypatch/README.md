<p align="center">
  <img src="frontend/public/logo.svg" width="112" alt="">
</p>
<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="frontend/public/wordmark.svg">
    <img src="frontend/public/wordmark-light.svg" height="72" alt="EasyPatch">
  </picture>
</h1>

<p align="center">
  <b>Self-hosted Windows and Linux patch management for Managed Service Providers.</b>
</p>

<p align="center">
  <a href="https://github.com/paulmataruso/EasyPatch/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/paulmataruso/EasyPatch?sort=semver"></a>
  <a href="https://github.com/paulmataruso/EasyPatch/actions/workflows/server.yml"><img alt="Server build" src="https://github.com/paulmataruso/EasyPatch/actions/workflows/server.yml/badge.svg"></a>
  <a href="https://github.com/paulmataruso/EasyPatch/actions/workflows/agent.yml"><img alt="Agent build" src="https://github.com/paulmataruso/EasyPatch/actions/workflows/agent.yml/badge.svg"></a>
  <a href="LICENSE.md"><img alt="License: FSL-1.1-ALv2" src="https://img.shields.io/badge/license-FSL--1.1--ALv2-blue"></a>
  <img alt="Platforms: Windows and Linux agents" src="https://img.shields.io/badge/agents-Windows%20%7C%20Linux-informational">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#features">Features</a> ·
  <a href="docs/installation.md">Installation</a> ·
  <a href="https://github.com/paulmataruso/EasyPatch/releases">Downloads</a> ·
  <a href="#license">License</a>
</p>

EasyPatch is a self-hosted patch management platform for Managed Service Providers. A small
agent reports Windows Update status, or the package upgrades available from apt or dnf, to a
central web console. From there an administrator installs the missing updates on one computer,
a site, or a whole customer, sees which missing updates fix actively exploited vulnerabilities,
and tracks compliance across every customer.

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/images/dashboard-light.png">
  <img src="docs/images/dashboard.png" alt="EasyPatch dashboard: compliance, known-exploited exposure, online and offline endpoints, a 30-day compliance trend and the least compliant organizations">
</picture>

## Principles

* **Outbound-only agents.** Endpoints connect to the server over HTTPS (TCP 443). No VPN,
  inbound firewall rule or port forwarding is needed, so agents work behind NAT.
* **Patching, and nothing else.** The agent has no remote shell and no command execution. It
  runs a fixed set of job types: update scan, inventory refresh, install updates, restart,
  agent update, uninstalling itself, and (Windows) preset messages to signed-in users.
* **No surprise restarts.** EasyPatch reports when a restart is pending and why. It restarts a
  computer only when an administrator asks for it, either once or through a restart schedule
  the administrator configured, and it warns signed-in users first. Installing updates never
  restarts a computer.
* **Respects existing configuration.** WSUS, Group Policy and Windows Update for Business
  settings are detected and reported. EasyPatch changes Windows Update policy settings only
  when an administrator configures an override. It never touches the WSUS server settings, and
  it puts the original values back when the override is removed. On Linux, repositories and
  `unattended-upgrades` or `dnf-automatic` are reported and never changed.

## Screenshots

All screenshots show fictional demo data.

<table>
  <tr>
    <td width="50%"><a href="docs/images/endpoint-updates.png"><img src="docs/images/endpoint-updates.png" alt="Missing updates of one endpoint, with CVE counts, known-exploited flags, rollout delays and winget application updates"></a><br><sub><b>Endpoint updates.</b> Known-exploited first, CVE counts, rollout delays, winget application updates.</sub></td>
    <td width="50%"><a href="docs/images/updates.png"><img src="docs/images/updates.png" alt="Fleet-wide update list across all organizations, known-exploited updates first"></a><br><sub><b>Update management.</b> Every update across the fleet, known-exploited first.</sub></td>
  </tr>
  <tr>
    <td><a href="docs/images/update-detail.png"><img src="docs/images/update-detail.png" alt="One cumulative update with the CVEs it fixes and its CISA KEV entry"></a><br><sub><b>Update detail.</b> The CVEs an update fixes, with CISA KEV dates.</sub></td>
    <td><a href="docs/images/linux-updates.png"><img src="docs/images/linux-updates.png" alt="A Rocky Linux server with security package updates and advisories"></a><br><sub><b>Linux endpoints.</b> apt and dnf upgrades with advisories and CVEs.</sub></td>
  </tr>
  <tr>
    <td><a href="docs/images/endpoints.png"><img src="docs/images/endpoints.png" alt="Endpoint list with compliance, tags, operating system support status and agent versions"></a><br><sub><b>Endpoints.</b> Compliance, tags, OS support status and filters.</sub></td>
    <td><a href="docs/images/policy.png"><img src="docs/images/policy.png" alt="Organization policy with automatic installation, maintenance window and rollout delays"></a><br><sub><b>Policy.</b> Maintenance windows and rollout delays, inherited or overridden.</sub></td>
  </tr>
  <tr>
    <td><a href="docs/images/job-detail.png"><img src="docs/images/job-detail.png" alt="An install job with a timeline and per-update results, one failed with its error code"></a><br><sub><b>Jobs.</b> Per-update results, verified by a scan, never assumed.</sub></td>
    <td><a href="docs/images/alerts.png"><img src="docs/images/alerts.png" alt="Open alerts for known-exploited vulnerabilities, offline endpoints and failed installs"></a><br><sub><b>Alerts.</b> Email, Slack, Teams or signed webhooks.</sub></td>
  </tr>
  <tr>
    <td><a href="docs/images/monthly-reports.png"><img src="docs/images/monthly-reports.png" alt="Monthly PDF reports per organization"></a><br><sub><b>Monthly reports.</b> One PDF per customer and month, emailed on schedule.</sub></td>
    <td><a href="docs/images/monthly-report-pdf.png"><img src="docs/images/monthly-report-pdf.png" alt="First page of a monthly compliance report PDF"></a><br><sub><b>Report PDF.</b> Compliance trend, sites and the most widely missing updates.</sub></td>
  </tr>
</table>

## Features

* **Multi-tenant hierarchy**: Organization → Site → Endpoint. Policies are inherited, with
  overrides at organization, site and endpoint level. Administrators can be restricted to
  specific organizations.
* **Tags and update rings.** Endpoints can carry MSP-wide tags (such as "Pilot" or "SQL
  servers"), and a tag can carry its own policy layer. Tag a whole organization or site and
  every endpoint in it has the tag. A **rollout delay** in policy (separate values for security
  and other updates) keeps new updates from being required or installed by schedule until they
  have been out for a given number of days, so a pilot ring can go first.
* **Uninstall from the console.** Removing the agent from an endpoint is one confirmed action;
  the agent removes its own package, restores the Windows Update settings EasyPatch changed and
  unenrolls.
* **Install all missing updates** on one endpoint or on many selected endpoints at once, or
  install chosen updates. A single update can also be rolled out across an organization or a
  site. Installing on a single endpoint first shows exactly which updates will be installed.
  Policy decides which categories are included: by default, everything except drivers and
  feature updates.
* **Roll back a bad update** (Windows agent 1.8.0 and later): remove an installed update from one
  endpoint, or from every endpoint in an organization or site, and exclude it so EasyPatch does not
  install it again. The agent uses Windows Update's own uninstall or DISM, and never restarts.
* **Rollout guard and update holds**: when a Windows update fails on too many endpoints (by
  default at least 3 endpoints and 20% of those that tried it in 7 days), EasyPatch puts it on hold
  for every organization. Scheduled installs and *Install all missing* then skip it, and an alert
  opens. Administrators can also hold an update themselves and release holds on the update's page.
* **Optional scheduled installs** inside a per-policy maintenance window (off by default),
  limited per site and globally. Updates still inside their rollout delay are skipped. Windows
  agents 1.8.0 and later can download the updates up to 24 hours before the window opens, so the
  window is spent installing.
* **Restarts** of one endpoint or many selected endpoints, now or at a chosen time, or on a
  recurring restart schedule set in policy (optionally only when Windows needs a restart).
  **Restart all that need it** on an organization or site lists every endpoint there that
  reports a pending restart and, once you confirm, restarts those.
  Signed-in users see a countdown, or can postpone up to a deadline. A restart job completes
  only when the computer's boot time shows that it actually restarted.
* **Tray icon, status window and user messages.** The agent shows an EasyPatch icon in the
  notification area of every signed-in user; hovering shows the agent version and status.
  Clicking it opens a status window with the connection and update status, *Check in now*,
  *Check for updates* (a scan only, rate-limited) and the recent agent log. Administrators can
  hide the icon in policy. Users are told when updates are being installed (this can be turned
  off in policy), and administrators can send preset messages. There is no free-text messaging.
* **Windows Update policy overrides** per organization, site or endpoint: Automatic Updates
  mode, feature update deferral and target version, quality update deferral and pausing, and
  restart behaviour with active hours. Each group is *Not configured* by default. The console
  shows whether each endpoint applied the settings, or whether another policy source such as
  domain Group Policy overrides them.
* **Durable job queue** in PostgreSQL. Jobs survive endpoint disconnects and server restarts.
  The agent acknowledges each delivery, and unacknowledged jobs are delivered again. Each job
  records who requested it, its delivery, start and completion times, and per-update results.
* **Verified results.** An update counts as installed only after a Windows Update scan confirms
  it. Updates waiting for a restart are tracked as such.
* **CVE and known-exploited prioritization.** Updates show the CVEs they fix (Windows from
  Microsoft's security update data, Debian from the Debian Security Tracker, RHEL-family and
  Fedora from the dnf advisories; Ubuntu not yet). Updates fixing a vulnerability in the CISA
  Known Exploited Vulnerabilities catalog are flagged, listed first and, by default, skip the
  rollout delay. See [docs/compliance.md](docs/compliance.md#vulnerabilities-and-known-exploited-updates).
* **Alerts and notifications.** Built-in rules (endpoint offline, failed installs, security
  updates missing too long, known-exploited vulnerabilities, stale scans, pending restarts, enrollment requests, unsupported OS)
  open alerts that resolve by themselves when the condition clears. Notifications go to email,
  Slack, Microsoft Teams or a signed JSON webhook for PSA and ticketing systems, grouped per
  channel and retried. Webhooks are restricted to public HTTPS addresses unless private ones
  are allowed. See [docs/alerts.md](docs/alerts.md).
* **Compliance reporting**: per-endpoint status, organization trends from daily snapshots, OS
  support status (including Windows 10 ESU), and CSV exports. See
  [docs/compliance.md](docs/compliance.md).
* **Monthly reports per customer**: a PDF per organization and month (compliance, installed and
  failed updates, most widely missing and known-exploited updates, operating systems, optional
  endpoint list), generated on demand or emailed on a chosen day to the organization's recipients
  over STARTTLS or TLS. See [docs/compliance.md](docs/compliance.md#monthly-reports).
* **Third-party application updates (Windows, opt-in)**: upgrades approved, already installed
  applications with winget from the winget community repository, verified by checking the
  installed version afterwards. Off by default; applications are approved per package ID in
  policy. Where winget is missing (Windows Server 2019 and 2022, Windows 10 LTSC), the agent
  installs a pinned, SHA-256-verified release itself. See
  [docs/application-updates.md](docs/application-updates.md).
* **Two enrollment methods**:
  * limited-use, expiring enrollment tokens;
  * tokenless deployment codes for RMM scripts. Each computer that uses one waits for an
    administrator to approve it, after the administrator compares key fingerprints.
* **Strong admin security**:
  * sign-in with the email address; Argon2id password hashing and mandatory MFA with recovery
    codes, by authenticator app (TOTP) or security key;
  * passkeys (WebAuthn) for passwordless sign-in, offered after sign-in to users without one
    (needs a DNS name with a trusted certificate);
  * single sign-on with OpenID Connect providers (Microsoft Entra ID, Google, Keycloak and
    others), linking existing users by verified email address. See
    [docs/single-sign-on.md](docs/single-sign-on.md);
  * server-side sessions, CSRF protection, lockout and rate limits;
  * three roles: SuperAdmin, Admin, ReadOnly;
  * API tokens for scripts and integrations: read-only or operator, optionally limited to
    some organizations, expiring and revocable, stored only as hashes;
  * an audit log of administrative actions.
* **Per-device agent credentials.** Each agent generates its own ECDSA P-256 key pair; only the
  public key goes to the server. Every request is signed with a timestamp and nonce for replay
  protection, and keys rotate automatically. The agent contains no shared secret.
* **Linux agent** for Debian and Ubuntu (apt) and Red Hat Enterprise Linux, Rocky Linux,
  AlmaLinux, Oracle Linux, CentOS Stream and Fedora (dnf4 and dnf5), as `.deb` and `.rpm` packages with a one-line install script
  for deployment codes. It reports and installs upgrades of installed packages at exact versions,
  classifies security updates from the distribution's security repositories and advisories, and
  uses the same policies, jobs, restarts and compliance reporting. See
  [docs/linux-agent.md](docs/linux-agent.md).
* **macOS agent (experimental: in development and not for production use)**, as a `.pkg` for
  macOS 14 and later (Intel and Apple silicon). It reports the updates Apple's `softwareupdate`
  offers and installs the approved ones. On Apple silicon it cannot install macOS updates
  (Apple allows only a volume owner or MDM to), and it has not yet been used on a real Mac. See
  [docs/macos-agent.md](docs/macos-agent.md).
* **Agent self-update** (Windows agent 1.2.0 and later, all Linux agents), automatic or on
  demand, set per organization, site or endpoint. Agents install only packages signed with your
  own release key, whose public half is built into the agent; the server only relays packages
  and cannot make an agent install anything else or downgrade it. See
  [docs/security.md](docs/security.md#agent-release-signing).

## Architecture

```
Windows/Linux agents ─HTTPS─┐
                            ├──► caddy (TLS, web console) ──► api ──► postgres
Admin browsers ─────HTTPS───┘                                  worker ──┘
```

| Component | Technology |
|---|---|
| Server API and worker | ASP.NET Core 10, EF Core 10, PostgreSQL 18 |
| Web console | React 19, TypeScript, Vite, Tailwind CSS (served by Caddy) |
| Reverse proxy | Caddy 2 with automatic certificates |
| Windows agent | .NET 10 Windows service using the Windows Update Agent COM API, plus a tray icon (Windows Forms) in each user session |
| Linux agent | .NET 10 self-contained systemd service driving apt or dnf |
| macOS agent (experimental) | .NET 10 self-contained launchd daemon driving `softwareupdate` |
| Installers | WiX Toolset v5 MSI; `.deb` and `.rpm` packages; macOS `.pkg` (x64 and ARM64) |
| Deployment | Docker Compose: `caddy`, `api`, `worker`, `postgres`, plus a one-shot `migrate` |

See [docs/architecture.md](docs/architecture.md) for the full design.

## Quick start

On a Linux host (x64 or ARM64) with Docker, a DNS name pointing at it, and ports 80 and 443 open:

```bash
git clone --branch v1.10.0 https://github.com/paulmataruso/EasyPatch.git easypatch && cd easypatch
./scripts/init-secrets.sh                 # database password secret, data directories, .env
$EDITOR .env                              # set EASYPATCH_DOMAIN and ACME_EMAIL
docker compose pull                       # ghcr.io/paulmataruso/easypatch-server and -proxy
docker compose up -d
docker compose run --rm api create-admin --email admin@example.com
```

Then:

1. Open `https://<EASYPATCH_DOMAIN>`, sign in with that email address and the printed temporary password, set up MFA
   and choose a new password.
2. Download the agent packages (MSI, `.deb`, `.rpm` and their `.sig` files) from the
   [release](https://github.com/paulmataruso/EasyPatch/releases/latest) into
   `data/agent-packages/`.
3. Create an organization, then deploy agents with an enrollment token or a deployment code.

The full guides are [docs/installation.md](docs/installation.md),
[docs/agent-installation.md](docs/agent-installation.md) and
[docs/linux-agent.md](docs/linux-agent.md). To build everything from source instead, see
[Building the images from source](docs/installation.md#building-the-images-from-source).

## Documentation

| Document | Contents |
|---|---|
| [installation.md](docs/installation.md) | Server installation, first sign-in, agent packages, upgrades, backup and restore, CLI commands |
| [agent-installation.md](docs/agent-installation.md) | Windows agent requirements, MSI properties, RMM deployment, command line, logs, building the MSI |
| [linux-agent.md](docs/linux-agent.md) | Linux agent: supported distributions, install script and token enrollment, how packages are scanned and installed, self-update, building the packages |
| [macos-agent.md](docs/macos-agent.md) | macOS agent (experimental, not for production use): known limitations, installing, how updates are scanned and installed, uninstalling, building the package |
| [architecture.md](docs/architecture.md) | Components, data model, update state model, policy, job system, agent lifecycle, deployment design |
| [application-updates.md](docs/application-updates.md) | Third-party application updates with winget: requirements, approval, what the agent runs, restarts, limitations and trust model |
| [compliance.md](docs/compliance.md) | Compliance statuses and rules, required updates, CVE and known-exploited data, OS support status, reports and monthly PDF reports |
| [alerts.md](docs/alerts.md) | Alert rules, notification channels (email, Slack, Teams, signed webhooks), delivery and troubleshooting |
| [single-sign-on.md](docs/single-sign-on.md) | Single sign-on with OpenID Connect: how accounts are linked, MFA, settings, Entra ID, Google and Keycloak setup |
| [security.md](docs/security.md) | Security model, threat model, hardening checklist, known limitations |
| [api.md](docs/api.md) | REST API (admin and agent protocol). The live OpenAPI document is served at `/api/docs` to signed-in administrators |
| [troubleshooting.md](docs/troubleshooting.md) | Diagnosing server, sign-in, agent and job problems |

## Development

Requirements: the .NET SDK pinned in `global.json` (10.0.404 or a later feature band), Node.js
24, and Docker (the integration tests start PostgreSQL with Testcontainers).

```bash
dotnet build EasyPatch.slnx -c Release
dotnet test backend/Tests/EasyPatch.Tests.csproj                 # unit + integration tests
dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj

cd frontend && npm ci && npm run typecheck && npm test && npm run build
```

The backend integration tests run against a real PostgreSQL database. They include an
end-to-end lifecycle test, which drives the real agent runtime (with the Windows-specific
services replaced by test doubles) against the real API: enrollment, scan, install, restart,
verification and compliance.

The agent builds and tests on Linux with `scripts/build-agent.sh`. The MSIs can be built on
Linux with Docker (`scripts/build-msi-linux.sh`, which runs WiX under Wine) or on Windows with
`scripts/build-agent.ps1`, which can also sign them. The `agent` GitHub Actions workflow builds
them on Windows. `scripts/build-linux-packages.sh` builds the signed `.deb` and `.rpm`
packages of the Linux agent (Docker). Pushing a version tag (`v1.10.0`) runs the `release`
workflow, which tests everything, builds and release-signs the agent packages, publishes the x64
and ARM64 images to GitHub Container Registry and creates the GitHub Release.

```
shared/      Contracts shared by agent and server (DTOs, request signing, update classification)
backend/     Core (domain), Infrastructure (EF Core, services), API, Worker, Tests
agent/       Agent core, communication, Windows Update, inventory, Windows, Linux and macOS hosts, apt/dnf, softwareupdate, tests, installers
frontend/    Web console
deployment/  Dockerfiles and Caddy configuration
scripts/     init-secrets, backup, restore, agent and MSI builds, agent icon, dependency audit
keys/        The release public key built into official agent builds
tools/       Release signing tool
docs/        Documentation
```

## Project status

Version 1.10.0 (1.4.0 was the first public release). Server, console and agent logic are covered
by automated tests on Linux, including an end-to-end test that drives the real agent runtime
against the real API and PostgreSQL. Release builds are made and signed by GitHub Actions.

Checked by hand so far:

* the Windows agent on a Windows 11 25H2 workstation: enrollment, scans, inventory, the tray
  icon, and self-update from 1.2.0 to 1.2.1 and to 1.4.0;
* the Linux agent on Debian 12 and 13, Ubuntu 22.04, 24.04, 26.04 and 26.10, Rocky Linux 8 and 9,
  AlmaLinux 10.2 and Fedora 45 containers: enrollment through the install script, scans, package
  installation and self-update.

The macOS agent is experimental and has not been run on a real Mac by the project.

Not yet validated on real systems: installing updates across Windows versions and Windows
Server, the MSI with Windows Installer ICE validation, the PowerShell install script, winget
application updates and email delivery. Validate them on test endpoints before rolling out to
production, and report what you find.

## Security

EasyPatch has no remote shell and runs no commands from the server, agents hold their own keys,
and agent updates must carry a release signature that the agent checks itself. The design,
threat model and hardening checklist are in [docs/security.md](docs/security.md).

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues.

## Contributing

Bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), including the
contributor terms, and the [code of conduct](CODE_OF_CONDUCT.md).

## License

EasyPatch is source-available under the **Functional Source License, Version 1.1, ALv2 Future
License** ([FSL-1.1-ALv2](LICENSE.md)). Copyright 2026 DHI Technical Services LLC.

* You may use, copy, modify and redistribute EasyPatch for any purpose **except a Competing
  Use**: making it available to others in a commercial product or service that substitutes for
  EasyPatch or offers substantially similar functionality.
* The licensor's intent: MSPs and IT departments may run EasyPatch free of charge to patch their
  own computers and the computers they manage for their clients, including as part of paid
  managed services. Selling EasyPatch, or offering it or a product built from it for others to
  run their own patch management, is not permitted.
* Each version becomes available under the Apache License 2.0 two years after it is released.
* For a commercial license, contact DHI Technical Services LLC at
  [paulmataruso@dhitechnical.com](mailto:paulmataruso@dhitechnical.com).

Third-party components keep their own licenses.
