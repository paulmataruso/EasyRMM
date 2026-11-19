<p align="center">
  <img src="web/public/logo.svg" width="104" alt="">
</p>
<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="web/public/wordmark.svg">
    <img src="web/public/wordmark-light.svg" height="64" alt="EasyRMM">
  </picture>
</h1>

<p align="center">
  <b>Self-hosted remote monitoring, management and patching for Managed Service Providers.</b><br>
  Windows first, Linux too. With EasyPatch, its patch management, in the same repository.
</p>

<p align="center">
  <a href="https://github.com/paulmataruso/EasyRMM/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/paulmataruso/EasyRMM/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE.md"><img alt="Licence: FSL-1.1-ALv2" src="https://img.shields.io/badge/licence-FSL--1.1--ALv2-blue"></a>
  <img alt="Endpoints: Windows and Linux" src="https://img.shields.io/badge/endpoints-Windows%20%7C%20Linux-informational">
</p>

<p align="center">
  <a href="#screenshots">Screenshots</a> ·
  <a href="#what-it-does">What it does</a> ·
  <a href="#how-easyrmm-and-easypatch-fit-together">EasyRMM and EasyPatch</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#development">Development</a> ·
  <a href="#licensing">Licensing</a>
</p>

EasyRMM is one project with two parts, built and released separately:

* **EasyRMM** is the platform: tenancy, users and roles, an endpoint agent,
  remote access through MeshCentral, inventory, monitoring and alerts,
  scripts, software deployment and reports.
* **EasyPatch** ([`easypatch/`](easypatch/)) is its patch management: Windows
  Update, apt and dnf, compliance, known-exploited vulnerabilities, policies
  and monthly reports, with its own agent and console.

You patch from EasyRMM's console; for everything else EasyPatch can do, its
own console is one click away.

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/images/dashboard-light.png">
  <img src="docs/images/dashboard.png" alt="EasyRMM dashboard: active alerts, organizations, sites, device groups and users, recent remote connections with Connect buttons, and the alerts that need attention">
</picture>

> **Status: pre-release, in production hardening.** EasyRMM has no tagged
> release yet. Tested and in the console:
> * the server, tenancy, users and roles, the audit log;
> * remote access through MeshCentral;
> * the agent and its install commands;
> * inventory, alerts, scripts and jobs, software deployment, reports;
> * patching through EasyPatch.
>
> Linux endpoints are verified end to end. Windows endpoints are verified for
> install, enrollment and remote access; the other Windows features are built
> but not yet run on Windows. EasyPatch was released on its own up to v1.10.0
> and is in use; its releases continue from this repository.
> [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) tracks what works
> today, and [`ROADMAP.md`](ROADMAP.md) what comes next.

## Screenshots

The screenshots show fictional demo data. They are made from the console's
production build with `npm run screenshots` in `web/`, so they can be
regenerated when the console changes.

<table>
  <tr>
    <td width="50%">
      <a href="docs/images/devices.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/devices-light.png"><img src="docs/images/devices.png" alt="Devices list with the organization, site and device tree, online and offline status, operating system and last seen"></picture></a>
      <br><sub><b>Devices.</b> Every organization's computers, grouped by organization and site.</sub>
    </td>
    <td width="50%">
      <a href="docs/images/device.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/device-light.png"><img src="docs/images/device.png" alt="A Windows server's page: remote desktop, RDP, terminal and files buttons, details, an active alert, live health and a 24-hour performance chart"></picture></a>
      <br><sub><b>A device.</b> Remote desktop, RDP, terminal and files; health, alerts and script runs.</sub>
    </td>
  </tr>
  <tr>
    <td>
      <a href="docs/images/patching.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/patching-light.png"><img src="docs/images/patching.png" alt="Patching page: each device's EasyPatch status, missing and known-exploited updates, last scan and EasyPatch agent"></picture></a>
      <br><sub><b>Patching.</b> Patch status of every device, read from EasyPatch.</sub>
    </td>
    <td>
      <a href="docs/images/device-patches.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/device-patches-light.png"><img src="docs/images/device-patches.png" alt="A device's Patches tab: missing updates with an exploited-in-the-wild flag, Scan now and Install updates, its patch status and EasyPatch policy"></picture></a>
      <br><sub><b>A device's updates.</b> Scan, install and restart; the policy in effect, value by value.</sub>
    </td>
  </tr>
  <tr>
    <td>
      <a href="docs/images/alerts.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/alerts-light.png"><img src="docs/images/alerts.png" alt="Alerts: disk, processor, offline and memory alerts with severity, latest value and acknowledge and resolve actions"></picture></a>
      <br><sub><b>Alerts.</b> Disk, processor, memory and offline policies, acknowledged and resolved by people.</sub>
    </td>
    <td>
      <a href="easypatch/docs/images/dashboard.png"><picture><source media="(prefers-color-scheme: light)" srcset="easypatch/docs/images/dashboard-light.png"><img src="easypatch/docs/images/dashboard.png" alt="EasyPatch dashboard: compliance, known-exploited exposure, online and offline endpoints, a 30-day compliance trend and the least compliant organizations"></picture></a>
      <br><sub><b>EasyPatch's console.</b> One click away with the EasyRMM | EasyPatch switch. <a href="easypatch/README.md#screenshots">More</a>.</sub>
    </td>
  </tr>
</table>

## What it does

**EasyRMM**

* **One install per endpoint.** One PowerShell command on Windows, or one
  shell command on Linux, installs our agent and MeshAgent, enrolls the
  device and registers it. MSI, DEB and RPM packages are planned.
* **Remote desktop, RDP, terminal and file management** from MeshCentral,
  inside EasyRMM's console. Our own authorization and audit trail sit in
  front of every session.
* **Organizations, sites and device groups**, with roles granted at
  organization or site level.
* **Inventory and monitoring**: hardware, software, processor, memory and
  disk history, with alert policies.
* **Scripts and jobs**: a script library, run on one device or many, with
  each device's output.
* **Software deployment** with winget, Chocolatey, APT, DNF, YUM and Zypper.
* **Reports** of devices, software and health.

**EasyPatch** ([its own README](easypatch/README.md))

* **Windows Update, apt and dnf** through a patch-only agent: no remote shell
  and no command execution.
* **Known-exploited first**: the CVEs each update fixes, and the updates that
  fix vulnerabilities in CISA's Known Exploited Vulnerabilities catalog.
* **Policies** per organization, site, endpoint or tag: maintenance windows,
  rollout delays and update rings, restart schedules, Windows Update policy
  overrides.
* **Verified results**: an update counts as installed only when a scan
  confirms it. A rollout guard holds an update that fails on too many
  endpoints.
* **Monthly compliance reports**, one PDF per customer.

**Both**

* **Secure by default**: MFA on by default (authenticator app, security key
  or passkey), single sign-on with OpenID Connect, tenant isolation, an audit
  log, signed agent updates.
* **Outbound-only agents.** Endpoints connect to the server over HTTPS (443).
  No VPN, inbound firewall rule or port forwarding.

## How EasyRMM and EasyPatch fit together

* **EasyRMM uses EasyPatch's API** for patching: patch status, scan,
  install, restart and retry, on one device or many, now or scheduled;
  holds; patch policies for organizations, sites, devices and tags; and
  patch reports: compliance with its trend, installations, and monthly PDFs
  made, emailed and scheduled; and EasyPatch's own server settings, OS
  lifecycle dates, agent packages and audit log. The devices' patches show
  on their own pages in EasyRMM.
* **Not in EasyRMM's console yet**: patch alerts, the
  [one-product plan](docs/architecture/one-product-plan.md)'s next step.
  With a connected EasyPatch server, they, its default policy, its tags,
  its server settings and its OS lifecycle are changed in EasyPatch's own
  console, and EasyRMM links to the matching page.
* **The EasyRMM | EasyPatch switch** under the logo moves between the two
  consoles, landing on the same device, organization or job.
* **EasyRMM installs EasyPatch's agent** through its own agent, per
  organization or per device ([ADR-0031](docs/architecture/adr/0031-easypatch-agent-install.md)).
* **Organizations are linked** once, by an administrator. EasyRMM's roles
  decide who sees and does what; EasyRMM records who acted in EasyPatch's
  audit log and on its jobs.
* **Any EasyPatch server.** EasyRMM connects to an EasyPatch server by its
  address and an API token: one on the same machine, behind EasyRMM's edge
  ([ADR-0035](docs/architecture/adr/0035-cohosting-easypatch.md)), or one
  elsewhere. EasyPatch also runs on its own, without EasyRMM.
* **One sign-in.** EasyRMM can be EasyPatch's sign-in provider, so the switch
  never asks for a password, and each person's EasyPatch role follows their
  EasyRMM roles
  ([ADR-0036](docs/architecture/adr/0036-easyrmm-signs-in-to-easypatch.md)).

The plan behind this, and its progress, is in
[the integration plan](docs/architecture/easypatch-integration-plan.md).
Setting it up is in [docs/operations/patching.md](docs/operations/patching.md).

## Architecture

```
                         ┌─ easyrmm-server (Go) ── TLS edge, console, API, agent gateway
browser, agents ──443──► │      ├──► PostgreSQL (loopback)
                         │      ├──► MeshCentral (loopback) ◄── MeshAgent
                         │      └──► EasyPatch API (HTTPS)
                         │
                         └─ EasyPatch's name: passed through, still encrypted
                                └──► EasyPatch (.NET): Caddy, API, worker, PostgreSQL
                                        ◄── EasyPatch agents
```

* EasyRMM is three containers (server, PostgreSQL, MeshCentral) on Docker
  with host networking. One public port (443), plus an optional port 80 for
  ACME. It works with or without an existing NGINX in front.
* EasyPatch is its own Compose stack. On the same server, EasyRMM's edge
  passes EasyPatch's connections through by server name; EasyRMM never holds
  EasyPatch's keys.

Start with [`docs/architecture/overview.md`](docs/architecture/overview.md).
The decisions behind the design are in
[`docs/architecture/adr/`](docs/architecture/adr/), and the research behind
them is in [`docs/architecture/research-report.md`](docs/architecture/research-report.md).
EasyPatch's own architecture is in [`easypatch/docs/`](easypatch/docs/).

## Repository layout

| Path | Contents |
|---|---|
| `server/` | EasyRMM's Go server (modular monolith), migrations; it serves the install scripts and writes MeshCentral's configuration |
| `web/` | EasyRMM's console: React + TypeScript, sharing EasyPatch's design system; Playwright end-to-end tests in `web/e2e/`, the README's screenshots in `web/screenshots/` |
| `agent/` | EasyRMM's endpoint agent (Go; Windows and Linux), including the EasyPatch agent installer |
| `internal/agentproto/` | Wire protocol shared by the server and the agent |
| `docker/`, `deploy/` | EasyRMM's container images and Compose deployment |
| `easypatch/` | EasyPatch: `backend/` (.NET 10 server), `frontend/` (React console), `agent/` (Windows and Linux agents), `deployment/`, `docs/` |
| `docs/` | Architecture and ADRs, deployment, operations, integrations, security, development |
| `scripts/` | CI, release, end-to-end and contract-test helpers; the backup and load drills in `scripts/drill/` |
| `tools/agentsim/` | Simulated agents for load tests |

Tests sit beside the code they test (`*_test.go`, `*_integration_test.go`,
`*.test.tsx`, and EasyPatch's `easypatch/backend/Tests/`).

## Development

EasyRMM, from the repository root:

```bash
make test-db                 # disposable PostgreSQL 18 on 127.0.0.1:55432
make test-mesh               # disposable MeshCentral for the remote-access tests
make test-oidc               # disposable Dex (OpenID Connect provider) for the single sign-on tests
export EASYRMM_TEST_DATABASE_URL='postgres://postgres:easyrmm-test-only@127.0.0.1:55432/postgres?sslmode=disable'
make check                   # format, vet, lint, unit + integration tests, coverage floors
make web-test                # console typecheck and unit tests
make e2e                     # build everything, browser tests against a real server
make test-contract           # EasyRMM's connector against a real EasyPatch built from easypatch/
make build-agents            # Windows and Linux agents in bin/agents; serve them with EASYRMM_AGENT_DIR=bin/agents
```

EasyPatch, from `easypatch/`: see
[easypatch/CONTRIBUTING.md](easypatch/CONTRIBUTING.md). When you run its
Docker Compose stack, name the project (`docker compose -p easypatch-dev …`)
so it cannot take over a real EasyPatch on the same machine.

* [docs/development/monorepo.md](docs/development/monorepo.md): how the two
  parts share the repository, CI, and the contract tests.
* [docs/development/web-console.md](docs/development/web-console.md): console
  development.
* [docs/development/drills.md](docs/development/drills.md): the backup and
  restore drill and the load test.
* [docs/deployment/agents.md](docs/deployment/agents.md): joining endpoints
  with the EasyRMM agent.
* [CONTRIBUTING.md](CONTRIBUTING.md): the workflow.

## Security

Report vulnerabilities privately, for either part. See [SECURITY.md](SECURITY.md).

## Licensing

EasyRMM, EasyPatch included, is source-available under the [Functional
Source License, Version 1.1, ALv2 Future License](LICENSE.md)
(FSL-1.1-ALv2). Copyright 2026 DHI Technical Services LLC.

MSPs and IT departments may run it free of charge for their own computers and
their clients', including as part of paid managed services. Selling it, or
offering it for others to run their own remote management or patching, is
not permitted. Each version becomes available under the Apache License 2.0
two years after its release. [LICENSING.md](LICENSING.md) has the details,
the licence's history, and what a contribution is made under.

MeshCentral and MeshAgent are Apache-2.0 projects by their respective
authors. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). EasyRMM is not
affiliated with the MeshCentral project.
