# EasyRMM

Open-source remote monitoring and management for Windows and Linux endpoints.
It is self-hosted, multi-tenant and built for MSPs.

> **Status: pre-release, in production hardening.** Tested and in the console:
> * the server, tenancy, users and roles, the audit log;
> * remote access through MeshCentral;
> * the agent and its install commands;
> * inventory, alerts, scripts and jobs, software deployment, reports;
> * patching through EasyPatch.
>
> Linux endpoints are verified end to end. Windows endpoints are verified for
> install, enrollment and remote access; the other Windows features are built
> but not yet run on Windows. There is no tagged release yet.
> [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) tracks what works
> today, and [`ROADMAP.md`](ROADMAP.md) what comes next.

## What it is

* **One install per endpoint.** One PowerShell command on Windows, or one
  shell command on Linux, installs both our agent and MeshAgent, enrolls the
  device and registers it. Nothing else needs to be installed by hand. MSI,
  DEB and RPM packages are planned.
* **Remote desktop, RDP, terminal and file management** from MeshCentral, built
  into EasyRMM's own interface. Our own authorization and audit trail sit in
  front of every session.
* **Our own RMM platform** for everything else:
  * organizations, sites and device groups
  * inventory and monitoring with alerting
  * a script library and job scheduling
  * software deployment (winget, Chocolatey, APT, DNF, YUM, Zypper)
  * reporting
  * native-feeling patch management through [EasyPatch](https://github.com/paulmataruso/EasyPatch)
* **Secure by default:**
  * MFA on by default (authenticator app, security key or passkey)
  * granular RBAC at organization and site level
  * tenant isolation enforced by PostgreSQL row-level security
  * a hash-chained audit log
  * signed agent updates
  * agents that only ever connect outbound
* **Simple to run:** three containers (server, PostgreSQL, MeshCentral) on
  Docker with host networking. One public port (443), plus an optional port 80
  for ACME. Works with or without an existing NGINX in front.

## Architecture

```
browser ──443──► easyrmm-server (Go: TLS edge, UI, API, agent gateway)
                    │            └──► MeshCentral (loopback) ◄── MeshAgent
                    ▼
                PostgreSQL (loopback)            endpoints ──443──► easyrmm-server
```

Start with [`docs/architecture/overview.md`](docs/architecture/overview.md).
The decisions behind the design are in
[`docs/architecture/adr/`](docs/architecture/adr/), and the research behind
them is in [`docs/architecture/research-report.md`](docs/architecture/research-report.md).

## Repository layout

| Path | Contents |
|---|---|
| `server/` | Go server (modular monolith), migrations; it serves the install scripts and writes MeshCentral's configuration |
| `web/` | Technician console: React + TypeScript, sharing EasyPatch's design system; Playwright end-to-end tests in `web/e2e/` |
| `agent/` | EasyRMM endpoint agent (Go; Windows and Linux), including the EasyPatch agent installer |
| `internal/agentproto/` | Wire protocol shared by the server and the agent |
| `docker/`, `deploy/` | Container images and the Compose deployment |
| `docs/` | Architecture and ADRs, deployment, operations, integrations, security, development |
| `scripts/` | CI, release, end-to-end and test helpers; the backup and load drills in `scripts/drill/` |
| `tools/agentsim/` | Simulated agents for load tests |

Tests sit beside the code they test (`*_test.go`, `*_integration_test.go`,
`*.test.tsx`).

## Development

```bash
make test-db                 # disposable PostgreSQL 18 on 127.0.0.1:55432
make test-mesh               # disposable MeshCentral for the remote-access tests
make test-oidc               # disposable Dex (OpenID Connect provider) for the single sign-on tests
export EASYRMM_TEST_DATABASE_URL='postgres://postgres:easyrmm-test-only@127.0.0.1:55432/postgres?sslmode=disable'
make check                   # format, vet, lint, unit + integration tests, coverage floors
make web-test                # console typecheck and unit tests
make e2e                     # build everything, browser tests against a real server
make build-agents            # Windows and Linux agents in bin/agents; serve them with EASYRMM_AGENT_DIR=bin/agents
```

Endpoints join with the EasyRMM agent: see
[docs/deployment/agents.md](docs/deployment/agents.md).

Console development is described in
[docs/development/web-console.md](docs/development/web-console.md). The
backup and restore drill and the load test are in
[docs/development/drills.md](docs/development/drills.md).

[CONTRIBUTING.md](CONTRIBUTING.md) explains the workflow.

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Licence

EasyRMM is licensed under the [GNU Affero General Public License v3.0 or
later](LICENSE). MeshCentral and MeshAgent are Apache-2.0 projects by their
respective authors. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
EasyRMM is not affiliated with the MeshCentral project.
