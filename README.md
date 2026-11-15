# EasyRMM

Open-source remote monitoring and management for Windows and Linux endpoints.
It is self-hosted, multi-tenant and built for MSPs.

> **Status: early development.** The architecture is settled and the security
> core of the server is implemented and tested. It is not ready for production
> use yet. [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) tracks what
> works today, and [`ROADMAP.md`](ROADMAP.md) shows what comes next.

## What it is

* **One install per endpoint.** A single package (MSI, EXE, PowerShell
  one-liner, DEB, RPM or shell one-liner) installs both our agent and
  MeshAgent, enrolls the device and registers it. Nothing else needs to be
  installed by hand.
* **Remote desktop, terminal and file management** from MeshCentral, built
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
  * mandatory MFA
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
| `server/` | Go server (modular monolith), migrations |
| `web/` | Technician console: React + TypeScript, sharing EasyPatch's design system |
| `agents/` | Go endpoint agent (Windows, Linux) |
| `installers/` | MSI, packages and install scripts |
| `meshcentral/` | MeshCentral configuration and integration assets |
| `integrations/easypatch/` | EasyPatch connector assets |
| `docker/`, `deploy/` | Container images and Compose deployment |
| `docs/` | Architecture, deployment, security, operations, API |
| `tests/` | End-to-end, security, installer and performance suites |
| `scripts/` | Developer and CI helpers |

Some directories are created as their phase starts. See the roadmap.

## Development

```bash
make test-db                 # disposable PostgreSQL 18 on 127.0.0.1:55432
export EASYRMM_TEST_DATABASE_URL='postgres://postgres:easyrmm-test-only@127.0.0.1:55432/postgres?sslmode=disable'
make check                   # format, vet, lint, unit + integration tests, coverage floors
make web-test                # console typecheck and unit tests
make e2e                     # build everything, browser tests against a real server
```

Console development is described in
[docs/development/web-console.md](docs/development/web-console.md).

[CONTRIBUTING.md](CONTRIBUTING.md) explains the workflow.

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Licence

EasyRMM is licensed under the [GNU Affero General Public License v3.0 or
later](LICENSE). MeshCentral and MeshAgent are Apache-2.0 projects by their
respective authors. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
EasyRMM is not affiliated with the MeshCentral project.
