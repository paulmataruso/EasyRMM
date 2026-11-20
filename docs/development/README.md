# Development guide

How the repository is laid out, how to build and test each part, and what
CI checks. The workflow (branches, commit messages, sign-off, contributor
terms) is in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Repository layout

| Path | Contents |
|---|---|
| `server/` | The Go server: `cmd/easyrmm-server`, its packages in `server/internal/` ([overview](../architecture/overview.md#server-packages-serverinternal)) and the database migrations |
| `web/` | The console: React, TypeScript and Vite. Playwright tests in `web/e2e/`, the README's screenshots in `web/screenshots/` |
| `agent/` | The EasyRMM agent (Go; Windows and Linux), including its installer of the EasyPatch agent |
| `internal/agentproto/` | The wire protocol the server and the agent share |
| `easypatch/` | The patching engine: `backend/` (.NET API, worker and their tests), `agent/` (the EasyPatch agent for Windows and Linux; macOS is experimental and not released), `shared/` (contracts), `scripts/` (agent packages), `tools/` (the release signer), `keys/` (the release public key) |
| `docker/`, `deploy/` | Container images and the Compose deployment with its scripts |
| `docs/` | Architecture and ADRs, deployment, operations, security, development; [index](../README.md) |
| `scripts/` | CI, release, end-to-end and contract-test helpers; the backup and load drills in `scripts/drill/` |
| `tools/agentsim/` | Simulated agents for load tests |

Tests sit beside the code they test: `*_test.go`, `*_integration_test.go`,
`*.test.tsx`, and the engine's `easypatch/backend/Tests/` and
`easypatch/agent/EasyPatch.Agent.Tests/`.

## Requirements

* Go, the version in `go.mod`.
* Node.js 22 or later, for the console.
* The .NET SDK pinned in `easypatch/global.json`, for the patching engine
  and the EasyPatch agent.
* Docker with the Compose plugin: the integration, contract and end-to-end
  tests start real PostgreSQL, MeshCentral and OpenID Connect containers.

## Building and testing

From the repository root:

```bash
make test-db                 # disposable PostgreSQL 18 on 127.0.0.1:55432
make test-mesh               # disposable MeshCentral for the remote-access tests
make test-oidc               # disposable Dex (OpenID Connect provider) for the single sign-on tests
export EASYRMM_TEST_DATABASE_URL='postgres://postgres:easyrmm-test-only@127.0.0.1:55432/postgres?sslmode=disable'
make check                   # format, vet, lint, unit and integration tests, coverage floors
make web-test                # console typecheck and unit tests
make e2e                     # build everything, browser tests against a real server
make test-contract           # EasyRMM's calls against the real patching engine built from easypatch/
make build-agents            # agents in bin/agents; serve them with EASYRMM_AGENT_DIR=bin/agents
```

Integration tests **fail** rather than skip when the test database is not
configured, so CI cannot pass without running them.

The patching engine, from `easypatch/` (the backend tests start PostgreSQL
with Testcontainers):

```bash
dotnet build EasyPatch.slnx -c Release
dotnet test backend/Tests/EasyPatch.Tests.csproj
dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj
```

The engine does not run on its own. To try a change, install EasyRMM from a
clone: its Compose file builds the engine from `easypatch/`
([Patching engine](../deployment/docker.md#patching-engine)).

* [Console development](web-console.md): the console's conventions and the
  Impeccable design workflow.
* [Drills](drills.md): the backup and restore drill and the load test. Run
  them before a release and after changing `deploy/`, the backup guide or
  anything that affects load.
* [Releasing](releasing.md): versions, tags and the release workflow.

## Continuous integration

`ci.yml` runs on every pull request and push to `main`. Its first job,
**Changed files**, decides which areas changed, and only their checks run:

| Area | Runs when these change | Jobs |
|---|---|---|
| EasyRMM | anything outside `easypatch/` and `.github/workflows/easypatch-*.yml` | Backend, Integration, Frontend, Docker |
| Engine server | `easypatch/` except the agent, docs and Markdown; EasyRMM's patching client | EasyPatch server |
| EasyPatch agent | the agent, `shared/`, its build scripts and props | EasyPatch agent |
| Contract | the engine's server and its build, EasyRMM's patching client, `go.mod`, `scripts/contract/` | EasyPatch contract |
| Security | always | Security (CodeQL for Go, C# and JavaScript, gitleaks, …) |

A change to `ci.yml` runs everything, as do the merge queue and manual runs.
**CI result** is the one required check: it passes when every job passed or
was skipped because its area did not change. Besides the tests, CI fails on
formatting, lint and shellcheck findings, `go mod tidy` drift, coverage below
a package's floor (`scripts/ci/check-coverage.sh`), new CodeQL alerts and
findings of the Impeccable design detector.

### The contract tests

`make test-contract` (CI: **EasyPatch contract**) builds the engine's image
from `easypatch/` and starts it with PostgreSQL on the host network, as in a
deployment: plain HTTP on loopback, and HTTPS as its public address for
agents. Then it runs `server/internal/easypatch/contract_test.go` (build tag
`contract`), which:

* enrolls a simulated Debian agent that signs its requests as the EasyPatch
  agent does, and reports a scan and update history;
* drives every call EasyRMM makes against the real engine, with statements
  as EasyRMM sends them: reads, an install cancelled while the agent works on
  it, a scheduled install, bulk actions, errors, and refusals by role and
  organization;
* checks that the engine's audit log names the EasyRMM user for each action;
* asks `eptest` (the stand-in engine the fast tests use) and the real engine
  the same questions, and fails when `eptest` sends a field the engine does
  not, or with another JSON type.

It needs Docker and `openssl`, and ports 55433, 18443 and 18444 on
127.0.0.1 (`EASYPATCH_CONTRACT_PG_PORT`, `EASYPATCH_CONTRACT_PORT`,
`EASYPATCH_CONTRACT_ENGINE_PORT`). Everything it starts is removed
afterwards.

## Rules for agent and job changes

EasyRMM and the EasyPatch agent manage other people's computers. Changes
must keep these properties:

* The EasyPatch agent has no remote shell and runs no arbitrary command
  through jobs, policies or any other input from the server. Scripts run
  only through the EasyRMM agent's signed jobs, by people allowed to run
  them.
* No restart without an administrator's explicit action or policy.
* No change to Group Policy, WSUS or Windows Update settings unless an
  administrator configured it, and the original values restored when it is
  removed.
* An update counts as installed only when a scan confirms it. Never report
  success that was not verified.
* No shared secrets in agents, no reusable credentials in plain text, and no
  tokens or credentials in logs.
* Jobs survive disconnects and restarts.
* Agents install only builds whose signature or SHA-256 they have checked:
  the release key for EasyPatch agent packages, the server's signed
  instruction for the EasyRMM agent ([CODE_SIGNING.md](../../CODE_SIGNING.md)).

## Files that are never committed

A working copy of the engine keeps machine-local files in `easypatch/`:
`.env`, `secrets/`, `local/` (including a release signing key for signed
local builds), `data/`, `backups/` and `artifacts/`. They are ignored by
both `easypatch/.gitignore` and the root `.gitignore`, so an edit to one
cannot expose them; `easypatch/.dockerignore` keeps them out of the engine's
image, and the root `.dockerignore` keeps `easypatch/` out of EasyRMM's.
Never paste them into an issue, a log or a chat.

## EasyPatch's former repository

EasyPatch was developed in <https://github.com/paulmataruso/EasyPatch> up to
1.10.0 and moved here with its history (`git log -- easypatch/` and
`git blame` work across the move). That repository keeps those releases and
their downloads, which existing installations use, and a README saying
EasyPatch moved; nothing is pushed to it. Its old tags are here as
`easypatch-v1.10.0` and older. Issues, pull requests and security reports
for the engine and the EasyPatch agent belong in this repository.
