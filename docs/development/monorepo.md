# One repository, one project

This repository holds the EasyRMM project: EasyRMM's platform and EasyPatch,
its patch management component, under `easypatch/`. They are separate
programs with separate licences ([LICENSING.md](../../LICENSING.md)), builds
and releases. EasyPatch also runs on its own. EasyRMM talks to EasyPatch only
over EasyPatch's HTTP API.

| | EasyRMM | EasyPatch |
|---|---|---|
| Code | everything except `easypatch/` | `easypatch/` |
| Language | Go, React (`web/`) | .NET 10, React (`easypatch/frontend/`) |
| Built from | the repository root | `easypatch/` |
| Release tags | `easyrmm-v1.2.3` | `easypatch-v1.10.0` |
| Release workflow | `release.yml` | `easypatch-release.yml` |
| Contributing terms | [CONTRIBUTING.md](../../CONTRIBUTING.md) | [easypatch/CONTRIBUTING.md](../../easypatch/CONTRIBUTING.md) |

The integration between them, and the plan for it, are in
[the integration plan](../architecture/easypatch-integration-plan.md).

## History

EasyPatch's whole history came in with commit `819ae8f` ("Bring EasyPatch
into this repository, under easypatch/"). It is a merge: its second parent,
`a890e36`, is the head of EasyPatch's former repository at the time, so
every EasyPatch commit keeps its hash. `git log -- easypatch/` and `git blame`
work across the import.

EasyPatch's old release tags were renamed `v1.10.0` → `easypatch-v1.10.0`, so
they cannot be confused with EasyRMM's. They point at commits from before the
import, so checking one out puts EasyPatch's files at the top of the
checkout, not in `easypatch/`. The releases themselves, up to 1.10.0, and
their downloads stay in the
[former repository](https://github.com/paulmataruso/EasyPatch/releases).

## Local files that are never committed

EasyPatch's working copy keeps machine-local files in `easypatch/`:

* `.env`, its configuration;
* `secrets/`, including the database password;
* `local/`, including the release signing key;
* `data/`, `backups/` and `artifacts/`.

They are ignored twice: by `easypatch/.gitignore` and by the root
`.gitignore`, so an edit to one cannot expose them. `easypatch/.dockerignore`
keeps them out of EasyPatch's images. The root `.dockerignore` keeps all of
`easypatch/` out of EasyRMM's.

Never print or copy these files into an issue, a log or a chat.

## Running EasyPatch from this repository

Its own documentation applies, run from `easypatch/`
([easypatch/docs/installation.md](../../easypatch/docs/installation.md)), with
one caution.

> **Name the Compose project.** `easypatch/docker-compose.yml` names its
> project `easypatch` (and so would the folder's name), the name a real
> EasyPatch server has too. On a machine that also runs one,
> `docker compose up` in `easypatch/` would take over that server's
> containers and volumes. Use another name:
> `docker compose -p easypatch-dev …`, or set `COMPOSE_PROJECT_NAME`.

## Continuous integration

`ci.yml` runs on every pull request and push to `main`. Its first job,
**Changed files**, decides which areas changed, and only their checks run:

| Area | Runs when these change | Jobs |
|---|---|---|
| EasyRMM | anything outside `easypatch/` and `easypatch-*.yml` | Backend, Integration, Frontend, Docker |
| EasyPatch server | `easypatch/` except the agent, docs and Markdown; EasyRMM's connector | EasyPatch server |
| EasyPatch agent | the agent, `shared/`, its build scripts and props | EasyPatch agent |
| Contract | EasyPatch's server and its build, EasyRMM's connector, `go.mod`, `scripts/contract/` | EasyPatch contract |
| Security | always | Security (CodeQL for Go, C# and JavaScript, gitleaks, …) |

A change to `ci.yml` runs everything, as do the merge queue and manual runs.
**CI result** is the one required check: it passes when every job passed or
was skipped because its area did not change.

### The contract tests

`make test-contract` (CI: **EasyPatch contract**) builds EasyPatch's server
image from `easypatch/`, starts it with PostgreSQL on the host network over
TLS, makes an operator and a read-only API token with `create-api-token`, and
runs `server/internal/easypatch/contract_test.go` (build tag `contract`).
That test:

* enrolls a simulated Debian agent, which signs its requests as EasyPatch's
  agents do, and reports a scan and update history;
* drives every call of EasyRMM's connector against the real server: reads,
  an install followed to a cancel while the agent works on it, a scheduled
  install, bulk actions, errors, and the read-only token's refusals;
* checks that EasyPatch's audit log names the EasyRMM user for each action;
* asks `eptest` (the fake EasyPatch the fast tests use) and the real server
  the same questions, and fails when `eptest` sends a field EasyPatch does
  not, or with another JSON type.

It needs Docker and `openssl`, and ports 55433 and 18443 on 127.0.0.1
(`EASYPATCH_CONTRACT_PG_PORT`, `EASYPATCH_CONTRACT_PORT`). Everything it
starts is removed afterwards.

## The former EasyPatch repository

EasyPatch's former repository, <https://github.com/paulmataruso/EasyPatch>,
is not archived and no longer updated. Its README says EasyPatch has moved
here, and its description links here.

* It keeps EasyPatch's releases up to 1.10.0 and their downloads (MSIs,
  signed agent packages), which existing installations and links use. Do not
  delete them.
* New releases are published from this repository, tagged `easypatch-v*`.
* Issues, pull requests and security reports for EasyPatch belong here.
* A server installed from the former repository moves to a checkout of this
  one when it next upgrades; EasyPatch's
  [installation guide](../../easypatch/docs/installation.md#upgrading) says
  how.

It is not a mirror of `easypatch/`: the owner chose a notice instead
(2026-11-18), so nothing pushes to it.
