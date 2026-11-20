# Contributing to EasyRMM

Thank you for helping. EasyRMM manages real computers, so the bar for
correctness and security is high; these rules keep it that way.

This repository holds the whole product, EasyPatch (its patch management,
in `easypatch/`) included. These terms cover all of it.
[easypatch/CONTRIBUTING.md](easypatch/CONTRIBUTING.md) adds the rules
specific to EasyPatch's code. How the two share the repository and CI is in
[docs/development/monorepo.md](docs/development/monorepo.md).

## Licence and contributor terms

EasyRMM is licensed under the [Functional Source License, Version 1.1, ALv2
Future License](LICENSE.md) (FSL-1.1-ALv2). The copyright holder is DHI
Technical Services LLC ([LICENSING.md](LICENSING.md)).

**By submitting a contribution (code, documentation or other material) you
agree that:**

1. you have the right to submit it, and it is your original work or you have
   identified the parts that are not, with their licence;
2. you grant DHI Technical Services LLC a perpetual, worldwide,
   non-exclusive, royalty-free, irrevocable licence to use, copy, modify,
   distribute, sublicense and sell your contribution, under the FSL, the
   Apache License 2.0 or any other licence, including commercial licences;
3. you grant everyone who receives EasyRMM a licence to your contribution
   under the same terms as the rest of the version that includes it.

You keep the copyright in your contribution. These terms let DHI Technical
Services LLC keep EasyRMM under a single licence and offer commercial
licences. If you cannot agree to them, please open an issue describing the
change instead of a pull request.

Dependencies must be under a permissive licence (MIT, BSD, ISC, Apache-2.0,
MPL-2.0). Copyleft licences (GPL, AGPL, LGPL) cannot be accepted: CI checks
Go modules, the consoles' npm packages and EasyPatch's NuGet packages.

## Ground rules

* Work on a feature branch (`feat/…`, `fix/…`, `docs/…`) and open a pull
  request against `main`. `main` is protected: CI must pass before merging.
* Every change ships with tests. A feature is not done until backend,
  frontend, permissions, error handling and tests exist
  (see `IMPLEMENTATION_STATUS.md` for the definition of each status).
* Never commit secrets, certificates, tokens, production configuration or
  personal data. Use `.env.example`-style placeholders.
* Never disable or weaken a failing check to get a merge through.
* Keep commits focused, with messages that explain *why*
  (`area: imperative summary`, e.g. `auth: rotate session token after MFA`).
* Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/), in
  addition to the contributor terms above.

## Development environment

Requirements: Go (version in `go.mod`), Node.js 22+, Docker with Compose.
EasyPatch's (the .NET SDK and Node.js 24) are in
[easypatch/CONTRIBUTING.md](easypatch/CONTRIBUTING.md).

```bash
make test-db            # starts a disposable PostgreSQL on 127.0.0.1:55432
export EASYRMM_TEST_DATABASE_URL='postgres://postgres:easyrmm-test-only@127.0.0.1:55432/postgres?sslmode=disable'
make check              # format check, vet, lint, unit + integration tests
```

See [`docs/development/`](docs/development/) for the full guide, including
frontend development and the Impeccable design workflow.

## Tests

| Kind | Where | Run with |
|---|---|---|
| Go unit | `*_test.go` beside code | `make test-unit` |
| Go integration (real PostgreSQL) | `*_integration_test.go`, build tag `integration` | `make test-integration` |
| Frontend unit (Vitest, coverage floors) | `web/src/**/*.test.{ts,tsx}` | `make web-test` |
| End-to-end (Playwright, real server and PostgreSQL) | `web/e2e/` | `make e2e` (after `make test-db`) |
| Security regression (tenant isolation, permissions, agent API, gateway) | `*_integration_test.go` beside the code | part of the above |
| EasyPatch contract (EasyRMM's calls against the real patching engine built from `easypatch/`, and `eptest`'s answers against its answers) | `server/internal/easypatch/contract_test.go`, build tag `contract` | `make test-contract` (needs Docker) |

Integration tests **fail** (they do not skip) when the test database is not
configured, so CI cannot pass without running them.

Before a release, and after changing `deploy/`, the backup guide or anything
that affects load, run the drills in
[`docs/development/drills.md`](docs/development/drills.md). They run the
Compose deployment itself, which the tests above do not.

## UI changes

The console shares EasyPatch's design system (ADR-0013); `DESIGN.md` records
it. UI work follows the Impeccable workflow and the conventions in
[`docs/development/web-console.md`](docs/development/web-console.md). The
Impeccable detector runs in CI and blocks merges on findings.
