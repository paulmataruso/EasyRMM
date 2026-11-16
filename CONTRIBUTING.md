# Contributing to EasyRMM

Thank you for helping. EasyRMM manages real computers, so the bar for
correctness and security is high; these rules keep it that way.

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
  [Developer Certificate of Origin](https://developercertificate.org/).
  Contributions are licensed under AGPL-3.0-or-later.

## Development environment

Requirements: Go (version in `go.mod`), Node.js 22+, Docker with Compose.

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
| Security regression | `tests/security/` and `*_integration_test.go` | part of the above |

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
