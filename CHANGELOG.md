# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Phase 1 research report and Phase 2 architecture with ADRs 0001–0012.
- Server security core: AES-256-GCM secret sealing with key rotation,
  Argon2id password hashing with parameter upgrades, NIST-style password
  policy, RBAC with five built-in roles at platform/organization/site scope
  and escalation prevention.
- PostgreSQL schema with forced row-level security for tenant isolation,
  split owner/runtime roles, and an append-only hash-chained audit log
  written through a `SECURITY DEFINER` function.
- Authentication service: sessions with idle/absolute expiry and token
  rotation, mandatory TOTP MFA with replay protection, recovery codes,
  progressive account lockout, per-address rate limiting, password change
  and reset.
- CI: formatting, vet, golangci-lint, unit and integration tests with
  coverage gates, govulncheck, gitleaks, CodeQL, Trivy, dependency review and
  licence checks.
- HTTP API, first-run setup, organizations/sites/device groups, users and
  roles, audit API, TLS edge, SMTP mailer and the Docker Compose deployment
  with host networking.
- Technician console (`web/`) sharing EasyPatch's design system (ADR-0013):
  first-run setup, sign-in with mandatory authenticator enrollment, recovery
  codes, password reset and invitations, dashboard, organizations, sites and
  device groups, users and roles, audit log with chain verification, account
  page with sessions; dark and light themes; keyboard row travel (j/k).
- Frontend CI: typecheck, Vitest unit tests with coverage floors, production
  build, Impeccable design detector, and Playwright end-to-end tests against
  a real server and PostgreSQL. actionlint for workflow files. Dependabot for
  npm and Docker.

### Fixed
- Docker smoke test: two negated checks (`! grep`, `! test`) could never fail
  the step; they now do.
