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
