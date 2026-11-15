# Roadmap

Phases follow the project specification. A phase is finished when every
feature in it is **Complete** in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

| Phase | Scope | State |
|---|---|---|
| 1. Research and discovery | MeshCentral/MeshAgent, Tactical RMM, EasyPatch, Impeccable, stack, risks | Done (`docs/architecture/research-report.md`) |
| 2. Architecture | System, data, network, MeshCentral, installer, identity, auth, EasyPatch; ADRs | Done (`docs/architecture/`) |
| 3. GitHub foundation | Repository, CI (lint, tests, coverage floors, security scanning), templates, branch protection | In progress |
| 4. Server foundation | Config, HTTP API, auth flows, organizations/sites/groups, users and roles, audit API, Docker deployment, web foundation with Impeccable, dashboard | In progress |
| 5. MeshCentral integration | Container and config, control client, user/group sync, edge gateway, session launch, embedded desktop/terminal/files | Not started |
| 6. Unified endpoint installation | Go agent, enrollment, MeshAgent install and correlation, MSI/EXE/PowerShell, DEB/RPM/script, updates, uninstall | Not started |
| 7. Core RMM | Inventory, telemetry, monitoring, alerts, scripts, jobs, software deployment | Not started |
| 8. EasyPatch | EasyPatch changes (integration credentials, external ids…), connector, native patch UI | Not started |
| 9. Production hardening | Security review, performance and soak tests, backup/restore drills, release pipeline, documentation completion | Not started |

## Next steps

1. HTTP API layer: routing, security middleware (CSRF, security headers,
   request limits, real-IP handling), session cookies, auth endpoints,
   first-run setup.
2. Organizations, sites and device groups, plus user and role management,
   with tests for permissions and tenant isolation.
3. Server configuration, TLS edge (ACME/manual/offload) and the Docker
   Compose deployment with host networking.
4. Web foundation: Impeccable init, PRODUCT.md and DESIGN.md, sign-in and
   MFA, shell and navigation, dashboard, organization management.
5. Playwright end-to-end suite in CI.
