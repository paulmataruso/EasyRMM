# Roadmap

Phases follow the project specification. A phase is finished when every
feature in it is **Complete** in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

| Phase | Scope | State |
|---|---|---|
| 1. Research and discovery | MeshCentral/MeshAgent, Tactical RMM, EasyPatch, Impeccable, stack, risks | Done (`docs/architecture/research-report.md`) |
| 2. Architecture | System, data, network, MeshCentral, installer, identity, auth, EasyPatch; ADRs | Done (`docs/architecture/`) |
| 3. GitHub foundation | Repository, CI (lint, tests, coverage floors, security scanning), templates, branch protection | In progress |
| 4. Server foundation | Config, HTTP API, auth flows, organizations/sites/groups, users and roles, audit API, Docker deployment, web console (EasyPatch design system), dashboard | Implemented and tested locally; waiting for its first CI run on GitHub |
| 5. MeshCentral integration | Container and config, control client, user/group sync, edge gateway, session launch, embedded desktop/terminal/files | Implemented and tested locally (including a real agent end to end); waiting for its first CI run on GitHub |
| 6. Unified endpoint installation | Go agent, enrollment, MeshAgent install and correlation, MSI/EXE/PowerShell, DEB/RPM/script, updates, uninstall | Not started |
| 7. Core RMM | Inventory, telemetry, monitoring, alerts, scripts, jobs, software deployment | Not started |
| 8. EasyPatch | EasyPatch changes (integration credentials, external ids…), connector, native patch UI | Not started |
| 9. Production hardening | Security review, performance and soak tests, backup/restore drills, release pipeline, documentation completion | Not started |

## Next steps

1. Push the branch and let CI run on GitHub (needs a token with the
   `workflow` scope), then enable branch protection with "CI result" as the
   required check.
2. Licence the EasyPatch-derived stylesheet and logo construction to
   EasyRMM (ADR-0013).
3. Phase 6: the EasyRMM agent, enrollment, and installers that bundle the
   MeshAgent (ADR-0008, ADR-0009), so devices can be added from the console.
