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
| 6. Unified endpoint installation | Go agent, enrollment, MeshAgent install and correlation, MSI/EXE/PowerShell, DEB/RPM/script, updates, uninstall | In progress: Linux and Windows agents, deployment tokens and approval, MeshAgent install and correlation, install scripts, uninstall and coordinated agent updates (ADR-0027) done; the Windows agent verified on Windows Server 2025. MSI and DEB/RPM packages to do |
| 7. Core RMM | Inventory, telemetry, monitoring, alerts, scripts, jobs, software deployment | Done: inventory, telemetry, alerts, scripts, jobs, software deployment (ADR-0028) and reports (ADR-0029); see `IMPLEMENTATION_STATUS.md`. The winget and Chocolatey scripts have not been run on Windows |
| 8. EasyPatch | EasyPatch changes (integration credentials, external ids…), connector, native patch UI | Done: connector and patch UI (ADR-0030), installing the EasyPatch agent from EasyRMM (ADR-0031); verified on Linux (apt-get and dnf) against EasyPatch 1.9.0; the script library warns about scripts that install updates themselves. On Windows, detection and refusal verified; the installer path and patching a linked Windows endpoint not yet run |
| 9. Production hardening | Security review, performance and soak tests, backup/restore drills, release pipeline, documentation completion | In progress: Go 1.27.4 for a standard-library vulnerability; release pipeline (not yet run on GitHub); security review done, its findings fixed or documented (`docs/security/security-review.md`); backup and restore drill passing (`scripts/drill/`), after fixing the deployment and guide bugs it found; upgrade guide, and a release bundle that deploys; load and soak drill with 2,000 simulated agents for an hour: no errors, jobs on 500 devices in about 6 s, and a nonce table that grew for an hour now pruned every minute (`docs/development/drills.md`) |

## Next steps

1. Push the branch and let CI run on GitHub (needs a token with the
   `workflow` scope), then enable branch protection with "CI result" as the
   required check.
2. ~~Licence the EasyPatch-derived stylesheet and logo construction to
   EasyRMM (ADR-0013).~~ Resolved by one licence (ADR-0037).
3. Phase 6, remainder: an MSI for the Windows agent (needs Windows CI
   runners) and DEB/RPM packages.
4. Run the winget and Chocolatey software scripts on Windows (ADR-0028).
5. Run the EasyPatch agent install and patching on a Windows machine
   with no EasyPatch agent (ADR-0030, ADR-0031). The two Windows test
   machines already run one, so only the refusal has run on Windows.
6. Try security keys and passkeys (ADR-0032) with a physical key and a
   platform passkey, on a deployment with a DNS name.
