# ADR-0008: Unified endpoint installer bundling MeshAgent

* Status: Accepted (2026-11-15)

## Context
Customers must perform exactly one installation. MeshAgent needs a
server-specific `.msh` (server URL, ServerID, MeshID); our installers are
built once by CI and are not server-specific.

## Options
1. Bundle the generic MeshAgent binary in our package; obtain the `.msh` at
   enrolment through our authenticated API. **(chosen)**
2. Download MeshAgent from the server during installation (smaller package,
   no offline media, extra failure point).
3. Per-server installers with embedded `.msh` built on the server (complex
   signing, Windows-only tooling on a Linux server).
4. Modify MeshAgent (fork maintenance).

## Decision
Option 1, with MeshCentral's own update mechanism as the version-drift
fallback: the release pipeline extracts the MeshAgent binaries from the pinned
MeshCentral image, records their SHA-256 in `meshcentral/agents.lock.json`,
and packages them. Packages: MSI (WiX, built on Windows runners), a
self-installing EXE (the agent binary itself), PowerShell and shell one-liners
served by the server, DEB and RPM (nfpm), and a tarball. Every installer runs
the same `easyrmm-agent install/enroll` code path, which installs and
configures MeshAgent, writes the correlation tag, and verifies health.
Uninstallation removes MeshAgent (`-fulluninstall`) and everything we created.

## Consequences
* Our package is a few MB larger.
* The `.msh` is never published unauthenticated.
* Endpoint integration tests need real Windows and Linux machines
  (GitHub-hosted runners for clean installs; documented self-hosted runners
  for upgrade/repair matrices).
