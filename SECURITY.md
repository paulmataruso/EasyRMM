# Security policy

EasyRMM controls remote computers. We treat every vulnerability report as a
priority.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
<https://github.com/paulmataruso/EasyRMM/security/advisories/new>.

Please include affected version or commit, a description, reproduction steps
or a proof of concept, and the impact you expect. We aim to acknowledge
reports within 3 business days and to agree on a disclosure date with you.

## Supported versions

Until 1.0, only the latest release and `main` receive security fixes.

## Scope

In scope: the server, web UI, agent, installers, Docker deployment, and the
MeshCentral and EasyPatch integration code in this repository. Vulnerabilities
in MeshCentral, MeshAgent or EasyPatch themselves should also be reported to
those projects; tell us too if EasyRMM's configuration makes them reachable.

## Hardening documentation

See [`docs/security/`](docs/security/) for the threat model, RBAC model and
operational hardening guidance.
