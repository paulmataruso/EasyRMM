# Security policy

EasyRMM controls remote computers, and EasyPatch, its patch management,
installs software on them. We treat every vulnerability report as a
priority.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
<https://github.com/paulmataruso/EasyRMM/security/advisories/new>.

This link covers the whole project, EasyPatch (`easypatch/`) included.

Please include whether it affects EasyRMM or EasyPatch, the affected version
or commit, a description, reproduction steps or a proof of concept, and the
impact you expect. We aim to acknowledge reports within 3 business days and
to agree on a disclosure date with you.

## Supported versions

Until 1.0, only EasyRMM's latest release and `main` receive security fixes.
EasyPatch's supported versions are in
[easypatch/SECURITY.md](easypatch/SECURITY.md).

## Scope

In scope: the server, web UI, agent, installers, Docker deployment, and the
MeshCentral and EasyPatch integration code in this repository, and EasyPatch
itself (its scope is in [easypatch/SECURITY.md](easypatch/SECURITY.md)).
Vulnerabilities in MeshCentral or MeshAgent themselves should also be
reported to that project; tell us too if EasyRMM's configuration makes them
reachable.

## Hardening documentation

See [`docs/security/`](docs/security/):

* [Threat model](docs/security/threat-model.md): what EasyRMM protects, from
  whom, and where each boundary is enforced.
* [Phase 9 security review](docs/security/security-review.md): findings and
  what became of them.
* [Roles and permissions](docs/security/rbac.md) and
  [Signing in](docs/security/sign-in.md).

Deployment guidance is in [`docs/deployment/`](docs/deployment/) (TLS and
the internal certificate authority). The ports to open in a firewall are
in [`docs/architecture/network.md`](docs/architecture/network.md).

EasyPatch's security model, threat model and hardening checklist are in
[`easypatch/docs/security.md`](easypatch/docs/security.md).
