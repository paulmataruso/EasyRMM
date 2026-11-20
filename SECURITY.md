# Security policy

EasyRMM controls remote computers and installs software on them. We treat
every vulnerability report as a priority.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
<https://github.com/paulmataruso/EasyRMM/security/advisories/new>.

Please include the affected version or commit, a description, reproduction
steps or a proof of concept, and the impact you expect. We aim to
acknowledge reports within 3 business days and to agree on a disclosure
date with you, and we credit you in the advisory unless you prefer
otherwise.

## Supported versions

Until 1.0.0, only the latest release candidate and `main` receive security
fixes. From 1.0.0, the newest minor release does. Upgrade the server
([Upgrading](docs/operations/upgrading.md)); by default the agents then
update themselves from it (**Settings → Agent updates** for the EasyRMM
agent, the patch policy's agent updates for the EasyPatch agent). The
EasyPatch agent a release carries is the supported one.

## Scope

Everything in this repository: the server and its console, the EasyRMM
agent and its install scripts, the patching engine (`easypatch/`), the
EasyPatch agent and its packages, the release signing, and the Docker
deployment. Vulnerabilities in MeshCentral or MeshAgent themselves should
also be reported to that project; tell us too if EasyRMM's configuration
makes them reachable.

We especially want to hear about:

* a way for the server, or anyone who controls it, to make the EasyPatch
  agent run a command or install anything other than updates, a signed agent
  package or an approved application;
* a way around authentication or authorization: sessions and second
  factors, roles and organization boundaries, the remote-access gateway's
  grants, the agents' signed requests, or the statements EasyRMM sends the
  patching engine;
* ways to read or forge agent credentials, enrollment tokens or signed jobs;
* secrets written to logs, images or the database in plain text.

Limits already listed in the [threat model](docs/security/threat-model.md)
are not new vulnerabilities, but reports that show they are worse than
described are welcome.

## Verifying releases

How releases and agent packages are signed, and how to check them, is in
[CODE_SIGNING.md](CODE_SIGNING.md).

## Security documentation

* [Threat model](docs/security/threat-model.md): what EasyRMM protects, from
  whom, and where each boundary is enforced.
* [Security review](docs/security/security-review.md): the review before the
  first release, its findings and what became of them.
* [Roles and permissions](docs/security/rbac.md),
  [Signing in](docs/security/sign-in.md) and
  [Single sign-on](docs/security/single-sign-on.md).
* [Agent release signing](docs/architecture/patching-engine.md#agent-release-signing)
  for the EasyPatch agent's packages.
* Deployment guidance (TLS and the server's own certificate authority) is in
  [`docs/deployment/`](docs/deployment/); the ports to open in a firewall are
  in [`docs/architecture/network.md`](docs/architecture/network.md).
