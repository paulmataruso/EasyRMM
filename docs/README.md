# Documentation

Everything about running, using and building EasyRMM. Start with the
[README](../README.md) for what it is, and the
[Docker deployment](deployment/docker.md) to install it.

## Deploy

* [Docker deployment](deployment/docker.md): requirements, install, TLS
  modes, running without DNS, remote access, Authentik, the patching engine,
  retention and the containers' security.
* [Running behind NGINX](deployment/nginx.md): TLS offload to an existing
  reverse proxy.
* [Installing the EasyRMM agent](deployment/agents.md): tokens, approval,
  Windows and Linux install commands, updates and uninstalling.
* [The EasyPatch agent](deployment/patching-agent.md): how EasyRMM installs
  it, what it puts on Windows and Linux, its logs, updates and
  troubleshooting.
* [Upgrading EasyRMM](operations/upgrading.md) and
  [Backup and restore](operations/backup-restore.md).
* [Importing a standalone EasyPatch](operations/import-easypatch.md): moving
  an EasyPatch 1.4 to 1.10 server, its agents and history into EasyRMM.

## Use

* [Patching](operations/patching.md): status, scans, installs, restarts,
  holds, policies, reports, alerts and the engine's settings.
* [Inventory and health](operations/inventory.md)
* [Alerts](operations/alerts.md)
* [Scripts and jobs](operations/scripts-and-jobs.md)
* [Installing, updating and removing software](operations/software.md)
* [Hardening Linux computers](operations/hardening.md): checks, each
  device's findings, and drift across the fleet.
* [Reports](operations/reports.md)
* [Forwarding the audit log](operations/audit-forwarding.md)
* [Mail](operations/mail.md): the mail server in the console or `.env`,
  the test message, and the limits.

## Secure

* [Signing in](security/sign-in.md): passwords, second factors, security
  keys and passkeys, sessions.
* [Single sign-on](security/single-sign-on.md) with OpenID Connect.
* [Roles and permissions](security/rbac.md)
* [Threat model](security/threat-model.md)
* [Security review before the first release](security/security-review.md)
* Outside `docs/`: [SECURITY.md](../SECURITY.md) (reporting
  vulnerabilities), [PRIVACY.md](../PRIVACY.md) and
  [CODE_SIGNING.md](../CODE_SIGNING.md).

## Understand

* [Architecture](architecture/overview.md): the system, its components and
  how they fit.
* [Network](architecture/network.md): ports, names and the firewall.
* [Database](architecture/database.md): schema, roles and row-level
  security.
* [Patching engine](architecture/patching-engine.md): how patching works
  inside.
* [Architecture decision records](architecture/adr/README.md): why it is
  built this way.
* [Feature plan](architecture/feature-plan.md): how the next nine
  features will work and the order they are built in.
* [MSP feature plan](architecture/feature-plan-msp.md): the twelve
  features asked for on 2026-11-21 and a keystore for recovery keys,
  planned from the owner's
  [requirements](architecture/requirements/2026-11-21-msp-features.md).

## Develop

* [Development guide](development/README.md): layout, builds, tests and CI.
* [Developing the technician console](development/web-console.md)
* [Drills](development/drills.md): backup and restore, load and soak.
* [Hand test: software on Windows](development/windows-software-hand-test.md):
  winget and Chocolatey on a real computer.
* [Releasing](development/releasing.md)
* [Diagrams](images/diagrams/README.md): how the diagrams are drawn.
* Outside `docs/`: [CONTRIBUTING.md](../CONTRIBUTING.md),
  [DESIGN.md](../DESIGN.md) and [PRODUCT.md](../PRODUCT.md).
