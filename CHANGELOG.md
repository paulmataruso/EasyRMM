# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **The patch policy's delay hints say what the engine does.** A delay
  counts from when an update first appears on any device, not from its
  release; the delay for security updates covers security updates only
  (critical updates take the other delay), and definition updates are never
  delayed. A device's policy shows "7 days after first seen".
- **Messages call the engine the patching engine.** A failed EasyPatch agent
  install on a device's page, and the patching engine's alerts and events,
  no longer call the engine "EasyPatch"; the EasyPatch agent keeps its name.
- **The console fetches each page when it is first shown.** The script the
  browser loads first went from 618 kB to 75 kB (plus the libraries, which
  browsers keep across upgrades). If a page cannot be fetched because
  EasyRMM was upgraded while the console was open, the console reloads
  once to get the new version; if it still cannot, it says so and offers
  **Reload**.

### Removed

- **What only EasyPatch's own console reached**
  ([ADR-0048](docs/architecture/adr/0048-the-engine-keeps-what-is-reached.md)).
  The patching engine no longer keeps deployment codes, enrollment requests
  waiting for approval or their install scripts, and a migration drops
  their tables. The EasyPatch agent enrolls only with the single-use token
  EasyRMM gives it; an older agent installed with a code is refused with
  `deployment_codes_retired`. Engine routes EasyRMM never calls go too, as
  do the "Enrollment waiting for approval" patching alert and the restart
  dialog's fallback for engines before 1.10.0.
- **The check for the engine's scheduled-installs capability.** EasyRMM
  ships with its engine, so the install dialog always offers a later time,
  and `canSchedule` and the engine's `capabilities` leave the API.

### Fixed

- **The agent stops a package manager gently.** An `rpm` query, or an
  `apt-get` or `dnf` install of the EasyPatch agent, that ran past its
  deadline was killed outright, which can leave the package database locked
  or, with RHEL 8's Berkeley DB, needing recovery. It is now asked to stop
  (SIGTERM) and killed only if it has not stopped 10 seconds (a query) or 30
  seconds (an install) later.
- **A damaged RPM database is named.** When `dnf` cannot install the
  EasyPatch agent because the machine's RPM database cannot be opened
  (`DB_RUNRECOVERY`, `rpmdb open failed`), the device's install status says
  to run `rpm --rebuilddb` as root and install again. Found on the first real
  deployment, on a RHEL 8.10 machine whose database was already damaged when
  it enrolled.
- **Sign-in says when no passkey answered.** When the browser's passkey or
  security key prompt ended without a key, sign-in and the second factor
  showed nothing, so a password manager that did not open (locked, or
  updated since the page loaded) looked like a page that ignored the click.
  They now say no passkey or security key answered and suggest reloading the
  page. Browsers report a closed prompt the same way, so it is a note, not an
  error.
- **The patching engine sorts agent versions as versions.** Its endpoint
  list, sorted by agent version, put 1.10.0 before 1.9.0. It now compares the
  numbers, in the database so that paging stays right.
- **The patching engine refuses a null list from an agent.** An agent
  request that sent `null` for a list, such as `"activeJobIds": null`, got a
  server error; it now gets `400 validation_failed` naming the list.
  EasyPatch agents never send one.
- **Software on Windows treats a missing package as Linux does.**
  *Uninstall* of a package that is not installed now succeeds with winget
  and Chocolatey, as the guide says, instead of failing; *Update* of one
  fails with exit code 3 and says it is not installed; a winget *Install* of
  an ID the `winget` source does not have says so. Chocolatey's check uses
  its own list of installed packages, so `choco` does not run.
  The guide also said winget's *Install* leaves an installed package as it
  is; winget updates it when a newer version exists, and the guide now says
  so.

## [1.0.0-rc.2] - 2026-11-20

The second release candidate, with what the first real deployment of
rc.1 found. Patching engine 1.11.1.

### Added

- **Show a token's install commands again.** Under Devices → Add devices,
  an active deployment or approval token has **Show install commands**,
  which opens the same install steps as when it was created. The server
  keeps each new token sealed with its encryption key, bound to the token;
  only people who manage the token can show it, only while it can still add
  devices, and each time is in the audit log (`enrollment_token.reveal`,
  `approval_token.reveal`). Tokens created before this release keep only
  their hash and say so (ADR-0047; migration 00024).

### Fixed

- A device approved in the console no longer shows twice for a few seconds.
  Its agent installs MeshAgent, and MeshCentral reported the new node before
  the agent's next heartbeat claimed it, so the node was listed as a
  discovered device of its own until the two were merged. A node no device
  claims now waits two minutes (two heartbeats) before it is recorded as
  discovered; a MeshAgent installed by hand shows up after that wait.

## [1.0.0-rc.1] - 2026-11-20

EasyRMM's first release candidate, for testing on a real server before
1.0.0: self-hosted remote monitoring, management and patching for MSPs, in
one Docker Compose deployment on host networking. Its patching engine,
EasyPatch's server, is built from the same commit and released with it as
version 1.11.0. Source-available under [FSL-1.1-ALv2](LICENSE.md).

### Added

- **Endpoints and the agent**
  - The EasyRMM agent for Windows (x64, ARM64) and Linux (x86-64, ARM64,
    ARMv7, x86), installed with one PowerShell or shell command from
    **Devices → Add devices**; it installs MeshAgent too.
  - Deployment tokens per site, or one approval token for every customer,
    with each computer approved into a site in the console.
  - Outbound HTTPS only: a signed heartbeat every minute, jobs by long poll.
  - Agent updates a few devices at a time (**Settings → Agent updates**),
    rolled back when a new build crashes or cannot reach the server.
- **Remote access**
  - Remote desktop, terminal and files, and RDP to Windows devices, through
    MeshCentral 1.3.1 behind EasyRMM's gateway; each session authorized and
    audited, RDP credentials never stored.
- **Inventory, monitoring and alerts**
  - Hardware, operating system, network and installed software; processor,
    memory, load and disk use charted on each device's page.
  - Alert policies for offline devices and processor, memory or disk use;
    alerts acknowledged and resolved in the console.
- **Scripts, jobs and software**
  - A script library (PowerShell, cmd, Bash, sh, Python 3) at shared,
    organization and site level; jobs on up to 500 devices, with output.
  - Software installed, updated and uninstalled through winget, Chocolatey,
    apt-get, dnf, yum or zypper, on one device or many.
  - A warning on scripts that install updates themselves and so bypass
    patch policies and maintenance windows.
- **Reports**
  - Device inventory, installed software, device health and alert history,
    in the console or as CSV.
  - Patch compliance with its trend, patch installations, and monthly patch
    reports: PDFs made by hand or on a schedule, downloaded or emailed.
- **Patching**
  - The patching engine in every deployment, on loopback with its own
    database; EasyRMM keeps its organizations and sites in step.
  - The EasyPatch agent for Windows (Windows Update, winget application
    updates) and Linux (apt, dnf), installed by the EasyRMM agent on chosen
    devices or across an organization (**Settings → Patching engine**).
  - **Patching**: what needs attention, worst first; devices; every update
    with its CVEs and known exploitation (CISA KEV); jobs and alerts; scans,
    installs, holds, restarts and retries across devices.
  - A device's **Patches** tab: install preview, exclusions, removing a
    Windows update, restarts, messages to users, the agent's version, the
    policy in effect with each value's layer, and stopping patching.
  - Patch policies for the default, organizations, sites, tags and devices:
    maintenance windows, delays, categories, restarts, Windows Update.
  - **Settings → Patching**: tags, report schedules, engine settings, OS
    lifecycle dates, agent packages, alert rules, notification channels
    (email, Slack, Microsoft Teams, webhooks) and the engine's audit log.
- **Organizations, users and sign-in**
  - Organizations (each with a time zone), sites and device groups; five
    built-in roles, Super Admin for the whole server and the others per
    organization or site.
  - Sign-in with a password and a required second factor (authenticator
    app with recovery codes, security key or passkey), or a passkey alone.
  - Single sign-on with OpenID Connect (**Settings → Single sign-on**);
    Authentik as an install option (`setup.sh --with-authentik`); a
    one-time recovery link from `easyrmm-server recover`.
  - A hash-chained audit log, forwarded to syslog or a SIEM if wanted
    (**Settings → Audit forwarding**).
- **Deployment**
  - One Docker Compose deployment on host networking: only EasyRMM's server
    listens publicly; MeshCentral, the patching engine and PostgreSQL on
    loopback ([guide](docs/deployment/docker.md)).
  - TLS by Let's Encrypt, your own certificate, the server's own CA, or
    NGINX in front ([guide](docs/deployment/nginx.md)).
  - Access by IP address beside the DNS name, or by IP alone; install
    commands by IP pin the server's key.
  - Backup and restore ([guide](docs/operations/backup-restore.md)) and
    upgrades ([guide](docs/operations/upgrading.md)).
  - Importing a standalone EasyPatch server (1.4 to 1.10) from its backup;
    its agents keep working ([guide](docs/operations/import-easypatch.md)).
- **Releases**
  - One release from one commit: server and engine images for amd64 and
    arm64, and a deployment bundle pinning both by digest, with the EasyRMM
    agents and `SHA256SUMS`.

### Security

- Tenant isolation in PostgreSQL by forced row-level security.
- Passwords hashed with Argon2id; secrets sealed with AES-256-GCM.
- Agent requests signed with each device's Ed25519 key; jobs and agent
  updates signed with the server's job key, pinned at enrollment.
- Remote sessions only with a grant for one device and session type; no
  TCP or UDP tunnels through agents.
- The patching engine accepts only EasyRMM's signed statements (30 seconds,
  one request) and its agents' signed requests.
- EasyPatch agent packages are signed with the release key, and the agent
  installs nothing else; it cannot run commands.
- Images and release files attested (Sigstore) with SBOMs and provenance,
  and scanned with Trivy ([CODE_SIGNING.md](CODE_SIGNING.md)).
- A security review of sign-in, the agent channel, remote access and tenant
  isolation ([findings](docs/security/security-review.md)).

### Known limitations

- No MSI, DEB or RPM packages of the EasyRMM agent: install commands only.
- No Authenticode signature on `easyrmm-agent.exe` or EasyPatch agent MSIs.
- Email and webhook notifications for patching alerts only, not device
  alerts; not yet tested against a real mail server or webhook receiver.
- No agent WebSocket channel: jobs arrive by long polling. Script output is
  not streamed, and scripts cannot be scheduled.
- Devices cannot be moved, renamed or removed in the console yet. No
  inventory history, scheduled device reports or software catalog.
- Not yet run end to end on a real Windows machine: RDP, the winget and
  Chocolatey scripts, undoing a crashing agent update, the ARM64 agent.
- No Windows update has yet been installed through EasyRMM on a real
  machine (the test machines had none missing); nor removing an update,
  messages to users, restart modes other than the countdown, or policy
  changes applied on Windows.
- The macOS EasyPatch agent is experimental and not released.
- Single sign-on has no group-to-role mapping, SAML or just-in-time
  accounts, and has not been tried with Entra ID, Google, Okta or Keycloak.
  The Authentik option has run only on an install addressed by IP.
- Security keys and passkeys need a DNS name and have not been tried with a
  physical key.
- One patching engine API instance per deployment; it cannot reach webhooks
  on the server's own subnet. The Linux EasyPatch agent needs systemd.
- EasyPatch's standalone console is not part of EasyRMM. The import needs
  an engine with no agents yet, and is tested only from EasyPatch 1.10.0
  with a Linux agent.
- The `internal` certificate authority has no name constraints: install it
  only on technicians' computers.
- Inviting an address that has an account on the server says that it
  exists ([roles](docs/security/rbac.md)).
- No outside penetration test yet.
