# Changelog

All notable changes to EasyPatch are listed here. Versions follow `MAJOR.MINOR.BUILD`; the server,
the web console and the agents share one version number.

## [1.10.0] - 2026-11-17

> **Users now sign in with their email address, not their username.** Before upgrading, make
> sure every user has an email address of their own (the upgrade stops, changing nothing, if two
> users share one, ignoring case) and that you know the address of your own account. Passkeys
> and security keys need the console to be reached by a DNS name with a certificate browsers
> trust. Pull both the server and the proxy image. The agents are unchanged in this release:
> there is no need to copy the 1.10.0 agent packages to `data/agent-packages/`.

### Added

- **Security keys and passkeys (WebAuthn).** On **My account → Passkeys and security keys**
  users add, rename and remove them. A security key can be the second step after the password
  instead of an authenticator code; a passkey signs in on its own with **Sign in with a
  passkey** (PIN or biometrics on the device count as the second factor). Either one satisfies
  the "MFA required" policy, and a new user can choose one instead of an authenticator app.
  Passkeys and security keys need the console to be reached by a **DNS name with a
  certificate the browser trusts**; on an IP address (or plain HTTP) the console says they are
  unavailable. **Reset MFA** also removes a user's passkeys and security keys. Verification
  uses the MIT-licensed `Fido2` library 4.3.3 (with `NSec.Cryptography` and `libsodium`,
  pinned).
- **Passkey offer after sign-in.** Users without a passkey are offered to create one, when
  passkeys work on the server and in their browser. "Not now" is remembered on the server for
  30 days.
- **Single sign-on with OpenID Connect** (Microsoft Entra ID, Google, Keycloak and other
  providers), configured under **Settings → Single sign-on** by super administrators. Each
  enabled provider adds a **Sign in with …** button; password sign-in stays available. The
  authorization code flow uses PKCE, `state` and `nonce`; the ID token's signature, issuer,
  audience, lifetime and nonce are checked. Existing users are linked on their first sign-in by
  a verified email address (optionally trusting the provider's email claim), then by the
  provider's issuer and subject. Creating accounts on first sign-in is off by default and needs
  allowed email domains; new accounts get the chosen role (Read only by default, never super
  administrator). EasyPatch's MFA still applies unless the provider is marked as enforcing MFA.
  Super administrators see and remove users' links under **Settings → Users**. Client secrets
  are encrypted with the Data Protection keys and never returned. The `api` container connects
  to the configured providers over HTTPS, and the proxy's access log replaces the callback's
  `code` and `state` parameters with `REDACTED`. Uses Microsoft IdentityModel 8.23.0 (MIT). See
  [docs/single-sign-on.md](docs/single-sign-on.md).
- **Restart all that need it** on an organization (page header) and on each site (*Sites* tab):
  lists the endpoints that report a pending restart, marking servers, domain controllers,
  offline endpoints and agents too old to restart, and restarts the ones you confirm. The
  restart options are the usual ones (now or at a time, countdown or prompt); the condition is
  always *only if pending*. API: `GET`/`POST /api/v1/organizations/{id}/restart-pending`.
- The *Sites* tab shows how many endpoints of each site have a restart pending (also
  `rebootPendingCount` on sites in the API).
- **My account → Change email**: users change their own email address, confirmed with their
  current password (`POST /api/v1/auth/email/change`; `409 email_in_use` when another user has the address). Super administrators can still change
  any user's email under **Settings → Users**.

### Changed

- **Users sign in with their email address**, not their username; case does not matter. The
  username stays as the account's name in the console and the audit log. The upgrade adds a
  unique index on `lower(email)` and stops, changing nothing, if two users share an address
  in different case (give one of them another address first). The administration commands
  `create-admin`, `reset-password`, `reset-mfa` and `unlock` take `--email` instead of
  `--username`; `create-admin --name` sets the account name. Creating or changing a user with
  an address another user has answers `409 email_in_use`, a taken username
  `409 username_in_use`.
- The endpoint page has a **Restart…** button next to **Scan now** (it was in the **More** menu).
- Bulk results show endpoints that were skipped on purpose as *Skipped* instead of *Failed*.

## [1.9.0] - 2026-11-16

> **The macOS agent added in this release is experimental: it is in development and not for
> production use.** It has not yet been used to patch a real Mac. Use it only on test Macs you
> can wipe. Nothing changes for Windows and Linux agents unless you copy the macOS packages to
> `data/agent-packages/`.

### Added

- **macOS agent (experimental, not for production use)** for macOS 14 and later on Intel and
  Apple silicon, as an unsigned `.pkg` (x64, arm64) built on Linux. It runs as the launchd
  daemon `com.dhitechnical.easypatch.agent`, reports the updates Apple's `softwareupdate` offers
  and the Mac's inventory, installs approved updates with `softwareupdate --install <label>`
  (never `--restart`), restarts only for administrator restart jobs, updates itself from
  release-signed `.pkg` packages and can be removed from the console or with
  `sudo /Library/EasyPatch/uninstall.sh`. An update counts as installed only when a new listing
  no longer shows it, or when `softwareupdate` says it is completed by a restart (then it is
  shown as waiting for the restart); updates that disappear without a matching
  `softwareupdate --history` entry are not reported installed, and an unreadable listing fails
  the scan instead of reporting no updates. See [docs/macos-agent.md](docs/macos-agent.md).
- Known limitations of the macOS agent: on Apple silicon it cannot install updates that need a
  restart (every macOS update), because Apple allows only a volume owner or MDM to; those fail
  at once with `macos_owner_required`. It gives no on-screen warning before a restart, the
  package is not signed with an Apple Developer ID or notarized, its private key is protected by
  file permissions only, and Macs have no CVE or end-of-support data.
- Console: macOS endpoints are labelled *macOS (experimental)* and show a warning banner. The
  deploy page has a **macOS (experimental)** tab with a `curl … | sudo sh` install script for
  deployment codes, an enroll command for tokens, and a warning that lists the limitations.
  Messages to users, update removal and downloads before the maintenance window are refused for
  Macs (`409 not_supported_on_macos`).
- `scripts/build-macos-packages.sh` builds and release-signs the `.pkg` packages on Linux
  (Docker, no Mac needed); the release workflow publishes them, and the agent workflow installs,
  runs and removes them on GitHub's macOS runners.

### Changed

- The server only offers an agent update in the package format of the endpoint's own platform
  (MSI for Windows, `.deb` or `.rpm` for Linux, `.pkg` for macOS).

### Fixed

- Agents (all platforms) rotate their log before writing to it instead of after, so `agent.log`
  always holds the newest lines; right after a rotation it could be missing until the next line.

## [1.8.0] - 2026-11-15

Items marked *Needs Windows agent 1.8.0* are not offered to older agents: removing an update from
an endpoint with an older agent is refused with a message to update the agent first, and older
agents are not sent downloads ahead of the maintenance window.

### Added

- **Roll back an installed Windows update**: operators can remove one installed update from an
  endpoint (its **Installed** tab, or an update waiting for a restart), or from every endpoint
  of an organization or site on the update's page. The agent uses Windows Update's own
  uninstall when the update supports it, otherwise DISM (`/Remove-Package`, always with
  `/NoRestart`). The removal counts only when the package is no longer installed, a scan
  follows, and the computer is never restarted. By default the update is also excluded on each
  endpoint so it is not installed again. Needs Windows agent 1.8.0.
- **Update holds and the rollout guard**: when an update fails on at least 3 endpoints and on at
  least 20% of the endpoints that tried it in the last 7 days, the worker puts it on hold for
  every organization (on by default; thresholds under **Settings → Server settings → Rollout
  guard**). Administrators can also hold an update for an organization (super administrators
  for every organization) and release holds on the update's page. A held update is left out of
  maintenance-window installations and *Install all missing*, including jobs already queued;
  selecting it by hand still installs it, with a warning. New alert type and default rule
  *Update on hold*, and an option to hold an update when removing it from endpoints.
- **Download before the maintenance window**: a new policy setting (0 to 24 hours, off by
  default) has Windows agents download the updates the next maintenance window will install in
  the hours before it starts, so the window is spent installing. Downloads go through the
  Windows Update Agent (WSUS and Group Policy still apply), install nothing, stop when the
  window starts, skip held updates and never change compliance. They are limited per site by
  the policy's maximum concurrent installations. Needs Windows agent 1.8.0.
- **API tokens** for scripts and integrations (**Settings → API tokens**, super administrators):
  read-only or operator, optionally limited to some organizations, expiring after at most 365
  days, revocable, with the time and address of their last use. Sent as
  `Authorization: Bearer ept_…`; only a hash is stored, the secret is shown once, and actions are
  audited as `token:<name>`. Tokens cannot manage users, API tokens or server settings. See
  [api.md](docs/api.md#api-tokens-apiv1api-tokens-superadmin).

### Changed

- Updates that Windows offers again right after a successful installation (for example the
  Windows Security platform update KB5007651) are now **Reoffered** instead of **Failed**. They
  do not count against compliance (they still count as known exploited), automatic
  installations skip them, they can still be installed by selecting them, and a new revision
  makes them Missing again. Existing rows are migrated.

### Fixed

- The Windows agent reported a pending restart when the only queued file operations were
  deletions of temporary files (`PendingFileRenameOperations` entries without a destination),
  which Windows carries out at the next start without anything waiting for it. Only file
  replacements now count. Needs Windows agent 1.8.0.

## [1.7.1] - 2026-11-15

### Fixed

- Agent updates could fail with `Downloading EasyPatchAgent-… failed with HTTP 404` right after
  new packages were copied into `data/agent-packages/`: the worker offered the new version to
  agents while the API still served its package list from before the copy (each refreshes it
  once a minute), and the failed update was only retried 6 hours later. The API now looks at
  the folder again when an agent asks for a package that is there but not in its list yet.

## [1.7.0] - 2026-11-15

The first published release since 1.4.0. It also contains the changes listed under 1.5.0, 1.5.1,
1.5.3, 1.6.0 and 1.6.1 in
[CHANGELOG.md](https://github.com/paulmataruso/EasyPatch/blob/v1.7.0/CHANGELOG.md).

### Added

- **Download and install progress per update**: while a job runs, the job page and the
  endpoint's update list show how far each Windows update has downloaded and installed (in
  percent, as Windows Update reports it), and the tray's status window shows it in the current
  activity. Agents report the percentage at most every 10 seconds. If Windows Update does not
  support progress reporting for an update, it is installed as before, without a percentage.
  Needs agent 1.7.0 or later.
- **The Windows agent installs winget**: when a computer has no App Installer (winget) 1.6 or
  newer for all users, the agent installs winget 1.29.380 a few minutes after it starts, so
  application updates work without preparation (Windows Server 2019 and 2022 and Windows 10 LTSC
  do not include it). It downloads the release from GitHub, or from the EasyPatch server when
  GitHub cannot be reached; the server fetches its own copy from GitHub the first time an agent
  asks (`GET /downloads/winget/{file}`). Every file must match the size and SHA-256 built into
  the agent, and App Installer is installed for all users with DISM. Failures are shown on the
  endpoint's Overview tab and retried later. Needs Windows 10 1809 or Windows Server 2019 or
  later. Event IDs 1018 (installed) and 1019 (failed).

### Changed

- The Compose file adds the `winget` volume (the server's copy of winget, written by the
  `worker`). Use the new `docker-compose.yml`.

## [1.6.1] - 2026-11-15

### Fixed

- Windows agents installed or updated by the MSI did not offer *Uninstall agent* until their
  service restarted: Windows Installer starts the service before it registers the product, and
  the agent looked for the product only once, at startup. It now looks again at each check-in
  until it finds it.

## [1.6.0] - 2026-11-15

### Added

- **Uninstall the agent from the console**: *More → Uninstall agent…* on the endpoint page
  (Operators, confirmed by typing the computer name). The agent removes its own package the
  next time it checks in (Windows Installer by the MSI's upgrade code; `apt-get remove` or
  `rpm -e easypatch-agent` on Linux) and nothing else. The package's uninstall step restores
  the Windows Update settings EasyPatch changed and unenrolls the agent; the job completes when
  that unenrollment reaches the server, and the endpoint becomes decommissioned with its other
  queued jobs cancelled. Needs agent 1.6.0 or later. API: `POST /endpoints/{id}/uninstall-agent`.
- **Tags on organizations and sites** (pilot groups): tag a customer or an office, for example
  *Pilot*, and every endpoint in it has the tag and its tag policy, including its rollout
  delay. Set on the organization page (header and *Sites* tab). Inherited tags are shown with a
  dashed outline on endpoints, count in *Settings → Tags*, and match the endpoint tag filter and
  alert rule tag scopes. API: `PUT /organizations/{id}/tags`, `PUT /sites/{id}/tags`.

### Changed

- Removing the Linux package (not upgrading it) now stops the service and unenrolls the agent
  first, as the Windows uninstaller does.
- Endpoint events for an uninstall read "Agent uninstalled." instead of repeating the reason.

## [1.5.3] - 2026-11-15

### Added

- **What a pending restart is for**, on the endpoint page: the updates waiting for the restart
  (installed and waiting, listed by Windows Update, or named by a pending Windows servicing
  package, with links to the updates), other pending servicing packages, and the files Windows
  will replace or delete during the restart (the first 25, with the user name in profile paths
  replaced by `*`), which shows which program asked for it. Windows agents 1.5.3 and later report
  the details; for older agents only installed updates waiting for the restart are listed.

## [1.5.1] - 2026-11-15

### Added

- **Skip certificate check** for the Windows install script (off by default), for servers with
  a private CA such as the lab setup. The one-liner and the script download without checking the
  server certificate; the script then passes the CA that the lab proxy publishes at
  `/server-ca.crt` to the MSI. The agent trusts that CA for its connection to EasyPatch only and
  keeps checking certificates (name, validity, chain). Use it only on a network you trust.
- MSI property `SERVERCACERT`: a certificate authority the agent trusts for its connection to the
  server only. It is remembered on upgrade.

### Changed

- The tray's status window, menus and restart prompts follow the Windows app mode (dark or light).
- Console: *Pending Approvals* is its own item in the sidebar (with the count of waiting
  computers), and *Agent Management* is renamed *Deploy* (enrollment tokens, deployment codes and
  agent packages). Old `/agents` links still work.

## [1.5.0] - 2026-11-15

Update the server before the Windows agents: a 1.5.0 agent reports update checks started from
the status window with the scan trigger `User`, which older servers reject.

### Added

- **Status window in the Windows tray.** Clicking the EasyPatch icon (or *Open EasyPatch
  status* in its menu) opens a window with a colored summary (up to date, updates available,
  restart required, busy, can't reach the server, waiting for approval, not enrolled), the
  details behind it (server connection and last check-in, the server's host name, last update
  check and the number of applicable updates, last installation, restart needed, current
  activity, computer name, agent version) and the newest 200 agent log entries (first lines
  only, redacted, with *Copy* for support tickets).
- **Check in now** and **Check for updates** in the status window. An update check is a scan
  only; it never installs anything and is reported with the scan trigger `User`. Both are
  limited for the whole computer: a check-in every 30 seconds, an update check every 5 minutes
  and not while Windows Update is busy.
- The icon's tooltip shows the agent version and the current status, and its menu shows the
  agent version.

### Changed

- The tray pipe carries larger frames from the service to the tray (up to 256 KB, for the
  log); frames from a tray are still limited to 16 KB.
- The `.deb` package's maintainer and the `.rpm` package's packager are now
  DHI Technical Services LLC (paulmataruso@dhitechnical.com).

## [1.4.0] - 2026-11-14

First public release. It contains everything below plus these additions.

### Added

- **Endpoint tags and rollout rings.** MSP-wide tags (for example *Pilot* or *Servers*) with their
  own policy layer and priority, and a **rollout delay** in policy with separate values for
  security and other updates, so a pilot ring gets updates first.
- **Alerts and notifications.** Eight built-in rules (endpoint offline, install failed, security
  update missing, known-exploited vulnerability unpatched, scan stale, restart pending, enrollment
  waiting for approval, unsupported operating system). Alerts resolve by themselves when the
  condition clears. Notifications go to email (SMTP), Slack, Microsoft Teams or a signed JSON
  webhook. Webhooks are limited to public HTTPS addresses unless private addresses are allowed.
- **CVE and CISA KEV prioritization.** Updates show the CVEs they fix: Windows from Microsoft's
  security update data, Debian from the Debian Security Tracker, and RHEL-family and Fedora from
  the dnf advisories. Updates fixing a vulnerability in the CISA Known Exploited Vulnerabilities
  catalog are flagged, listed first and, by default, skip the rollout delay.
- **Monthly PDF compliance reports** per organization, generated on demand or emailed on a chosen
  day over STARTTLS or TLS, with an optional *Prepared by* brand name.
- **Third-party application updates on Windows (opt-in)** with winget: upgrades of already
  installed applications on an approved list of package IDs, from the winget community repository
  only, counted as installed only when winget lists the new version.
- **SMTP: skip certificate validation** (off by default, audited), for internal mail servers with
  self-signed certificates.

### Fixed

- Windows feature updates are no longer shown as fixing the CVEs of the cumulative update they
  share a KB number with.

## [1.3.2] - 2026-11-14

### Added

- Linux agent: dnf5 support (Fedora 41 and later), tolerance of `systemd` re-executing during
  upgrades, and newer lifecycle dates for Ubuntu 26.04, Debian 13, EL10 and Fedora.
- The Linux install script can reinstall an agent that is not enrolled.

## [1.3.0] - 2026-11-14

### Added

- **Linux agent** for Debian and Ubuntu (apt) and Red Hat Enterprise Linux, Rocky Linux,
  AlmaLinux, Oracle Linux, CentOS Stream and Fedora (dnf), as signed `.deb` and `.rpm` packages
  for x64 and ARM64, with a one-line install script for deployment codes. It installs upgrades of
  installed packages at exact versions and uses the same policies, jobs, restarts and compliance
  reporting as Windows.

## [1.2.0] - 2026-11-14

### Added

- **Agent self-update** from packages signed with your own release key (ECDSA P-256). The public
  key is built into the agent, which verifies every package itself and never downgrades. An
  *Agent updates* policy (Automatic or Manual) at global, organization, site and endpoint level,
  plus *Update agent* for one or many endpoints.

## [1.1.1] - 2026-11-13

### Fixed

- The tray icon did not connect for users without administrator rights.

## [1.1.0] - 2026-11-13

### Added

- Tray icon for every signed-in user, install notifications and preset messages to users (no
  free text).
- Restarts of one or many endpoints, now, at a chosen time or on a recurring schedule, with a
  countdown or a postpone deadline for signed-in users. A restart job completes only when the boot
  time shows that the computer restarted.
- Windows Update policy overrides per organization, site or endpoint (Automatic Updates mode,
  feature and quality update deferral, pausing, restart behaviour and active hours). Each group is
  *Not configured* by default, conflicts with Group Policy, WSUS or Intune are reported, and the
  original values are restored when an override is removed.
- Policy can be set per endpoint.

## [1.0.0] - 2026-11-13

### Added

- Server (ASP.NET Core, PostgreSQL), web console (React) and Windows agent (Windows Update Agent
  API) with an MSI installer.
- Organizations, sites and inherited policies; enrollment tokens and tokenless deployment codes
  with administrator approval; per-device ECDSA agent credentials with signed requests.
- Scans, inventory, install jobs with a durable queue, verification of installed updates by scan,
  maintenance windows, compliance status, OS support status and CSV reports.
- Argon2id passwords, mandatory TOTP MFA, roles and an audit log.

[1.4.0]: https://github.com/paulmataruso/EasyPatch/releases/tag/v1.4.0
