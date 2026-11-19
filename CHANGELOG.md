# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **The patching engine inside EasyRMM's deployment, for testing** (one-product
  plan, phase B1): `scripts/setup.sh --patching bundled` runs EasyPatch's API
  and worker from `deploy/docker-compose.yml`, on host networking and loopback
  only (127.0.0.1:18180 and :18181), with their own database and roles in
  EasyRMM's PostgreSQL. `easypatch-db-init` creates them, also on an existing
  install; setup.sh adds the new secrets to an older `.env` without changing
  what it has. A compose test keeps every service on host networking, every
  listener but the edge on loopback, and no two on one port.
- **EasyRMM's statements to its patching engine** (phase B2, ADR-0038): EasyRMM
  can call the engine with a statement per request in `X-EasyRMM-Assertion`,
  signed with `EASYRMM_PATCHING_KEY` from `.env`, naming who acts and the
  role and organizations that one call may use, for that method and target
  only, for 30 seconds. The engine builds its principal from the statement,
  without user rows, sessions or CSRF tokens, and still applies its own role
  and organization checks; its audit trail names `easyrmm:<user>`. A shared
  test statement keeps EasyRMM's Go signer and the engine's .NET check in
  agreement.
- **Patching from the engine in the deployment** (phase B3): with
  `EASYRMM_PATCHING=bundled`, the patching pages use the engine on loopback
  instead of a server set up in Settings. Each person's call carries their
  role and the organizations it concerns: read-only for views, Admin for
  scans and installs. Settings → EasyPatch shows the engine and cannot
  change it. The engine refusing EasyRMM shows as `patching_unavailable`,
  never as a 401 or 403, and EasyPatch's field errors become EasyRMM's.
  Switching to bundled forgets a connected server and its links, with an
  audit record.
- **EasyPatch agents on EasyRMM's name** (phase B4, ADR-0039): in bundled
  mode, EasyRMM's edge forwards exactly the engine's agent API and package
  downloads to it, before the session and CSRF layers, byte for byte so
  agents' request signatures hold, with the client address EasyRMM
  resolved. Statements and cookies from outside never reach the engine;
  its answers cannot set cookies, clear site data or run script on
  EasyRMM's origin. Paths that could reach the rest of the engine are
  refused; requests are capped at 20 MB.
- **One set of organizations** (phase B5, ADR-0040): with the bundled engine,
  every EasyRMM organization and site has its own in the engine, created
  with EasyRMM's name and time zone, renamed with it, archived under a freed
  name when deleted, and put back when someone archives or deletes it in the
  engine. Names that clash ignoring case get part of EasyRMM's id. A create
  whose reply was lost is adopted, not repeated. Changes reach the engine at
  once; the whole set is compared every 5 minutes, and again every minute
  while the engine is unavailable. Settings → EasyPatch shows whether the
  engine is in step and no longer links organizations by hand. A device
  moved to another site takes its endpoint with it; one moved to another
  organization, or deleted, has its EasyPatch agent uninstall itself, and
  the endpoint is revoked if it has not within 7 days.
- **Agent packages in the engine's image** (phase B6, ADR-0041): a released
  engine image carries the EasyPatch agent's Windows and Linux packages of its
  version with their release signatures, checked against the release public
  key before the build and in the image after it. EasyRMM's compose file no
  longer mounts a package directory, so there is nothing to download or copy.
  CI images carry Linux packages signed with a key made for the run.
- **One release** (phase B8, ADR-0043): EasyRMM's release workflow builds
  the patching engine from the same commit (EasyPatch's tests, its agent
  packages signed with the release key, its server image) and the release
  bundle's `docker-compose.yml` pins that engine by digest, so upgrading the
  bundle upgrades both. A manifest (`easyrmm-<version>-manifest.json`)
  records both images by digest, the engine's version and its agent
  packages. The engine keeps its own version line, and a version is
  published only once.
- **The bundle test** (`make e2e-bundle`, CI's *Bundle end to end*): the
  deployment a release ships, brought up with the engine on host networking
  and addressed by IP, then a Debian machine with systemd is set up through
  the console: first account, install command, EasyPatch agent, a scan and
  an update from a local package repository. It also checks that only the
  edge listens beyond loopback, and that the engine refuses missing, forged,
  altered, expired, replayed and out-of-scope statements.
- **Patching on installs addressed by IP** (phase B7, ADR-0042): with the
  bundled engine and `EASYRMM_TLS_MODE=internal`, EasyRMM gives the EasyPatch
  agents its own certificate authority, which they trust for EasyRMM's
  address only: the Windows MSI as `SERVERCACERT`, the Linux agent with the
  new `enroll --server-ca`. A connected EasyPatch server's authority now
  reaches Linux agents the same way. Linux agents from before that option
  are enrolled without it, and need the authority in the device's store.
- **The device's Patches tab does what EasyPatch's endpoint page did**
  (one-product plan, phase C1): exclude an update on the device and include
  it again; remove an installed Windows update, excluding it too by
  default; send the signed-in users one of EasyPatch's preset messages; update
  the EasyPatch agent; see what an install would do before it starts; the
  whole effective policy with the layer that set each value, and how Windows
  applied its Windows Update settings; what a pending restart is for; who
  is signed in and whether the EasyPatch icon reaches them. The actions need
  `patch.manage` and are audited as `patch.exclude`, `patch.include`,
  `patch.remove_update`, `patch.notify` and `patch.agent_update`. Links to
  EasyPatch's console show only where there is one: the bundled engine has
  none.
- **Patching's overview, its update list and holds** (one-product plan, phase
  C2): Patching opens on an overview of the devices you can see (the share
  up to date, what needs attention worst first with links to the filtered
  lists, organizations least up to date first, and EasyPatch endpoints with
  no EasyRMM device, with how to link them). The **Updates** tab lists every
  update across devices with its counts, exploited ones first, filtered and
  ordered; an update's page shows what it fixes, its holds and the devices
  reporting it, and installs it on chosen devices or wherever it is missing,
  removes a Windows update across devices, and holds it in an organization
  or, for super administrators, everywhere. Holds need `patch.configure` and
  are audited as `patch.hold` and `patch.release_hold`.
- **Patch jobs and restarts** (one-product plan, phase C3): the **Jobs** tab
  filters by type, and all recent jobs by status, how they started and when
  they were requested, and says when older ones are left out; a job shows
  when it was sent to the device and how often, when a queued job gives up,
  the job a retry runs again, a cancellation asked for, and its progress.
  **Restart…** offers what EasyPatch's restart did: a countdown of 1 to 60
  minutes, asking users with a deadline of up to 7 days or without one, or
  at once; only if a restart is pending, or always (at most 100 devices,
  each read from EasyPatch to tell servers apart); and how long an offline
  device gets to come back. It is on every patched device, not only those
  reporting a pending restart. Servers still restart only when ticked.
- **Patch policies and tags** (one-product plan, phase C4): the default
  policy (Settings → **Patching**), an organization's and a site's (their new
  **Patch policy** tab), a tag's and a device's own (**Set values for this
  device** on its Policy view) are edited in EasyRMM. Each value is
  inherited, shown with the layer it comes from, or overridden: automatic
  installs and the maintenance window, delays, categories, excluded KBs,
  application updates, a recurring restart, the tray icon and notifications,
  the agent's schedule and Windows Update settings. Tags are added, changed
  and deleted under Settings → Patching → Tags and given to organizations,
  sites and devices with **Change tags**. Policies need `patch.configure` in
  the organization; the default policy, tags and their policies a super
  administrator. With a connected EasyPatch server, whose API token is never
  SuperAdmin, the default policy and tags are read and assigned in EasyRMM
  but changed in EasyPatch's console. Audited as `patch.policy_update`,
  `patch.policy_reset`, `patch.tag_create`, `patch.tag_update`,
  `patch.tag_delete` and `patch.tag_assign`. The **Change in EasyPatch** link
  on a device's Policy view is gone.
- **Organization time zones**: organizations have a time zone (default UTC;
  the browser's for a new one), which patching reports use.
- **Stop patching for a device**: the device's Patches tab can stop
  patching. EasyRMM removes the EasyPatch agent it linked, and installs none
  there again until patching is allowed again. Audited as `patch.stop` and
  `patch.allow`.
- `npm run screenshots` in `web/` makes the README's screenshots from the
  console's production build, its API answered from fictional demo data
  (`web/screenshots/`). It fails when a page asks for something the data does
  not answer.
- EasyRMM can be EasyPatch's sign-in provider (ADR-0036): an OpenID
  provider with one client, EasyPatch, set up by a super administrator under
  Settings → EasyPatch → Sign-in, its secret shown once. Code flow with PKCE;
  single-use codes valid 60 seconds; ES256 ID tokens carrying the person's
  EasyPatch role and organizations from their EasyRMM roles, and
  `email_verified: false`, and an `amr` that always includes `mfa`. A
  second factor in the session is required. Audited as `idp.authorize` and
  `idp.client_*`. EasyPatch's side is in `easypatch/` (its CHANGELOG,
  "Sign in through EasyRMM").
- `make e2e-sign-in`: both consoles in a browser over TLS on two domains,
  signing in once across them; a CI job runs it. The co-hosting guide has a
  step for signing in to EasyPatch through EasyRMM.
- Sessions record how they signed in (`amr`: password, single sign-on,
  authenticator code, security key, recovery code, passkey).
- Links from EasyPatch into EasyRMM, `/go/from-easypatch/endpoints|
  organizations|jobs/:id`, open the device's Patches tab, the organization or
  the job; anything EasyRMM does not link, or the person may not see, opens
  Patching with a note.
- **EasyRMM | EasyPatch** under the logo switches to EasyPatch's console in
  the same tab, on the page of what you were looking at: a device's endpoint
  (on the tab matching its Patches view), an organization (also from a
  site), a job, or EasyPatch's lists. Shown to super administrators and to
  people with a role over a whole organization linked to EasyPatch. A dot
  warns when EasyPatch was not answering.
- `patch.configure`, held by organization administrators and above, never
  from a role over one site: who will be an Admin in EasyPatch rather than
  ReadOnly.
- Patching: **Restart…** for devices whose restart is pending, on a
  device's Patches tab and for chosen devices on the Patching page. One safe
  preset: only if a restart is still pending, after EasyPatch's countdown,
  now or at a time up to 31 days ahead; servers restart only when ticked by
  name. The dialog says which devices will not restart and why. Audited as
  `patch.restart`.
- Patching: **Retry** on a job that failed, was cancelled or expired, or
  left updates uninstalled. The new job opens in its place. Audited as
  `patch.retry`.
- Links from EasyRMM to the EasyPatch page that edits what EasyRMM only
  shows: a device's endpoint page (on the matching tab), its policy, its
  updates (to exclude them), an update, a job. They open in the same tab
  through `/go/to-easypatch`, which finds the endpoint from EasyRMM's own
  links and never says more than the person may see.
- EasyPatch lives in this repository, under `easypatch/`, with its whole
  history, its own licence (`LICENSING.md`), build, `easypatch-v*` tags and
  release workflow. One CI run checks both and runs only what a change
  touches (`docs/development/monorepo.md`).
- Contract tests: `make test-contract` runs EasyRMM's EasyPatch connector
  against a real EasyPatch built from the same commit, and checks the fake
  EasyPatch the fast tests use against it.
- EasyPatch on the same server (ADR-0035): with `EASYRMM_EASYPATCH_HOSTNAME`
  set, EasyRMM's edge keeps ports 80 and 443 and passes EasyPatch's name
  through, still encrypted, to EasyPatch's own Caddy on loopback, with a
  PROXY protocol header so EasyPatch still sees each client's address.
  EasyPatch keeps its own certificates (HTTP-01 and TLS-ALPN-01 both work
  through EasyRMM), headers and URL; EasyRMM's connector reaches it over
  loopback. `deploy/easypatch/` has the Compose override and Caddyfile for
  EasyPatch 1.9.0; the guide is `docs/deployment/easypatch-cohost.md`.
  **Open EasyPatch** on the Patching page and in Settings → EasyPatch opens
  its own console.
- Single sign-on with OpenID Connect (ADR-0034): providers (Entra ID,
  Google, Okta, Keycloak, Authentik…) set up under **Settings → Single
  sign-on**; "Sign in with …" on the sign-in page; the code flow with PKCE,
  state and nonce in a sealed cookie; accounts linked at the first sign-in
  by a verified email in an allowed domain, then by the provider's subject;
  EasyRMM's second factor still asked for unless the provider is declared to
  enforce MFA; linked accounts listed and unlinked under **Account**.
  Tested against a real provider (Dex) in CI.
- An offer of a passkey after sign-in, for people without one: add it
  there (password again, named after the device), "Not now" (asked again
  in 30 days) or "Don't ask again". Only where passkeys work: a DNS name,
  a browser with WebAuthn, the public address.
- Phase 1 research report and Phase 2 architecture with ADRs 0001–0012.
- Server security core: AES-256-GCM secret sealing with key rotation,
  Argon2id password hashing with parameter upgrades, NIST-style password
  policy, RBAC with five built-in roles at platform/organization/site scope
  and escalation prevention.
- PostgreSQL schema with forced row-level security for tenant isolation,
  split owner/runtime roles, and an append-only hash-chained audit log
  written through a `SECURITY DEFINER` function.
- Authentication service: sessions with idle/absolute expiry and token
  rotation, mandatory TOTP MFA with replay protection, recovery codes,
  progressive account lockout, per-address rate limiting, password change
  and reset.
- CI: formatting, vet, golangci-lint, unit and integration tests with
  coverage gates, govulncheck, gitleaks, CodeQL, Trivy, dependency review and
  licence checks.
- HTTP API, first-run setup, organizations/sites/device groups, users and
  roles, audit API, TLS edge, SMTP mailer and the Docker Compose deployment
  with host networking.
- Technician console (`web/`) sharing EasyPatch's design system (ADR-0013):
  first-run setup, sign-in with mandatory authenticator enrollment, recovery
  codes, password reset and invitations, dashboard, organizations, sites and
  device groups, users and roles, audit log with chain verification, account
  page with sessions; dark and light themes; keyboard row travel (j/k).
- Frontend CI: typecheck, Vitest unit tests with coverage floors, production
  build, Impeccable design detector, and Playwright end-to-end tests against
  a real server and PostgreSQL. actionlint for workflow files. Dependabot for
  npm and Docker.

- Remote access through MeshCentral 1.3.1 (ADR-0004, ADR-0005, ADR-0014):
  a hardened `meshcentral` container on loopback with its configuration
  written by the server; a control-channel client; device groups and
  accounts kept in step with sites, users and roles; a gateway on the
  MeshCentral hostname that admits agents, and browsers only with a
  session launched from the console; one-time, audited session launches;
  open sessions closed when the EasyRMM session ends.
- Devices discovered from MeshCentral: API (`/api/v1/devices`), devices list
  and device page with recent remote sessions, and full-window remote
  desktop, terminal and files sessions. **Settings → Remote access** shows
  the connection to MeshCentral.
- Start-up refuses a MeshCentral hostname that does not share a parent
  domain with the console's, since browsers would not admit the embedded
  sessions.
- Integration tests against the real MeshCentral container, including a
  MeshAgent in a locked-down container connecting through the gateway and a
  live terminal session over the relay.

- EasyRMM agent for Linux (`agent/`, ADR-0015): enrollment with a
  deployment token, an Ed25519 device key and signed requests with replay
  protection, a heartbeat every minute, MeshAgent installed from the
  server's own MeshCentral and linked to the device, `status` and
  `uninstall` commands.
- Deployment tokens per site (optional device group, expiry, device limit,
  revocation) and the **Devices → Add devices** page: one-time install
  command, agent downloads with SHA-256, token list.
- Agent API under `/api/agent/v1/` with a checksum-verifying install script
  and the Linux agent builds (`make build-agents`; included in the Docker
  image, served from `EASYRMM_AGENT_DIR`).
- Devices no longer depend on remote access: they are listed with their
  agent's online state, version and enrollment even when MeshCentral is
  turned off. The session reports which optional features the server has.
- Guide: [Installing the EasyRMM agent](docs/deployment/agents.md).
- Reaching the server by IP address (ADR-0016). Besides its DNS name, the
  server answers on its IP addresses (`EASYRMM_IP_ACCESS`, on by default;
  `EASYRMM_IP_ADDRESSES`, detected by default): the console on
  `https://<address>` and remote sessions on `https://<address>:4443`.
  `EASYRMM_PUBLIC_URL` may be an IP address for a deployment without DNS
  (`setup.sh --hostname 203.0.113.10`).
- `internal` TLS mode: the server's own certificate authority, stored
  encrypted in the database, issues the certificate for IP addresses and
  renews it with the same key. The console shows its fingerprint and offers
  it for download. Install commands for an IP address pin the server's key
  (`curl --pinnedpubkey`), and the agent trusts the authority afterwards.
- Requests are routed by host and port, so the console and MeshCentral can
  share an address. The remote-access gateway keeps the console's cookies
  away from MeshCentral and stops MeshCentral from setting cookies under
  EasyRMM's names.
- A remote session on an address with the server's own certificate has a
  **Not loading?** help in its header: a browser cannot accept a certificate
  inside the session frame, so it explains how to accept it for the session's
  address or install the certificate authority.
- Remote desktop, terminal and files open **In this tab** or **In a new
  window**. Each device gets one session window, which a second request
  brings forward; in its own window a session ends by closing it.
- Device tree: a **Tree** button on the devices pages docks a panel at the
  right listing every organization, site and device with online counts. It
  filters by name or hostname, moves with the keyboard, narrows the list to
  an organization or site, and opens a device. It stays open across pages
  on wide screens and opens over the page on narrow ones.
- Scripts and jobs (ADR-0017). A script library at three levels (shared,
  organization, site) for Bash, sh and Python 3, with permissions per level
  and audited changes. Jobs run a script on up to 500 Linux devices with
  arguments, a timeout and a wait for offline devices; the agent picks them
  up over a signed long poll, verifies each job against the server's
  Ed25519 job key pinned at enrollment, runs it as its own process group in
  a temporary directory with a minimal environment, and reports the exit
  code and the head and tail of its output. Jobs and runs can be stopped;
  undelivered runs expire, silent ones are marked as having no result, and
  finished jobs are removed after `EASYRMM_JOB_RETENTION` (90 days). Console
  pages: **Scripts** (library, editor), **Jobs** (progress, devices, output),
  **Run script** from a script, a job (**Run again**) or a device, and the
  device's recent runs on its page. Guide:
  [Scripts and jobs](docs/operations/scripts-and-jobs.md).
- Inventory and telemetry (ADR-0018). The Linux agent reports the
  computer's hardware, operating system, network and installed packages
  (dpkg, RPM, apk, pacman), sending them only when they change, and its
  processor, memory, swap, load and filesystem use with every heartbeat.
  The device page gains **Overview** (health with usage meters and a
  performance chart over an hour, a day or a week), **Hardware** and
  **Software** tabs; the **Software** page searches every device's packages
  and lists the devices with each version. Measurements are kept for
  `EASYRMM_METRICS_RETENTION` (7 days). `easyrmm-agent status` shows when
  the inventory was last sent. Guide:
  [Inventory and health](docs/operations/inventory.md).
- Monitoring and alerts (ADR-0019). Alert policies at the shared,
  organization or site level watch for devices that stop checking in and
  for processor, memory or disk use held above a percentage; new
  installations start with four shared policies. The server checks them
  every minute, opens alerts, follows their latest value and resolves them
  when the condition clears. The **Alerts** page lists active and resolved
  alerts and the policies; people with `alert.manage` acknowledge or
  resolve them there, on the device page or from the dashboard's **Needs
  attention** card; the menu shows the active count. Resolved alerts are
  kept for `EASYRMM_ALERT_RETENTION` (90 days). Guide:
  [Alerts](docs/operations/alerts.md).
- The Windows agent (ADR-0020). `easyrmm-agent.exe` for x64 and ARM64
  runs as the **EasyRMM Agent** service with MeshAgent as **EasyRMM
  MeshAgent**. **Devices → Add devices** now shows a PowerShell command
  first: it downloads `install.ps1` from the server, which checks the
  agent's SHA-256, enrolls the computer and starts the service. By IP
  address the command trusts only the server's own key. Windows devices
  report their hardware, Windows edition and build, network, installed
  programs (with publisher) and health; the device page shows the page
  file and no load average for them. Scripts gain **PowerShell** and
  **cmd**, the default for new scripts; each shell runs only on its
  platform. `make build-agents` and the Docker image build the Windows
  agents, and CI tests the agent on Windows. Guide:
  [Installing the EasyRMM agent](docs/deployment/agents.md).
- Navigation by section (ADR-0021). On the organizations, devices, alerts,
  scripts, jobs and settings pages the sidebar shows that section's own
  tree (organizations › sites › devices, with online, alert or script
  counts) and a **Back** button to the main menu; a row narrows the page's
  list and keeps its other filters. Alerts and jobs can be narrowed to a
  site or a device, scripts to a site. The device tree dock is gone.
- **Quick connect**: devices in the devices tree open a small panel to
  start a desktop, terminal or files session, in a window of its own or
  the current tab (hover, focus, the context menu or Shift+F10).
- The dashboard's **Recent connections** card lists the last ten devices
  you started a remote session on, with quick connect; the setup checklist
  and organizations card are gone.
- A console tab running an older build reloads on its next navigation
  after the server is upgraded (`X-EasyRMM-Console`).
- The sidebar widens to fit the longest organization, site or device name in
  a section's tree, up to 24rem (and a third of the window); longer names end
  in an ellipsis and show in full on hover (ADR-0021).
- The server's certificate authority also downloads as `easyrmm-ca.crt`
  (DER), which Windows installs from the file's context menu (**Install
  Certificate**); the Add devices page explains where to put it, with a
  PowerShell alternative. The PEM file stays for Linux, Firefox and the
  agent's `--ca-file`.
- Audit forwarding (ADR-0023). Super administrators can send every audit
  record to a syslog server or SIEM from **Settings → Audit forwarding**:
  RFC 5424 messages whose text is the record in JSON with its hash-chain
  links, over TLS (with an optional client certificate), TCP or UDP. Records
  go in order, resume after an outage, and are kept past retention until
  the collector has them; turning forwarding off is the last record sent.
  A test message checks the settings before saving. Guide:
  [Forwarding the audit log](docs/operations/audit-forwarding.md).
- Agents that wait for approval (ADR-0024). An approval token, created on
  **Devices → Add devices** with **Wait for approval**, gives one install
  command for every computer of every customer. Each computer that runs it
  waits under **Devices → Waiting for approval** with a device code, its
  system and address, and any device that already has its name; approve one
  or many into a site (and device group), where each takes its computer's
  name and enrolls within seconds, or reject them. The menu and the devices
  tree count the waiting devices; `easyrmm-agent status` shows the code.
  Deciding needs `enrollment.manage` on the whole server.
- Faster remote desktop (ADR-0025). Sessions connect as soon as they open;
  the agent looks for screen changes every 20 ms instead of 50 ms; it
  scales the desktop to the size the session is shown at, and again when
  the window is resized, so it sends no more pixels than the browser shows;
  pictures decode off the page's main thread; MeshCentral's pages are
  served compressed (4.6 MB down to 1.1 MB). On a slow connection, socket
  queues between the agent, the gateway and MeshCentral are kept to tens of
  kilobytes, and the agent is asked for pictures less often while the
  viewer is behind, so the screen shows what is happening now rather than
  what happened seconds ago: on an emulated 2 Mbit/s link under a
  full-screen load, a key press shows in 3.5 s (median) where before it did
  not show within 30 s.
- RDP sessions (ADR-0026). Windows devices offer **RDP** beside remote
  desktop, terminal and files, for roles with the remote desktop
  permission: MeshCentral's web RDP client, tunnelled to the device's own
  RDP port by its agent, with its own grant and audit record. Credentials
  are typed for each session and never stored. The session takes the size
  of the window, and connects again at the new size when the window is
  resized.
- Coordinated agent updates (ADR-0027). Agents follow the server's build:
  the server hands it out a few devices at a time (20 by default), and
  **Settings → Agent updates** sets whether that happens automatically,
  only when asked, or not at all, shows how many agents are up to date,
  and updates every outdated agent at once; a device's page shows its
  agent's update status and updates it alone. The agent waits for running
  scripts, checks the download against a signed instruction, test-runs it,
  restarts into it in place, and goes back to its previous build when the
  new one crashes or cannot reach the server for 10 minutes. Failed
  attempts are retried after 15 minutes and an hour, then marked failed;
  every outcome is audited. Agents installed before this release report no
  build hash and need the install command once more.
- Software deployment (ADR-0028). Install, update and uninstall software
  through winget or Chocolatey on Windows and apt-get, dnf, yum or zypper
  on Linux, on one device from its **Software** tab (with **Update** and
  **Uninstall** on each Debian, Ubuntu or RPM package) or on many from
  **Jobs → Install software**. Each request is a job of one of EasyRMM's
  own scripts with the package as an argument, needs `software.manage`, is
  audited per device, and the agent reports its software again as soon as
  the job ends. Jobs can be filtered by kind.
- Reports (ADR-0029). **Reports** in the main menu: device inventory,
  installed software, device health and alert history, filtered by
  organization, site, platform, name and more, read in the console or
  downloaded as CSV (UTF-8, times in UTC, cells that a spreadsheet would
  run as formulas defused). Each download is audited.
- EasyPatch connector (ADR-0030). **Settings → EasyPatch** connects EasyRMM
  to an EasyPatch server with one of its API tokens and links EasyRMM
  organizations to EasyPatch organizations. The agent reports the local
  EasyPatch agent with its inventory, and the server links the device to
  its EasyPatch endpoint once EasyPatch confirms the server, organization,
  key fingerprint, host name and serial, saying why when it does not.
  **Patching** in the main menu lists devices with their update compliance,
  scans and installs on many devices at once, and follows EasyPatch's jobs;
  each device has a **Patches** tab with its updates, history, jobs and
  effective policy. Installs at a later time are offered when the EasyPatch
  server supports them.
- Installing the EasyPatch agent from EasyRMM (ADR-0031). Devices with no
  EasyPatch agent can be given one from **Patching** or the device's
  **Patches** tab, or automatically for a whole organization (Settings →
  EasyPatch → **Install automatically**). The EasyRMM agent downloads the
  package from the EasyPatch server, checks its size and SHA-256, installs
  it (msiexec, apt-get or dnf) and enrolls it with a single-use token
  EasyRMM creates for that install. Devices that already have an EasyPatch
  agent are left alone. The console shows each install's progress and, when
  it fails, why.
- Release pipeline: pushing a version tag (`easyrmm-v1.2.3`; EasyPatch's,
  in the same repository, are `easypatch-v…`) re-runs every check, then
  publishes the scanned multi-arch server image with an SBOM and provenance,
  and a GitHub release with the deployment bundle (pinned to that image), the
  agents, checksums and attestations, and the changelog's notes. The release
  files are reproducible (`scripts/release/bundle.sh`).
- Security keys and passkeys (ADR-0032). At the first sign-in, people choose
  a security key or passkey or an authenticator app; either can be added
  later under **Account**, with the password entered again. A key answers the
  second-factor step after the password, and **Sign in with a passkey** signs
  in with a passkey alone when it verifies the person (PIN or biometric).
  Keys are named, at most ten per person, and removable; the last second
  factor stays while MFA is required, and an administrator's second-factor
  reset removes keys too. They need EasyRMM to have a DNS name: browsers
  refuse them on an IP address, and the console says so.
- The audit log names software actions, agent updates, report downloads and
  patching, and filters by agent updates, reports and patching.
- The console's libraries are served as a chunk of their own, which
  browsers keep across EasyRMM upgrades.
- When the server cannot open its stored certificate authority or job key,
  the start-up error now asks whether `EASYRMM_SECRET_KEY` was changed
  without listing the old key in `EASYRMM_SECRET_KEYS_PREVIOUS`.
- An upgrade guide (`docs/operations/upgrading.md`): back up, decide how
  agents follow, move to the release's files and image, check, and go back
  by restoring the backup, since migrations only run forward.
- Drills (`scripts/drill/`, `docs/development/drills.md`) that run EasyRMM
  as an operator does, on a disposable Compose deployment of the checkout:
  - `backup-restore.sh` backs up a server that has a real agent with the
    guide's commands, deletes the host and restores onto a new checkout. It
    then checks that users, the audit chain and the same agent carry on.
  - `soak.sh` runs a fleet of simulated agents (`tools/agentsim`) against
    the server while timing the console and jobs on 500 devices.
- Where EasyPatch is set up, the script library warns about scripts that
  install updates themselves and so skip EasyPatch's policies and
  maintenance windows. This covers Windows Update (PSWindowsUpdate,
  `usoclient`, `wusa`, DISM, Windows Update policy) and upgrading every
  package (`apt upgrade`, `dnf upgrade`, `zypper patch`, `pacman -Syu`…).
  It also covers turning on automatic updates. The warning names the lines,
  while editing, on the script's page and before a run.

### Changed
- **Licence: all of EasyRMM, EasyPatch included, is under FSL-1.1-ALv2**,
  licensor DHI Technical Services LLC (ADR-0037), instead of AGPL-3.0-or-later
  for EasyRMM's code. One `LICENSE.md` at the root; contributions grant DHI
  Technical Services LLC a licence (`CONTRIBUTING.md`); CI now checks the
  licences of the consoles' npm packages and EasyPatch's NuGet packages too,
  and Dependabot no longer proposes PDFsharp versions that are AGPL. Copies obtained under the AGPL between
  2026-11-15 and 2026-11-18 keep it (`LICENSING.md`).
- The README is the front page of the one project: what EasyRMM and EasyPatch
  each do, how they fit together, the architecture with EasyPatch, and
  screenshots of the console in dark and light.
- The documentation presents EasyRMM and EasyPatch as one project in one
  repository: EasyPatch, under `easypatch/`, is EasyRMM's patch management
  component. Issues and security reports for both go to this repository.
  Neither licence changes.

### Removed
- The mirror of `easypatch/` to EasyPatch's former repository
  (`easypatch-mirror.yml`, `scripts/easypatch/mirror.sh`). That repository
  now says EasyPatch has moved here, and keeps its releases up to 1.10.0.
- The fleet-wide **Software** page. Installed software is shown on each
  device's page; `GET /api/v1/software` remains.

### Security
- The EasyPatch connection and audit forwarding do not connect to
  link-local or cloud instance metadata addresses, even through a name that
  resolves to one. A Super Administrator's setting could otherwise make the
  server fetch its cloud instance's credentials (Phase 9 security review).
  Loopback and private addresses stay allowed.
- The server's certificate authority (`internal` TLS) has no name
  constraints, and the deployment guides now say to install it only on the
  computers technicians administer EasyRMM from. ADR-0016 explains why it
  is not constrained: agents trust it, and a constraint would cut them off
  when the server's addresses change.
- Agent API limits from the Phase 9 security review:
  - A signed request's header is checked before its body is read. Before,
    up to 4 MiB was read first, with no time limit, from anyone.
  - A body must arrive within two minutes.
  - Each device may send one signed request a second, after a burst of
    120. Inventory uploads (each replacing up to 20,000 rows) are limited
    to one every ten minutes, after six. At most four job polls may be
    open at once. Requests over these get 429 `rate_limited`.
  - Limits are spent only by verified requests.
  - Over HTTP/1, a request refused before its body is read is answered at
    once and the connection closed. net/http otherwise waits, with no time
    limit, for up to 256 KiB of the rest of the body first.
- Tenancy findings from the Phase 9 security review:
  - A report export's audit entry is written under each organization its
    rows came from (and its site, when they share one). Before, it was
    filed under the organization and site named in the request, so a
    technician could write an entry, with free text from the search box,
    into another organization's audit log, or keep their own export out
    of their organization's.
  - Renaming an organization needs a Super Administrator. Names are unique
    on the server, so an Organization Administrator could rename theirs to
    learn whether another customer's name exists. They still edit its
    notes; the console shows the name as locked.
  - Inviting an email address that has an account elsewhere still answers
    that it exists; `docs/security/rbac.md` explains why, and how to keep
    `user.manage` with your own staff where that matters.
- Remote-access gateway hardening from the Phase 9 security review
  (ADR-0033), checked against MeshCentral 1.3.1 and a real MeshAgent:
  - Tunnel requests on MeshCentral's control channel must be for a device
    and session type the EasyRMM session holds a grant on, and name this
    server's relay; an agent joins only tunnels a session was granted, for
    that device and session type, and a relay cannot switch session type
    after it opens. Before, a grant for one device let its holder have
    another device's agent join the relay, outside the grant and its audit
    entry.
  - Device messages outside EasyRMM's session types (process and service
    control, opening web pages, message boxes, system details) are dropped;
    clipboard and session selection need a desktop grant. MeshCentral and
    MeshAgent allowed them for any remote permission at the site.
  - Requests without browser headers are held to what MeshCentral's agent
    port serves. A plain GET of `devicefile.ashx` with a user's MeshCentral
    cookie downloaded a file from a device with no EasyRMM session; browser
    downloads now need a files grant on the device, and uploads to devices
    (`uploadfilebatch.ashx`) are refused.
  - MeshCentral's query parser reads `tcpport[]=22` as `tcpport`; routing
    and credential checks now do too, closing a way around ADR-0022.
- Agent hardening from the Phase 9 security review:
  - Windows: any user may create folders under ProgramData, so one could
    make `C:\ProgramData\EasyRMM\Agent` before the agent was installed,
    stay its owner whatever access list the agent set, and later replace
    the agent's settings and key to run code as SYSTEM. Folders there that
    are not owned by the system, Administrators or TrustedInstaller, or are
    links, are now moved aside and made anew, and new folders get their
    access list as they are created.
  - Chocolatey and winget actions run `choco.exe` or a `winget.exe` found
    on the system's PATH only if no one but administrators can change it
    or its folders; a standard user could create `C:\ProgramData\chocolatey`
    on a machine without Chocolatey and have the agent run their program.
  - A cmd script's arguments may not contain `%`: cmd expands variables
    inside quotes, and `%CMDCMDLINE:~-1%` ends the quotes, so an argument
    could run a command of its own. Refused when the job is created and by
    the agent.
  - The Linux install command passes the deployment token in the
    environment (`export EASYRMM_TOKEN=…; … | sudo --preserve-env=EASYRMM_TOKEN sh`)
    instead of `--token`, which put it on `sh`'s command line, readable by
    every user of the computer and kept in sudo's log.
- Sign-in hardening from the Phase 9 security review (migration 00016):
  - An authenticator app whose set-up was started but never confirmed no
    longer works as a second factor. Before, a session could start set-up
    without the password (for a user who signs in with security keys) and
    keep the secret as a hidden way in that outlived the session; starting
    set-up from a signed-in session now asks for the password.
  - Wrong authenticator or recovery codes count across sign-ins: ten in a
    row lock the account like wrong passwords do. Before, someone with the
    password could try five codes per sign-in indefinitely.
  - Every change that asks for the password again (password, recovery
    codes, second factors) is rate-limited and audited, and five wrong
    passwords end the session that tried them.
  - Changing the password gives the current session a new token.
  - Forgot-password answers before looking the address up and sends the
    e-mail afterwards, so its timing reveals nothing; each account gets at
    most a few reset e-mails an hour; an invited user who has not set a
    password is sent a new invitation instead of a 30-minute reset link.
  - Per-address limits (sign-in, passkeys, reset, setup, enrollment) count
    an IPv6 client's /64 as one address.
- The remote-access gateway now refuses TCP and UDP tunnels through
  agents (ADR-0022). MeshCentral lets anyone with remote-control rights on
  a device ask its agent to connect to any port on the device or its
  network and relay it; with an EasyRMM grant for a terminal, that reached
  every server on the customer's network. Relay connections must be one of
  EasyRMM's session types for a device the caller holds a grant for;
  control channel messages asking for a tunnel close the channel; the
  agent path no longer accepts a MeshCentral user's credentials; and
  `localrelay.ashx` is refused.
- A relay connection now needs a grant of its own session type: a session
  opened as a terminal can no longer open the device's desktop or files, so
  the audit log's record of the session's kind is what was used.
- MeshCentral's RDP relay is open only to a session holding an RDP grant
  for the device it names, by node ID; the stand-alone RDP page, which
  connects by cookie, stays blocked.

### Fixed
- `EASYRMM_DATABASE_MAX_CONNS` past 32 bits wrapped around before it was
  checked, so a value such as `4294967298` started the server with 2
  connections instead of refusing it. It is now checked first.
- A device's Patches tab ran its EasyPatch organization and site into the
  **Open in EasyPatch** link, and said "1 fix vulnerabilities exploited in
  the wild" for a single update.
- Settings → EasyPatch showed EasyPatch as failing after it refused a
  single request (a duplicate scan, an endpoint deleted in EasyPatch). Only
  no answer, a server error or a refused token count now.
- **Open EasyPatch** on the Patching page and in Settings opened a new tab;
  it now opens in the same tab, like the product switch, on EasyPatch's
  endpoint or job list.
- Patching dialogs hid the server's reason when it refused a field the
  dialog has no place for (an install time, for example), leaving the button
  doing nothing visible. They now show it. **Settings → Agent updates** hid
  a refused mode the same way.
- Remote sessions: a write that the gateway's pacing held while the browser
  fell behind could still reach the connection after it began closing. It now
  fails as a write on a closed connection does. Found by a flaky test in CI.
- Continuous integration: secret scanning covers the whole history on every
  run (gitleaks-action scanned only a pull request's range, which it could not
  work out once EasyPatch's history came in, and never past 250 commits), and
  fails when it cannot read the history instead of reporting no leaks.
  Trivy's findings that do not apply are excepted per file, with the reason,
  in `.trivyignore.yaml`.
- A new Docker Compose deployment did not start, found by the backup and
  restore drill. `setup.sh` created `postgres/` owned by root with mode 700,
  which the PostgreSQL 18 image mounts above its data directory, so
  PostgreSQL (uid 70) could not reach its data; it is now owned by 70:70.
  And the server refused the empty `EASYRMM_MESH_PUBLIC_URL` and
  `EASYRMM_MESH_CERT_URL` that `.env.example` leaves for their defaults:
  Compose passes them as empty strings, which the server took as values.
  Blank now means the default for these and `EASYRMM_ACME_DIRECTORY`. A
  test now loads the environment Compose builds from `.env.example`.
- The backup guide's `pg_dump` and `pg_restore` commands connected over TCP
  with no password and failed. They now run as the container's `postgres`
  user over its local socket. The guide also said the server's data
  directory would hold signing keys; those are in the database, sealed with
  `EASYRMM_SECRET_KEY`, and the guide now says what losing that key costs.
- Settings the documentation describes did nothing in a Compose deployment,
  because Compose did not pass them to the server: session timeouts, the
  password reset link's lifetime, the four retention periods and the ACME
  directory. Compose passes them now, and `EASYRMM_LISTEN_HTTPS` too, so a
  host with several addresses can serve on one. The same test fails when
  the server reads a setting Compose neither passes nor fixes on purpose.
- The release's deployment bundle could not start: `docker-compose.yml` sat
  at its root, so the PostgreSQL and MeshCentral start scripts it mounts
  from `../docker/` lay outside the bundle and were missing. The bundle now
  has the repository's layout (`deploy/`, `docker/`, `docs/`) and includes
  those scripts, the agent guide and the upgrade guide. `bundle.sh` refuses
  to build a bundle that lacks anything the Compose file mounts.
- In the audit log, long user names ran into the next column.
- Remote sessions opened MeshCentral's session view without the device, so
  nothing could connect. MeshCentral's device page calls into the
  MeshCommander frame it embeds (`/commander.ashx`), which the gateway
  blocked; that static page and the RDP client scripts (`/mstsc/*.js`) now
  pass, while the AMT, RDP and SSH relays stay blocked. The launch link also
  percent-encoded the device's ID (`@` as `%40`), and MeshCentral's page
  discards any argument containing `%`.
- A request the browser abandoned (a closed tab, a navigation) was logged as
  a server error with status 500. It is now recorded as 499, at info level.
- In `acme` mode MeshCentral could not read the certificate its agents pin:
  it connects without a server name, which ACME refuses. Such connections
  from the server's own host now get the MeshCentral name's certificate.
- The install script no longer leaves its downloads in a temporary
  directory: it ran the agent with `exec`, which skipped its cleanup.
- A device that disconnected from MeshCentral stayed online until the next
  five-minute sync: MeshCentral sends `nodeconnect` events without the
  `etype` the synchronizer filtered on.
- The first-run setup rate limiter was shared by every server instance in
  one process (tests), so one instance's attempts could refuse another's.
- Deleting a site that still has devices returned HTTP 500 instead of 409:
  PostgreSQL reports `ON DELETE RESTRICT` violations with their own error
  code, which is now recognized. Deleting an organization with sites only
  got its 409 because of the order PostgreSQL checked constraints in; it no
  longer depends on that.
- The "cannot delete" messages no longer suggest moving sites or devices,
  which EasyRMM cannot do yet.
- Docker smoke test: two negated checks (`! grep`, `! test`) could never fail
  the step; they now do.
- Expired agent request nonces are removed every minute rather than hourly.
  With 2,000 agents the table held an hour of requests (63 MB), cleared by
  one large delete; it now holds about seven minutes.
- The Windows software scripts read file permissions through .NET rather
  than `Get-Acl`. When `PSModulePath` names PowerShell 7's modules, as it
  does in a process started from PowerShell 7, `Get-Acl` fails to load, so
  the check refused even Windows' own programs and Chocolatey and winget
  never ran.
- The internal certificate authority stores the server certificate and
  serves it again after a restart. A new one on every start made MeshAgent
  see a certificate MeshCentral had not read, and after two restarts within
  two minutes MeshCentral held every agent's connection until it was
  restarted: devices checked in but remote access stayed "not connected".
  The Docker guide shows how to recognise and clear that state.
- A worker test waited a fixed 100 ms for a refused job result; it now
  answers polls until the result is sent again, as it failed on slow
  runners.
- CI: the end-to-end agent test reads the agent's private settings, and
  removes its files, as the agent's user; the Docker smoke test no longer
  globs a folder only root can list; the browser test expects the install
  command that keeps the token off the command line.
