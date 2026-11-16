# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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
- The audit log names software actions, agent updates, report downloads and
  patching, and filters by agent updates, reports and patching.
- The console's libraries are served as a chunk of their own, which
  browsers keep across EasyRMM upgrades.
- When the server cannot open its stored certificate authority or job key,
  the start-up error now asks whether `EASYRMM_SECRET_KEY` was changed
  without listing the old key in `EASYRMM_SECRET_KEYS_PREVIOUS`.

### Removed
- The fleet-wide **Software** page. Installed software is shown on each
  device's page; `GET /api/v1/software` remains.

### Security
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
