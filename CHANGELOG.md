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

### Fixed
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
