# Architecture decision records

Each ADR records one significant decision: its context, the options
considered, the decision and its consequences. A decision is not rewritten
once accepted (only links and names are kept current); a later ADR refines,
amends or supersedes it, and the status column says which. For how the parts fit together today, start with
the [architecture overview](../overview.md).

## In force

Some of these are refined or partly superseded by later ones; the status
says by which.

| # | Title | Status |
|---|---|---|
| [0001](0001-go-modular-monolith.md) | Go modular monolith for server and agent | Accepted |
| [0002](0002-postgresql-rls-tenant-isolation.md) | PostgreSQL with row-level security and split database roles | Accepted |
| [0003](0003-go-edge-host-networking.md) | Go TLS edge, host networking and the port plan | Accepted; refined by 0016 |
| [0004](0004-meshcentral-dedicated-origin.md) | MeshCentral behind our edge on a dedicated hostname | Accepted; refined by 0014 and 0016 |
| [0005](0005-meshcentral-identity-and-sessions.md) | MeshCentral users, groups, login tokens and session launch | Accepted; refined by 0014 |
| [0006](0006-sessions-and-mfa.md) | Opaque cookie sessions with mandatory MFA | Accepted |
| [0007](0007-hash-chained-audit-log.md) | Append-only, hash-chained audit log | Accepted |
| [0008](0008-unified-endpoint-installer.md) | Unified endpoint installer bundling MeshAgent | Accepted; MeshAgent sourcing superseded by 0015 |
| [0009](0009-agent-protocol.md) | Agent protocol: device keys, WebSocket with HTTPS polling fallback | Accepted; refined by 0017 |
| [0010](0010-easypatch-integration.md) | EasyPatch integration through a service API | Accepted; its separate EasyPatch server replaced by the engine in every deployment (0043, 0046) |
| [0012](0012-frontend-stack-and-impeccable.md) | React/TypeScript frontend designed with Impeccable | Accepted; styling superseded by 0013 |
| [0013](0013-easypatch-design-system.md) | The console shares EasyPatch's design system | Accepted |
| [0014](0014-remote-access-gateway-and-device-discovery.md) | Remote-access gateway rules and device discovery | Accepted |
| [0015](0015-enrollment-and-meshagent-delivery.md) | Deployment tokens, agent enrollment and MeshAgent delivery | Accepted; amended by 0047 |
| [0016](0016-ip-address-access.md) | Reaching the server by IP address: IP access, internal certificate authority, routing by port | Accepted |
| [0017](0017-scripts-and-jobs.md) | Scripts and jobs: a tenant-scoped library, signed jobs over a long poll | Accepted |
| [0018](0018-inventory-and-telemetry.md) | Inventory and telemetry: hash-synced inventory, metrics with every heartbeat | Accepted |
| [0019](0019-monitoring-and-alerts.md) | Monitoring and alerts: tenant-scoped policies evaluated every minute | Accepted |
| [0020](0020-windows-agent.md) | The Windows agent: services, install.ps1 with a key pin, PowerShell and cmd, Windows inventory | Accepted |
| [0021](0021-console-navigation.md) | Console navigation by section: a sidebar tree per section, quick connect, recent connections | Accepted |
| [0022](0022-gateway-relay-restrictions.md) | No TCP or UDP tunnels through the remote-access gateway | Accepted; refines 0014 |
| [0023](0023-audit-forwarding.md) | Forwarding the audit log over syslog (RFC 5424 over TLS, TCP or UDP) | Accepted |
| [0024](0024-enrollment-approval.md) | Installing agents that wait for approval: one command for every computer | Accepted; refines 0015; amended by 0047 |
| [0025](0025-remote-session-latency.md) | Remote session latency: session view tuning, compression, small socket queues | Accepted; refines 0005, 0014 |
| [0026](0026-rdp-sessions.md) | RDP sessions: a session kind of its own, the web RDP relay for RDP grants only, sized to the window | Accepted; refines 0005, 0022 |
| [0027](0027-agent-updates.md) | Coordinated agent updates: builds by hash, a few devices at a time, signed instructions, probation and rollback | Accepted; refines 0008, 0009; refined by 0049 |
| [0028](0028-software-deployment.md) | Software deployment: install, update and remove through winget, Chocolatey and the Linux package manager, as jobs of EasyRMM's own scripts | Accepted; builds on 0017, 0018 |
| [0029](0029-reports.md) | Reports: device inventory, installed software, device health and alert history, in the console and as audited CSV downloads | Accepted; builds on 0018, 0019 |
| [0030](0030-easypatch-connector.md) | EasyPatch connector: one server through an API token, organizations linked by hand, devices linked by what their EasyPatch agent reports, patch views and actions behind EasyRMM roles | Partly superseded by 0046: the API-token connection and links chosen by hand are retired (statements, 0038; one set of organizations, 0040); device links and patch views and actions behind EasyRMM roles stand. Refines 0010 |
| [0031](0031-easypatch-agent-install.md) | The EasyRMM agent installs the EasyPatch agent where there is none: a signed instruction in the heartbeat with EasyPatch's package and a single-use enrollment token, on request or automatically per organization; never a second agent, never a re-enrollment | Accepted; builds on 0027, 0030 |
| [0032](0032-webauthn-passkeys.md) | Security keys and passkeys (WebAuthn) as a second factor beside or instead of the authenticator app, and passkey sign-in with user verification; the relying party is the public URL's host, so IP-only deployments go without | Accepted; refines 0006 |
| [0033](0033-relays-bound-to-grants.md) | Tunnel requests and the agent's end of a relay bound to the session's grants; device messages beyond the session types dropped; the agent path held to what MeshCentral's agent port serves; downloads need a files grant | Accepted; amends 0014, 0022 |
| [0034](0034-oidc-single-sign-on.md) | Single sign-on with OpenID Connect: providers set up by super administrators, code flow with PKCE bound to a sealed cookie, identities linked to invited accounts by provider and subject (first time by a verified email in an allowed domain), EasyRMM's second factor unless the provider is declared to enforce MFA | Accepted; refines 0006, 0032 |
| [0037](0037-one-licence.md) | One licence: FSL-1.1-ALv2 for the whole repository, DHI Technical Services LLC as licensor, contributions licensed to it, permissive dependencies only | Accepted; supersedes 0011 |
| [0038](0038-statements-to-the-patching-engine.md) | EasyRMM calls its patching engine with a statement per request: HS256 with a key from the deployment, naming who acts, the role and organizations that one call may use, and the method and target it is for, valid 30 seconds; the engine builds a stateless principal and still applies its own checks | Accepted; refines 0030 |
| [0039](0039-agents-on-easyrmms-name.md) | EasyPatch agents on EasyRMM's name: in bundled mode the edge forwards exactly `/api/v1/agents/`, `/downloads/agent/` and `/downloads/winget/` to the engine, first, byte for byte, with the address EasyRMM resolved, without statements or cookies, and sandboxes every answer on EasyRMM's origin | Accepted; refines 0035, 0038 |
| [0040](0040-one-set-of-organizations.md) | One set of organizations: in bundled mode a reconciler creates, renames, restores and archives the engine's organizations and sites to match EasyRMM's (adopting an exact-name match, suffixing names that clash ignoring case), moves endpoints within an organization, and has agents of deleted, moved or opted-out devices uninstall themselves, revoking after 7 days; links are no longer chosen in Settings | Accepted; refines 0030, 0031 |
| [0041](0041-agent-packages-in-the-engine-image.md) | Agent packages in the engine's image: the release workflow stages the Windows and Linux packages it signed, after checking each signature against the committed public key, into the server image, root-owned and read-only; EasyRMM's compose no longer mounts a package directory; CI images carry Linux packages signed with a key made for the run, which the release key refuses | Accepted; refines 0031 |
| [0042](0042-agents-trust-easyrmms-authority.md) | EasyPatch agents trust EasyRMM's own authority: with the bundled engine and `EASYRMM_TLS_MODE=internal`, install instructions carry it; the Linux agent takes it with `enroll --server-ca` and trusts it for that server only, as the MSI's `SERVERCACERT` does; older Linux agents are enrolled without it | Accepted; refines 0031 and 0039 |
| [0043](0043-one-release.md) | One release: EasyRMM's release builds the patching engine from the same commit, with EasyPatch's own version line, published once per version; the bundle's compose file pins the engine by digest and a manifest records both images and the agent packages; `make e2e-bundle` brings the deployment up and patches a Linux machine through it | Accepted; refines 0041 |
| [0044](0044-authentik-when-chosen.md) | Authentik, when chosen: `setup.sh --with-authentik` runs Authentik on loopback behind EasyRMM's edge on its own name, with a blueprint for EasyRMM's provider, a required second factor and an invitation-only enrollment; the first super administrator is created without a password and linked at first sign-in; the provider is set by the deployment, reached over loopback, and never maps groups to roles; `easyrmm-server recover` prints a one-time sign-in link | Accepted; adds to 0034 |
| [0045](0045-importing-a-standalone-easypatch.md) | Importing a standalone EasyPatch (1.4 to 1.10): its backup restored aside, checked and migrated by the engine's `prepare-import` (accounts disabled), swapped in for a deployment's engine that patches nothing yet, its keys added and its agents' names answered; EasyRMM adopts its organizations and sites, joining exact names and naming case collisions `(2)` | Accepted; replaces 0035 for joining EasyRMM; refines 0040 |
| [0046](0046-what-one-product-retires.md) | What one product retires (phase R): EasyRMM's links to a separate EasyPatch (switch, sign-in across, co-hosting), the API-token connector, EasyPatch's console, proxy, standalone install and release, and its own accounts; each test of living code moves to statements before the path it used is deleted; EasyPatch's account tables stay for imports | Accepted; extended by 0048 |
| [0047](0047-tokens-shown-again.md) | Deployment and approval tokens can be shown again: the secret kept sealed with the encryption key and bound to the token, shown only while the token is active to those who manage it, every reveal audited, checked against its hash | Accepted; amends 0015 and 0024 |
| [0048](0048-the-engine-keeps-what-is-reached.md) | The engine keeps what is reached: enrolling with a code and approval (routes, install scripts, alert rule, the agent's side) and the engine routes EasyRMM does not call go; older agents still enroll with a token, a code is refused with `deployment_codes_retired`, and a migration drops the two tables | Accepted; amends 0046 |
| [0049](0049-operators-sign-windows-agents.md) | Operators sign the Windows agent with their own certificate: they sign the server's builds with their own tools and upload them; the server checks the Authenticode digest is its own build's and the signature verifies, hands the signed build out and updates agents to it; never holds the key | Accepted; refines 0027 |
| [0050](0050-removing-a-device.md) | Removing a device: the console asks its agents to uninstall themselves with a signed instruction, the EasyRMM agent uninstalls from outside its service and reports with its device key, the device is deleted on that report, its EasyPatch agent through `easypatch_removals` and its MeshCentral node with it; force removal keeps the agent's key and MeshAgent node for 90 days so a computer that comes back still cleans itself up | Accepted |
| [0051](0051-hardening-linux-computers.md) | Hardening Linux computers: a `hardening` job running EasyRMM's own script with checked arguments; check, apply and undo per module; 14 modules, 10 recommended; firewall keeps sshd's and every listening port open and leaves an active firewall alone, forwarding never turned off where used; backups for full undo; `device.harden` for Site Administrators and above | Accepted (revised after two reviews), not implemented yet |
| [0052](0052-the-host-updater.md) | Upgrading with an updater on the host: `easyrmm-updater` (root, systemd) verifies a build's manifest against its Sigstore attestation for this repository's release workflow at the tag, or `main`'s last CI job on the edge channel only, then stops the deployment, copies the data root, runs `setup.sh --upgrade`, starts the new version held and confirms, or restores the copy; a rollback after a confirmed upgrade restores it too, for 24 hours; the server only asks, through a validated file; edge builds published after all of CI, with versions that sort | Accepted (revised after review), not implemented yet |
| [0061](0061-moving-to-a-new-name.md) | Moving EasyRMM to a new name, or from an IP address to one: five steps from the console (agents, remote access, sign-in, browsers, removing the old name); each EasyRMM agent moves on a signed instruction only after the new address signs its own nonce with the job key, and moves its EasyPatch agent; MeshAgents follow MeshCentral's name; a redirect URI per name, confirmed per provider; passkeys keep their relying party ID and work at the new name through Related Origin Requests; move back until the old name is removed, at least 24 hours on | Proposed (2026-11-21), not implemented yet; amends 0031, 0032, 0034 and 0044 |

## Superseded

Kept as the record of what was decided and why it changed.

| # | Title | Status |
|---|---|---|
| [0011](0011-licensing.md) | AGPL-3.0 for EasyRMM | Superseded by 0037 |
| [0035](0035-cohosting-easypatch.md) | EasyPatch on the same server: EasyRMM's edge keeps 80 and 443, passes EasyPatch's name through by SNI, still encrypted, to its Caddy on loopback with a PROXY protocol v2 header naming the client, forwards its HTTP-01 challenges, and its connector reaches it over loopback | Superseded by 0046 |
| [0036](0036-easyrmm-signs-in-to-easypatch.md) | EasyRMM is EasyPatch's OpenID provider: one client set up by a super administrator, code flow with PKCE, single-use hashed codes, ES256 ID tokens carrying `amr` and the `easypatch` access claim with `email_verified: false`, a second factor required, one bounce through the console for the SameSite=Strict cookie | Superseded by 0046 |
