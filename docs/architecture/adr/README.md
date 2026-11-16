# Architecture Decision Records

Each ADR records one significant decision: its context, the options
considered, the decision, and its consequences. ADRs are immutable once
accepted; a later ADR supersedes an earlier one instead of editing it.

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
| [0010](0010-easypatch-integration.md) | EasyPatch integration through a service API | Accepted |
| [0011](0011-licensing.md) | AGPL-3.0 for EasyRMM | Accepted |
| [0012](0012-frontend-stack-and-impeccable.md) | React/TypeScript frontend designed with Impeccable | Accepted; styling superseded by 0013 |
| [0013](0013-easypatch-design-system.md) | The console shares EasyPatch's design system | Accepted |
| [0014](0014-remote-access-gateway-and-device-discovery.md) | Remote-access gateway rules and device discovery | Accepted |
| [0015](0015-enrollment-and-meshagent-delivery.md) | Deployment tokens, agent enrollment and MeshAgent delivery | Accepted |
| [0016](0016-ip-address-access.md) | Reaching the server by IP address: IP access, internal certificate authority, routing by port | Accepted |
| [0017](0017-scripts-and-jobs.md) | Scripts and jobs: a tenant-scoped library, signed jobs over a long poll | Accepted |
| [0018](0018-inventory-and-telemetry.md) | Inventory and telemetry: hash-synced inventory, metrics with every heartbeat | Accepted |
| [0019](0019-monitoring-and-alerts.md) | Monitoring and alerts: tenant-scoped policies evaluated every minute | Accepted |
| [0020](0020-windows-agent.md) | The Windows agent: services, install.ps1 with a key pin, PowerShell and cmd, Windows inventory | Accepted |
| [0021](0021-console-navigation.md) | Console navigation by section: a sidebar tree per section, quick connect, recent connections | Accepted |
| [0022](0022-gateway-relay-restrictions.md) | No TCP or UDP tunnels through the remote-access gateway | Accepted; refines 0014 |
| [0023](0023-audit-forwarding.md) | Forwarding the audit log over syslog (RFC 5424 over TLS, TCP or UDP) | Accepted |
| [0024](0024-enrollment-approval.md) | Installing agents that wait for approval: one command for every computer | Accepted; refines 0015 |
| [0025](0025-remote-session-latency.md) | Remote session latency: session view tuning, compression, small socket queues | Accepted; refines 0005, 0014 |
| [0026](0026-rdp-sessions.md) | RDP sessions: a session kind of its own, the web RDP relay for RDP grants only, sized to the window | Accepted; refines 0005, 0022 |
| [0027](0027-agent-updates.md) | Coordinated agent updates: builds by hash, a few devices at a time, signed instructions, probation and rollback | Accepted; refines 0008, 0009 |
| [0028](0028-software-deployment.md) | Software deployment: install, update and remove through winget, Chocolatey and the Linux package manager, as jobs of EasyRMM's own scripts | Accepted; builds on 0017, 0018 |
| [0029](0029-reports.md) | Reports: device inventory, installed software, device health and alert history, in the console and as audited CSV downloads | Accepted; builds on 0018, 0019 |
