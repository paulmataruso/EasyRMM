# Architecture Decision Records

Each ADR records one significant decision: its context, the options
considered, the decision, and its consequences. ADRs are immutable once
accepted; a later ADR supersedes an earlier one instead of editing it.

| # | Title | Status |
|---|---|---|
| [0001](0001-go-modular-monolith.md) | Go modular monolith for server and agent | Accepted |
| [0002](0002-postgresql-rls-tenant-isolation.md) | PostgreSQL with row-level security and split database roles | Accepted |
| [0003](0003-go-edge-host-networking.md) | Go TLS edge, host networking and the port plan | Accepted |
| [0004](0004-meshcentral-dedicated-origin.md) | MeshCentral behind our edge on a dedicated hostname | Accepted |
| [0005](0005-meshcentral-identity-and-sessions.md) | MeshCentral users, groups, login tokens and session launch | Accepted |
| [0006](0006-sessions-and-mfa.md) | Opaque cookie sessions with mandatory MFA | Accepted |
| [0007](0007-hash-chained-audit-log.md) | Append-only, hash-chained audit log | Accepted |
| [0008](0008-unified-endpoint-installer.md) | Unified endpoint installer bundling MeshAgent | Accepted |
| [0009](0009-agent-protocol.md) | Agent protocol: device keys, WebSocket with HTTPS polling fallback | Accepted |
| [0010](0010-easypatch-integration.md) | EasyPatch integration through a service API | Accepted |
| [0011](0011-licensing.md) | AGPL-3.0 for EasyRMM | Accepted |
| [0012](0012-frontend-stack-and-impeccable.md) | React/TypeScript frontend designed with Impeccable | Accepted |
