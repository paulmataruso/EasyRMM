# EasyRMM Phase 1: Research Report

## Executive Summary

Research completed across MeshCentral, Tactical RMM, EasyPatch, and commercial RMM products (NinjaOne, Level.io, Action1, Datto, Atera). Key findings inform our architecture:

1. **MeshCentral integration is proven** via login tokens + iframe embedding (Tactical RMM does this)
2. **Tactical RMM's biggest gap** is the non-unified installer — our primary differentiator
3. **EasyPatch is a mature .NET 10 app** with comprehensive REST API — integrate via API, don't rewrite
4. **Single port 443** is achievable for all MeshCentral traffic
5. **Commercial RMMs** emphasize single-pane workflows, fast search, and actionable dashboards

---

## MeshCentral Findings

### Architecture
- Node.js server, C-based agent (MeshAgent), browser web app
- Communication is WebSocket-based (not REST)
- Agent connects outbound to server on TCP 443 via WebSocket/TLS
- Server relays between browser sessions and agents
- Licensed under Apache 2.0

### Integration Methods
- **Login Tokens**: `AllowLoginToken: true` + `AllowFraming: true` in config.json
- Generate tokens server-side with `--logintokenkey`
- Tokens create time-limited sessions for iframe embedding
- **No REST API** — uses WebSocket command protocol and MeshCtrl CLI
- Plugin architecture exists but not suitable for external integration

### Port Requirements
- TCP 443: HTTPS, WebSocket agent connections, browser relay — all on one port
- TCP 80: Optional redirect/ACME
- WebRTC: Off by default, experimental — not needed for V1
- **Single-port deployment is achievable**

### Docker Support
- Official image at `ghcr.io/ylianst/meshcentral`
- Host networking supported and recommended
- Storage: NeDB (file-based) for small deployments, MongoDB for scale
- Persistent dirs: meshcentral-data/, meshcentral-files/, meshcentral-backups/

### Multi-Tenancy
- No first-class organization concept
- Device groups with per-user permissions provide basic isolation
- Our RMM must own the multi-tenant model

### Risks
- Iframe embedding may break across MeshCentral versions (issue #5155)
- Login tokens extractable from iframes (mitigate with short lifetime)
- Single login token key per server (acceptable — our backend is sole generator)
- Tactical RMM v1.6+ is moving away from MeshCentral for terminal/files

---

## Tactical RMM Findings

### Architecture
- Django backend, Vue.js frontend, Go agent, PostgreSQL, Redis, NATS
- Three subdomains required (api.*, rmm.*, mesh.*)
- MeshCentral runs as companion service

### MeshCentral Integration (Critical Reference)
- Login token + iframe with `hide=` parameter to suppress MeshCentral UI
- MeshCentral config: `AllowLoginToken: true`, `AllowFraming: true`
- Stores MeshCentral username, site URL, and login token
- Agent syncs MeshAgent node ID with Tactical database
- VNC relay cookies created per session
- **v1.6+ moved terminal and file browser in-house** — MeshCentral used only for remote desktop
- Forced 2FA on MeshCentral breaks integration

### Key Pain Points
- **Non-unified installer** — MeshAgent and Tactical agent are separate installs
- Three subdomains add deployment complexity
- Unsigned Go agent flagged by antivirus
- Two products to maintain and troubleshoot

### Lessons for EasyRMM
1. Login token + iframe is proven but has friction
2. Build terminal and file browser natively from the start
3. Unified installer is a real differentiator
4. Consolidate to single subdomain
5. Plan for agent code signing

---

## EasyPatch Findings

### Architecture
- **Backend**: C# / ASP.NET Core 10, EF Core 10, .NET 10
- **Database**: PostgreSQL 18 with ~30 tables
- **Frontend**: React 19, TypeScript, Vite 8, Tailwind CSS 4, TanStack Query 5
- **Agent**: .NET 10 self-contained, ECDSA P-256 signed HTTPS polling
- **License**: FSL-1.1-ALv2 (source-available, becomes Apache 2.0 after 2 years)

### API
- Complete REST API at `/api/v1` with OpenAPI docs
- Agent protocol: enroll, check-in, inventory, scan results, job ack/status, credential rotation
- Admin API: full CRUD for all entities
- Download endpoints for agent packages and install scripts

### Capabilities
- Windows Update scans via WUA COM API, Linux via apt/dnf
- CVE/CISA KEV prioritization
- Maintenance windows, rollout delays, restart management
- winget third-party updates
- Compliance tracking, monthly PDF reports
- Per-update exclusions at endpoint/org/site level

### Agent Communication
- Outbound HTTPS only (TCP 443)
- 60s check-in interval (±10% jitter)
- Job delivery via check-in with PostgreSQL `FOR UPDATE SKIP LOCKED`
- On-disk outbox with exponential backoff retry
- No persistent WebSocket — pure polling

### Docker Deployment
- 5 containers: Caddy (TLS), API, Worker, PostgreSQL, Migrate
- 3 Docker networks with security zones
- Ports: 80 and 443 only
- Read-only containers, no-new-privileges, cap_drop ALL

### Integration Implications
- Comprehensive REST API enables clean API-based integration
- Shared PostgreSQL instance possible (same technology)
- Multi-tenant model already in place (organizations, sites, endpoints)
- Agent is .NET self-contained — must be bundled in unified installer
- Authentication uses Argon2id + TOTP MFA with server-side sessions

---

## Commercial RMM Best Practices

### Dashboard & Navigation
- Single-pane daily workflow (NinjaOne pattern) — techs handle everything from one dashboard
- Meaningful KPIs, not vanity stats — every widget must be actionable
- Fast global search is a massive differentiator (command palette style)

### Device Management
- Tabbed device detail (overview, hardware, software, patches, monitoring, remote, terminal, files, jobs, activity)
- Bulk actions from device lists (multi-select → run script, install, reboot)
- Real-time status indicators visible at a glance
- Custom columns and saved filter presets

### Remote Access
- Seamless in-app sessions — no visible branding swap or login redirect
- One-click connect from any device page
- Session indicators on device list

### Patch Management
- Staged rollouts / update rings (Action1 pattern)
- Patch compliance dashboard with % compliant, missing critical, failed installs
- Reboot scheduling flexibility

### Automation
- Policy-based automation ("when condition X, run script Y")
- Script library with community sharing
- Readable job output with real-time streaming

### Alerting
- Alert fatigue is the #1 complaint across all RMMs
- Sane defaults, suppression, deduplication, maintenance windows
- Actionable alerts with one-click remediation

### UX Anti-Patterns to Avoid
- Weak reporting (build basic CSV/PDF export from day one)
- Complex policy setup (visual builder with sensible defaults)
- Shipping a "V1 UI" you plan to replace

---

## Technical Risks and Unknowns

| Risk | Severity | Mitigation |
|------|----------|------------|
| MeshCentral iframe embedding reliability | High | Pin version; test in CI; build native remote desktop path long-term |
| Login token extraction from iframes | Medium | Short token lifetime (5 min); CSP headers; session binding |
| Three agents in unified installer (MeshAgent + RMM + EasyPatch) | Medium | Clean service management; shared installer framework |
| EasyPatch FSL license compatibility | Medium | License allows integration; becomes Apache 2.0 after 2 years |
| MeshCentral version pinning vs. security updates | Medium | Track releases; test integration before upgrading |
| Agent antivirus false positives | Medium | Code signing from day one |
| WebSocket scalability at 10K+ devices | Low | Go handles concurrent connections well; add horizontal scaling later |
| Docker host networking port conflicts | Low | Clear documentation; configurable ports where possible |
