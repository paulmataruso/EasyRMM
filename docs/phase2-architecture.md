# EasyRMM Phase 2: Architecture

## Technology Stack Decisions

### Backend: Go
**Why Go over alternatives:**
- Compiles to single static binary — minimal Docker image, trivial deployment
- Excellent concurrent WebSocket handling (goroutines for thousands of agent connections)
- Cross-compilation for agent binaries (windows/amd64, linux/amd64, linux/arm64)
- Proven in RMM space (Tactical RMM's agent is Go)
- Fast startup, low memory footprint
- Strong standard library (HTTP server, crypto, JSON, SQL)
- No runtime dependency on endpoints

**Rejected alternatives:**
- C#/.NET: EasyPatch's stack, but adds .NET runtime to Docker and agent
- Python/Django: Tactical RMM's choice, but slower and heavier
- Node.js: MeshCentral's stack, but less ideal for agent binary compilation
- Rust: Excellent performance but slower development velocity for web backend

**Key libraries:**
- HTTP router: chi (lightweight, stdlib-compatible)
- Database: sqlc (type-safe SQL, no ORM magic) + golang-migrate
- WebSocket: gorilla/websocket or nhooyr.io/websocket
- Auth: golang-jwt, pquerna/otp (TOTP)
- Password hashing: argon2id via x/crypto
- Logging: slog (stdlib structured logging)
- Config: environment variables + YAML config file

### Frontend: React 19 + TypeScript + Vite
**Why:**
- Aligns with EasyPatch's frontend stack (enables shared UI component patterns)
- Rich ecosystem for complex dashboards
- TanStack Query for server state management
- TanStack Table for device lists with sorting/filtering/custom columns
- WebSocket integration for real-time updates
- Tailwind CSS 4 for styling (matches EasyPatch)

**Key libraries:**
- React 19 + TypeScript
- Vite 6 (build tool)
- Tailwind CSS 4 (utility-first styling)
- TanStack Query 5 (data fetching/caching)
- TanStack Table (device lists)
- TanStack Router (type-safe routing)
- Lucide React (icons — matches EasyPatch)
- Recharts or visx (charts)
- xterm.js (terminal emulator)

### Database: PostgreSQL 17
**Why:**
- Aligns with EasyPatch (shared instance possible)
- Robust indexing, JSONB for flexible metadata
- Full-text search for device/script/job search
- Row-level security capabilities for tenant isolation
- Excellent migration tooling
- Proven at scale for thousands of devices

### Agent Communication: WebSocket + HTTPS Fallback
**Why WebSocket over NATS:**
- One fewer infrastructure component (no message broker)
- Go handles thousands of concurrent WebSocket connections natively
- Direct bidirectional communication between agent and server
- HTTPS polling fallback for restrictive networks
- Simpler deployment (fewer ports, fewer services)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Host (host networking)            │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │  EasyRMM     │  │  EasyRMM     │  │  MeshCentral          │ │
│  │  Backend     │  │  Frontend    │  │  Server                │ │
│  │  (Go)        │  │  (React SPA) │  │  (Node.js)            │ │
│  │              │  │              │  │                         │ │
│  │  :8443 HTTPS │  │  served by   │  │  :443 HTTPS/WSS       │ │
│  │  - REST API  │  │  Go backend  │  │  - Agent connections   │ │
│  │  - WebSocket │  │  (static)    │  │  - Remote desktop      │ │
│  │  - Agent WS  │  │              │  │  - Terminal relay      │ │
│  │  - Auth      │  │              │  │  - File transfer       │ │
│  └──────┬───────┘  └──────────────┘  └───────────┬───────────┘ │
│         │                                         │             │
│  ┌──────┴─────────────────────────────────────────┴───────────┐ │
│  │                    PostgreSQL 17                            │ │
│  │                    :5432 (localhost only)                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Caddy (reverse proxy)                                     │ │
│  │  :443 public — routes to backend and MeshCentral           │ │
│  │  :80 redirect + ACME                                       │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

External ports: 443 (HTTPS), 80 (redirect/ACME)
```

### URL Routing (Caddy)
```
rmm.example.com/                    → EasyRMM Backend (serves SPA + API)
rmm.example.com/api/v1/*            → EasyRMM Backend API
rmm.example.com/ws/*                → EasyRMM Backend WebSocket
rmm.example.com/mesh/*              → MeshCentral (proxied, stripped prefix)
rmm.example.com/meshagent/*         → MeshCentral agent WebSocket
```

**Single subdomain** — eliminates Tactical RMM's three-subdomain pain point.

### MeshCentral Configuration
MeshCentral runs on an internal port (e.g., 4430) and is reverse-proxied through Caddy:
- `AllowLoginToken: true`
- `AllowFraming: true`
- `WebRTC: false` (V1 — relay only)
- `AgentPort` unified with main HTTPS port
- Minimal UI — we hide it behind our interface

---

## Component Architecture

### Backend Modules
```
cmd/
  easyrmmserver/          # Main server entry point
  easyrmmagent/           # Endpoint agent entry point

internal/
  config/                 # Configuration loading
  server/                 # HTTP server setup, middleware
  auth/                   # Authentication, sessions, MFA
  rbac/                   # Role-based access control
  organization/           # Organization management
  site/                   # Site management
  device/                 # Device management, inventory
  devicegroup/            # Device group management
  enrollment/             # Agent enrollment, tokens
  meshcentral/            # MeshCentral integration layer
  monitor/                # Monitoring engine
  alert/                  # Alert engine, notifications
  job/                    # Job execution engine
  script/                 # Script library management
  software/               # Software deployment
  easypatch/              # EasyPatch API integration
  audit/                  # Audit logging
  report/                 # Reporting
  websocket/              # WebSocket hub for agent connections
  agent/                  # Agent protocol handlers

pkg/
  models/                 # Shared data models
  middleware/             # HTTP middleware (auth, CORS, rate limiting)
  crypto/                 # Cryptographic utilities
  validator/              # Input validation
```

### Agent Architecture
```
cmd/easyrmmagent/
  main.go                 # Entry point, service registration

internal/agent/
  config/                 # Agent configuration
  service/                # Windows service / Linux daemon
  connection/             # WebSocket connection + HTTPS fallback
  inventory/              # System inventory collection
  monitor/                # Monitoring data collection
  executor/               # Script/job execution engine
  software/               # Package manager integration
  updater/                # Self-update mechanism
  health/                 # Health checks
  meshagent/              # MeshAgent lifecycle management
```

---

## Database Schema (Core Tables)

### Multi-Tenant Hierarchy
```sql
-- Organizations (top-level tenants)
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sites within organizations
CREATE TABLE sites (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(organization_id, slug)
);

-- Device groups within sites
CREATE TABLE device_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id         UUID NOT NULL REFERENCES sites(id),
    name            TEXT NOT NULL,
    description     TEXT,
    mesh_group_id   TEXT,  -- MeshCentral device group ID
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Devices
```sql
CREATE TABLE devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id),
    site_id             UUID NOT NULL REFERENCES sites(id),
    device_group_id     UUID REFERENCES device_groups(id),
    hostname            TEXT NOT NULL,
    display_name        TEXT,
    os_type             TEXT NOT NULL,  -- 'windows', 'linux'
    os_name             TEXT,
    os_version          TEXT,
    os_build            TEXT,
    arch                TEXT,
    -- MeshCentral mapping
    mesh_node_id        TEXT UNIQUE,    -- MeshCentral device node ID
    mesh_group_id       TEXT,
    -- Hardware
    cpu_model           TEXT,
    cpu_cores           INTEGER,
    total_memory_mb     BIGINT,
    -- Identity
    serial_number       TEXT,
    manufacturer        TEXT,
    model               TEXT,
    -- Agent
    agent_id            TEXT NOT NULL UNIQUE,
    agent_version       TEXT,
    mesh_agent_version  TEXT,
    -- Status
    status              TEXT NOT NULL DEFAULT 'pending',  -- pending, online, offline, alert
    last_seen_at        TIMESTAMPTZ,
    enrolled_at         TIMESTAMPTZ,
    -- Metadata
    tags                TEXT[] DEFAULT '{}',
    custom_properties   JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_org ON devices(organization_id);
CREATE INDEX idx_devices_site ON devices(site_id);
CREATE INDEX idx_devices_group ON devices(device_group_id);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_mesh_node ON devices(mesh_node_id);
CREATE INDEX idx_devices_agent ON devices(agent_id);
CREATE INDEX idx_devices_hostname ON devices(hostname);
CREATE INDEX idx_devices_tags ON devices USING GIN(tags);
```

### Authentication & RBAC
```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    display_name    TEXT,
    role            TEXT NOT NULL DEFAULT 'technician',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    mfa_enabled     BOOLEAN NOT NULL DEFAULT false,
    mfa_secret      TEXT,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User-organization access (which orgs a user can access)
CREATE TABLE user_organization_access (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL DEFAULT 'technician',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, organization_id)
);

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    ip_address      INET,
    user_agent      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enrollment tokens for agent deployment
CREATE TABLE enrollment_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    site_id         UUID REFERENCES sites(id),
    device_group_id UUID REFERENCES device_groups(id),
    token_hash      TEXT NOT NULL UNIQUE,
    name            TEXT,
    max_uses        INTEGER,
    use_count       INTEGER NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,
    revoked         BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Jobs & Scripts
```sql
CREATE TABLE scripts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),  -- NULL = global/built-in
    name            TEXT NOT NULL,
    description     TEXT,
    shell           TEXT NOT NULL,  -- powershell, cmd, bash, python
    os_type         TEXT NOT NULL,  -- windows, linux, any
    content         TEXT NOT NULL,
    parameters      JSONB DEFAULT '[]',
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    category        TEXT,
    is_builtin      BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name            TEXT NOT NULL,
    job_type        TEXT NOT NULL,  -- script, software_install, software_uninstall, command, patch
    status          TEXT NOT NULL DEFAULT 'pending',
    target_type     TEXT NOT NULL,  -- device, device_group, site, organization
    target_id       UUID NOT NULL,
    script_id       UUID REFERENCES scripts(id),
    payload         JSONB NOT NULL DEFAULT '{}',
    scheduled_at    TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE job_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL REFERENCES jobs(id),
    device_id       UUID NOT NULL REFERENCES devices(id),
    status          TEXT NOT NULL DEFAULT 'queued',
    exit_code       INTEGER,
    stdout          TEXT,
    stderr          TEXT,
    dispatched_at   TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_job_results_job ON job_results(job_id);
CREATE INDEX idx_job_results_device ON job_results(device_id);
CREATE INDEX idx_job_results_status ON job_results(status);
```

### Monitoring & Alerts
```sql
CREATE TABLE alert_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    name            TEXT NOT NULL,
    description     TEXT,
    metric          TEXT NOT NULL,  -- cpu, memory, disk, service, agent_offline, etc.
    condition       JSONB NOT NULL, -- {operator: "gt", threshold: 90, duration_minutes: 5}
    severity        TEXT NOT NULL DEFAULT 'warning',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    notification_channels JSONB DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_rule_id   UUID REFERENCES alert_rules(id),
    device_id       UUID NOT NULL REFERENCES devices(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    severity        TEXT NOT NULL,
    message         TEXT NOT NULL,
    metric          TEXT NOT NULL,
    metric_value    DOUBLE PRECISION,
    status          TEXT NOT NULL DEFAULT 'active',  -- active, acknowledged, resolved
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_device ON alerts(device_id);
CREATE INDEX idx_alerts_org ON alerts(organization_id);
CREATE INDEX idx_alerts_status ON alerts(status);

CREATE TABLE device_telemetry (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id),
    cpu_percent     DOUBLE PRECISION,
    memory_percent  DOUBLE PRECISION,
    disk_usage      JSONB,  -- [{mount: "/", total: ..., used: ..., percent: ...}]
    network         JSONB,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_telemetry_device_time ON device_telemetry(device_id, collected_at DESC);
```

### Audit Logging
```sql
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id),
    organization_id UUID REFERENCES organizations(id),
    device_id       UUID REFERENCES devices(id),
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT,
    details         JSONB DEFAULT '{}',
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_org ON audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_device ON audit_logs(device_id, created_at DESC);
CREATE INDEX idx_audit_action ON audit_logs(action, created_at DESC);
```

---

## Docker Architecture

### docker-compose.yml Structure
```yaml
# All containers use network_mode: host
services:
  easyrmmdb:        # PostgreSQL 17
  meshcentral:      # MeshCentral server (internal port 4430)
  easyrmmserver:    # Go backend (internal port 8443)
  caddy:            # Reverse proxy (public 443, 80)
```

All containers use `network_mode: host`. Caddy is the single public entry point on ports 443/80, routing to:
- EasyRMM backend on localhost:8443
- MeshCentral on localhost:4430

PostgreSQL listens on localhost:5432 only.

### Persistent Storage (bind mounts)
```
./data/postgres/          # PostgreSQL data
./data/meshcentral/       # MeshCentral data, certs, config
./data/meshcentral-files/ # MeshCentral uploaded files
./data/easyrm/config/     # EasyRMM configuration
./data/easyrm/logs/       # Application logs
./data/easyrm/agents/     # Agent installation packages
./data/easyrm/uploads/    # Uploaded files (scripts, packages)
./data/easyrm/backups/    # Backup directory
./data/caddy/data/        # Caddy TLS certificates
./data/caddy/config/      # Caddy configuration
```

---

## MeshCentral Integration Design

### Device Identity Mapping
1. During enrollment, our agent installs and starts MeshAgent
2. MeshAgent connects to MeshCentral, gets assigned a `node_id`
3. Our agent reads the MeshAgent's node ID from its local state
4. Our agent sends the node ID as part of its enrollment payload
5. Backend stores the mapping: `devices.mesh_node_id = MeshCentral node_id`
6. Periodic sync reconciles any drift

### Remote Desktop Flow
1. User clicks "Remote Desktop" on a device page
2. Frontend requests a session token from our backend API
3. Backend verifies RBAC permissions
4. Backend generates a MeshCentral login token scoped to the target device
5. Backend logs the session in audit log
6. Frontend loads MeshCentral remote desktop viewer in an iframe with the token
7. MeshCentral handles the actual remote desktop relay
8. Session end is detected and logged

### Terminal & File Manager
Build natively using our Go agent + WebSocket, not MeshCentral.
- **Terminal**: Agent opens a PTY (Windows ConPTY / Linux pty), streams I/O over WebSocket to frontend xterm.js
- **File Manager**: Agent provides file system operations over WebSocket, frontend renders a file browser UI

This follows Tactical RMM v1.6+'s direction and gives us full control.

---

## Unified Installer Architecture

### Components Bundled
1. **MeshAgent** — remote access (desktop, relay)
2. **EasyRMM Agent** — monitoring, inventory, scripts, jobs, software, terminal, files
3. **EasyPatch Agent** — patch management (Windows only, optional on Linux)

### Windows Installer (MSI via WiX)
```
EasyRMM-Agent-Setup.msi
  ├── MeshAgent.exe (bundled)
  ├── EasyRMMAgent.exe (Go, static)
  ├── EasyPatchAgent/ (optional, .NET self-contained)
  └── install.ps1 (orchestrator)
```

Custom actions:
1. Extract all components
2. Configure MeshAgent with server URL and mesh ID
3. Install MeshAgent as service
4. Configure EasyRMM agent with server URL and enrollment token
5. Install EasyRMM agent as service
6. If Windows: configure and install EasyPatch agent as service
7. Start all services
8. Agent enrolls with backend, reports MeshAgent node ID
9. Health check

### Linux Installer (Shell script + DEB/RPM)
```
easyrm-agent-install.sh
  Downloads or extracts:
  ├── meshagent (bundled binary)
  ├── easyrmmagent (Go, static)
  └── easypatchagent (optional, .NET self-contained)
```

### Enrollment Flow
```
Installer → Configure MeshAgent → Start MeshAgent → MeshAgent gets node_id
         → Configure RMM Agent → Start RMM Agent
         → RMM Agent reads MeshAgent node_id
         → RMM Agent sends enrollment request to server
           (token, hostname, OS, mesh_node_id, capabilities)
         → Server validates token, creates device record
         → Server maps mesh_node_id to device
         → Server creates MeshCentral device group mapping
         → Server responds with agent credentials + config
         → Agent stores credentials securely
         → Agent begins check-ins and telemetry
```

---

## EasyPatch Integration Design

### Approach: API Gateway Integration
Our backend acts as a proxy/gateway to EasyPatch's REST API:

1. EasyRMM backend makes authenticated API calls to EasyPatch's `/api/v1/*` endpoints
2. EasyRMM maps its device IDs to EasyPatch endpoint IDs
3. EasyRMM frontend displays patch data in the device's "Updates" tab
4. Admin actions (scan, install, schedule) are proxied through our backend

### Device Mapping
- EasyPatch and EasyRMM share the same PostgreSQL instance
- Both use organization/site hierarchy
- Device mapping by hostname + agent ID or a shared identifier
- Sync job keeps device records aligned

### EasyPatch Deployment
EasyPatch runs as an additional Docker container in the stack:
```yaml
easypatch-api:     # EasyPatch backend (internal port)
easypatch-worker:  # EasyPatch background worker
```

Caddy routes `/api/v1/patches/*` to EasyPatch (or our backend proxies the calls).

---

## Security Architecture

### Authentication
- Argon2id password hashing (matches EasyPatch)
- TOTP MFA (mandatory for admins, optional for techs)
- Server-side sessions with `__Host-` cookie prefix
- CSRF protection via `X-XSRF-TOKEN` header
- Rate limiting: 20 requests/min on auth endpoints
- Account lockout: 5 failures → escalating lockout (5m, 15m, 1h, 24h)
- Session expiration: 24 hours, sliding window

### Agent Authentication
- Per-device ECDSA P-256 key pair generated at enrollment
- Every agent request signed with timestamp + nonce
- Server validates signature, timestamp freshness, nonce uniqueness
- Automatic key rotation
- Enrollment tokens are single/limited-use with expiration

### Tenant Isolation
- Every database query includes `organization_id` filter
- API middleware extracts and enforces tenant context
- Backend validates organization access before every operation
- MeshCentral device groups scoped per organization
- Login tokens scoped to specific device nodes
- File operations sandboxed per organization

### RBAC Roles
| Role | Scope | Capabilities |
|------|-------|-------------|
| Super Admin | Global | Everything |
| Org Admin | Organization | Manage org users, sites, all devices, all operations |
| Site Admin | Site | Manage site devices, run scripts, remote access |
| Technician | Assigned orgs | View/manage devices, remote access, run scripts |
| Read Only | Assigned orgs | View only |
