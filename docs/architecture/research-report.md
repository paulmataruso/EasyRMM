# Phase 1 — Research and Discovery Report

Date: 2026-11-15. Sources were inspected directly: shallow clones of each
repository's default branch, read at the source level. Citations use
`file:line` against the revision named in each section. Nothing in this report
is copied code; the products below were studied for design only.

## 1. MeshCentral and MeshAgent

Revision: MeshCentral `master` @ b8cac8f (package 1.3.1, latest tag);
MeshAgent `master` @ 0e6b4f7. Licence: Apache-2.0 for both (MeshAgent states it
in `readme.md` and per-file headers; it bundles OpenSSL, libjpeg-turbo, Duktape
and zlib, whose notices must ship with it).

### 1.1 How agents trust the server

* The `.msh` `ServerID` is the SHA-384 of the public key of MeshCentral's
  **agent certificate** (`agentserver-cert-public.crt`), not the TLS
  certificate (`webserver.js:307`, `certoperations.js:967`).
* The agent additionally reports the SHA-384 of the TLS certificate it saw;
  the server signs it together with both nonces (`MA: meshcore/agentcore.c:3120`).
  This is channel binding: the server refuses ("BadWebCertHash") if the hash is
  not one of its known web certificates (`meshagent.js:487`).
* Behind TLS offload, MeshCentral learns the public certificate from the
  domain's `certUrl` (`certoperations.js:547`), which also accepts
  `file:///path.pem`. It is re-read when an agent presents an unknown hash, at
  most every two minutes, after which held agents are disconnected and
  reconnect (`meshcentral.js:2331, 2367`). Certificate renewal therefore costs
  agents up to ~2 minutes of reconnect, not a lock-out.
* `ignoreAgentHashCheck` disables the channel binding and lets any TLS
  interceptor relay agent sessions. **We never use it.**
* `meshcentral-data/agentserver-cert-*` is the root of agent trust. Losing it
  orphans every agent; it must be in every backup.

### 1.2 Serving MeshCentral behind our edge

* `tlsOffload` + `trustedProxy` make MeshCentral serve plain HTTP on a loopback
  port and trust `X-Forwarded-*` from our edge (`webserver.js:7166, 7259`).
  `aliasPort:443` keeps generated URLs on 443; `exactPorts:true` stops it from
  silently moving to port+1.
* Listeners to disable under host networking: `redirPort:0` (otherwise binds
  :80), `mpsPort:0` (Intel AMT CIRA on :4433, all interfaces),
  `amtManager:false`, `WANonly:true` (stops UDP 16990 multicast scanning),
  `webRTC:false` (otherwise direct UDP + public STUN). Everything agents need —
  `agent.ashx`, `meshrelay.ashx`, file transfer, self-update via
  `meshagents` — works over the single HTTPS port.
* Sub-path domains (`/mesh/`) work for agents and browsers, but share the
  browser origin with the host application. MeshCentral's CSP allows
  `'unsafe-inline'` (`webserver.js:7462`) and its cookies use path `/`, so an XSS
  in MeshCentral would become an XSS in our application. A **dedicated
  hostname** isolates it.

### 1.3 Embedding and login tokens

* There is no REST API. Administration uses the `control.ashx` WebSocket JSON
  protocol (as `meshctrl.js` does), authenticated with an encrypted cookie in
  `?auth=` and correlated by `responseid`.
* Login token format (`meshcentral.js:3987`): `base64(iv[12] ‖ tag[16] ‖
  AES-256-GCM(key[0:32], json))` with `+→@`, `/→$`. JSON:
  `{"u":"user/<domain>/<name>","a":3,"time":<unix>}`, optional `expire`
  (minutes) and `once` (single use). Key: 80 random bytes,
  `settings.loginCookieEncryptionKey` (160 hex) overrides the stored one.
* A legacy CBC token format exists. Tactical RMM uses it, and it only
  validates because of an inverted HMAC comparison in MeshCentral
  (`Buffer.compare(...) == false`). **We use the GCM format only.**
* `?login=` is honoured whenever a key exists, regardless of
  `allowLoginToken`, so the key is equivalent to an admin impersonation
  credential and is stored sealed, like other root secrets.
* Embedding URL: `/?login=<token>&gotonode=<96-hex or b64 node id>&viewmode=11|12|13&hide=63`
  (11 desktop, 12 terminal, 13 files; `hide` 63 hides header, tabs, footer,
  titles, left menu and back buttons; `default.handlebars:2068`). Framing is
  allowed with `allowedFramingOrigins`.
* A login token carries the MeshCentral user's full rights. Least privilege
  therefore needs one MeshCentral user per technician, with rights granted per
  device group (`addmeshuser`) or per device (`adddeviceuser`). Device share
  links (`createDeviceShareLink`) can scope a session to one node.

### 1.4 Installing MeshAgent and identifying the node

* A generic agent binary (`meshagents?id=N`) plus a separate `.msh` works:
  `meshagent -fullinstall --copy-msh=1` (the official Linux installer does
  exactly this). Agent IDs: Windows x64 4, x86 3, ARM64 43; Linux x64 6,
  ARM64 32, armhf 25.
* Our server can generate the `.msh` itself (`MeshName`, `MeshType=2`,
  `MeshID=0x…`, `ServerID=…`, `MeshServer=wss://host:443/agent.ashx`).
* MeshCentral replaces any agent binary whose hash differs from its own on
  connect (`meshagent.js:2280`), so bundled binaries must match the pinned
  server version or will be updated once automatically.
* Node id: `node/<domain>/<b64(SHA384(agent cert pubkey))>`. Read locally from
  the Windows registry `HKLM\SOFTWARE\Open Source\Mesh Agent\NodeId` or by
  running `<installed binary> -nodeid` (hex) as root/admin. It changes after a
  reinstall with data removed, `-resetnodeid`, or when none of the recorded MAC
  addresses remain, so correlation must be continuous.
* A `MeshAgent.tag` file next to the binary is read at every start and sent on
  every connect; the server stores it as `node.agent.tag` and emits
  `changenode`. **`Tag=` inside the `.msh` appears to be wiped**
  (`MA: agentcore.c:5463`). We write `easyrmm:<device-uuid>` to the tag file for
  server-side correlation (to be verified empirically on both platforms).

### 1.5 Docker

`ghcr.io/ylianst/meshcentral:1.3.1` (Node 24 alpine). Config at
`/opt/meshcentral/meshcentral-data/config.json`; supported stores include
NeDB (default), MongoDB and PostgreSQL. Persist `meshcentral-data`,
`meshcentral-files`, `meshcentral-backups` and, if recording,
`meshcentral-recordings` (not a declared volume).

## 2. Tactical RMM

Revisions: `amidaware/tacticalrmm`, `amidaware/rmmagent` v2.12.0,
`tacticalrmm-web`. Licence: Tactical RMM License (source-available). Studied
for design only.

What it does well, and we adopt in our own implementation:

* Mutual self-healing: the RMM agent restarts or reinstalls MeshAgent, and
  MeshCentral `runcommands` can recover the RMM agent. Exposed as one-click
  "Restart / Recover connection" on the remote session view.
* Per-technician MeshCentral accounts with a least-privilege rights mask, real
  names shown in end-user consent prompts, and an audit row per session.
* Jittered, split check-in cadences: cheap heartbeat every 30–60 s, inventory
  every few hours.
* Scripts with variables, environment variables, run-as-user, default
  timeouts, platform filters and return-code-to-severity mapping;
  process-tree kill on timeout.
* Monitoring with warning/error thresholds, fails-before-alert, maintenance
  mode, alert templates with failure *and* resolution actions.
* Expiring per-site deployment links.

Weaknesses we design against:

* Deployment friction: three subdomains, ~12 services (Django, Celery, Redis,
  NATS, MongoDB…), an 1100-line install script.
* Two identities per device that drift (`mesh_node_id` duplicates after
  reinstall), and a 4-minute polling permission sync that throttles itself
  to avoid overloading MeshCentral, opening a new WebSocket per call.
* Ad-hoc commands fail if the agent is offline; there is no durable queue.
* No signature verification of agent updates or scripts; the NATS admin
  password is the Django secret; TLS verification disabled for mesh downloads;
  agent token in plaintext in the registry; broad Defender exclusions
  (including the script directory).
* Software inventory as one JSON blob per agent; features hidden behind
  right-click menus; one policy per level.

## 3. EasyPatch

Repository: `paulmataruso/EasyPatch` v1.7.1. C# / .NET 10, ASP.NET Core
minimal APIs, EF Core + PostgreSQL 18, React 19 SPA behind Caddy. Licence:
**FSL-1.1-ALv2** (source-available, *not* OSI-approved; each version becomes
Apache-2.0 after two years; "Competing Use" restricted).

* Agent: .NET self-contained (~53 MB), Windows Update Agent COM API, apt/dnf on
  Linux, winget app updates; ECDSA P-256 signed HTTPS polling (60 s);
  per-device key pair generated locally (DPAPI / `systemd-creds`); signed
  self-update manifests.
* API: `/api/v1` with endpoints for endpoints, updates, scans, install jobs,
  job history and progress, policies (maintenance windows, rings), reports.
  Iframing is blocked (`frame-ancestors 'none'`).
* Authentication: browser sessions (MFA) and agent signatures only. **No API
  keys or service accounts exist**, so a third-party backend cannot call the
  API today.
* Device re-identification on reinstall: organisation + SMBIOS UUID +
  hostname.
* Deployment: bridge networking, Caddy owns host ports 80/443 — it cannot
  co-reside with our host-networked edge without changes.

Implications: integration must be **server-to-server through an integration
credential** that EasyPatch does not have yet; the EasyPatch agent must not be
redistributed inside our OSI-licensed installer (licence), so our agent
**downloads it from the customer's own EasyPatch server** at enrolment time.
The full list of required EasyPatch changes is in
[`docs/integrations/easypatch.md`](../integrations/easypatch.md).

## 4. Impeccable

`impeccable` 4.9.1 (Apache-2.0). Installed for Claude Code at project scope
with `npx impeccable install -y --providers=claude --scope=project`.
`/impeccable init` writes `PRODUCT.md`; `DESIGN.md` is produced by
`/impeccable document` from the shipped interface. The deterministic detector
(`npx impeccable detect`) has 62 rules, emits `--json` or GitHub annotations
(`--github`), and exits 2 on findings — usable as a CI gate. For TSX/CSS it
runs regex rules only; rendered-page rules (contrast, tiny text, nested
cards) need a URL scan with a browser.

Constraints that shape our visual direction: the detector flags cyan-on-dark
palettes, colored glows, gradient text, nested cards, hero-metric templates,
pulsing dots for non-live data, and overused fonts (Inter, Roboto, Geist,
Space Grotesk, Plus Jakarta Sans…). Glassmorphism must be a specific effect,
not decoration. The requested "restrained aqua/cyan accents on dark" must
therefore be declared deliberately in `DESIGN.md` and used sparingly.

Operational notes: hooks run outside model approval; Impeccable's optional
"live" mode can launch `claude --permission-mode bypassPermissions` — we keep
live mode disabled (`IMPECCABLE_LIVE_COPY_AGENT=off`).

## 5. Other products (feature benchmarking)

NinjaOne, Datto RMM, Atera, Syncro, Level.io and Action1 converge on: one
lightweight agent, a fleet table with saved views and bulk actions, policy
inheritance (global → org → site → device), patch rings and maintenance
windows, scripted automation with a library, and remote access launched from
the device page in one click. Level.io and Action1 emphasise a fast,
keyboard-friendly UI; NinjaOne emphasises policy-driven monitoring. RustDesk
is an alternative remote access engine (AGPL) we do not adopt because
MeshCentral already meets the requirements.

## 6. Technical unknowns and risks

| Risk | Mitigation / verification |
|---|---|
| `.tag` correlation and `Tag=` behaviour unverified at runtime | Integration test against pinned MeshCentral 1.3.1 with real agents on Windows and Linux runners |
| Agents disconnect up to ~2 min after certificate renewal | Edge writes `proxy-cert.pem` before switching certificates; document the window |
| `loginCookieEncryptionKey` is an admin-equivalent secret | Sealed at rest, never sent to browsers, tokens are short-lived and single-use |
| MeshCentral meshid works as an enrolment secret (`/meshsettings`, `/meshagents` unauthenticated) | Edge does not expose those routes publicly; our agent obtains the `.msh` through our authenticated API |
| `closeusersessions` may not end live desktop relays | Verify; additionally block the technician's MeshCentral user (rights removal) on revocation |
| Windows agent code signing / SmartScreen / AV false positives | Signing pipeline ready for an Authenticode certificate; never add AV exclusions |
| EasyPatch lacks service credentials | Required EasyPatch changes documented before implementation (Phase 8) |
| Go reverse proxy behaviour with long-lived upgraded connections | Soak test agent WebSockets through the edge |
| GitHub-hosted runners cannot validate every Windows/Linux endpoint scenario | Documented self-hosted runner matrix for installer tests |
