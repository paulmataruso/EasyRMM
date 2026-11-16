# ADR-0014: Remote-access gateway rules and device discovery

* Status: Accepted (2026-11-15). Refines ADR-0004 and ADR-0005.

## Context
Building ADR-0004's gateway and ADR-0005's session launch against
MeshCentral 1.3.1 raised questions those records left open:

* Some MeshCentral routes serve both agents and browsers (`meshrelay.ashx`
  carries both ends of a remote session). Forwarding "agent routes
  unconditionally" would let any browser reach them without a grant.
* The grant has to reach a browser inside an iframe on another hostname,
  and stay unusable from anywhere else.
* Revoking an EasyRMM session must also end remote sessions that are
  already open, not only refuse new requests.
* By default MeshCentral serves agent installers and their settings to
  anyone who knows a device group's identifier.
* EasyRMM needs devices before its own agent exists (phase 6).

## Decision
* **Browser or agent.** A request counts as coming from a browser if it
  carries `Origin`, `Sec-Fetch-Mode` or `Sec-Fetch-Site`, or the gateway's
  cookie. Agents send none of these. Agent routes (`agent.ashx`,
  `meshrelay.ashx`, `devicefile.ashx`, `agenttransfer.ashx`, `meshagents`,
  `agentdownload.ashx`) are forwarded without a grant only for non-browser
  requests; MeshCentral still authenticates them itself. Browsers need a
  grant for every path. (ADR-0033: agent requests must also be the kind
  MeshCentral's agent port serves, WebSocket or GET, and an agent's relay
  must join a tunnel a session was granted.)
* **Features EasyRMM does not offer are refused**, grant or not: account
  creation and password pages, invitations and sharing links, server
  backup and restore, plugins, the web RDP/SSH/VNC relays, Intel AMT,
  messenger and recordings. Unusual paths (encoded slashes, dot segments)
  are refused before routing.
* **Launch.** The console asks the API for a session; the server checks the
  permission at the device's site, that the device is online and that
  MeshCentral is connected, makes sure the user's MeshCentral account and
  its rights at that site exist, stores the SHA-256 of a one-time launch
  token (valid one minute) and audits the launch. The iframe opens
  `/.easyrmm/launch?t=…` on the MeshCentral hostname. The gateway redeems
  the token once, sets `__Host-easyrmm_remote` (`HttpOnly`, `Secure`,
  `SameSite=Strict`, `Path=/`), whose hash is bound to the grant and the
  EasyRMM session, and redirects to MeshCentral with a single-use login
  token, MeshCentral's own navigation hidden and the device view open. Our
  cookie is removed before requests reach MeshCentral.
* **Same site, HTTPS only.** A `SameSite=Strict` cookie is sent inside an
  iframe only when the console and the framed page are the same site, so
  the two hostnames must share a registrable domain. The server refuses to
  start otherwise (checked with the Public Suffix List). Remote sessions
  need HTTPS; plain-HTTP and bare-IP lab installs cannot embed them.
* **Revocation reaches open sessions.** Grant checks are cached for 15
  seconds. The gateway tracks every WebSocket it proxies by EasyRMM session
  and, every 15 seconds, closes those whose session has ended (sign-out,
  revocation, expiry, user disabled). It closes all of them on shutdown.
* **Agent downloads need a session** (`lockAgentDownload`). Agents'
  self-update keeps working. EasyRMM will publish its own installers
  (ADR-0008).
* **Devices are discovered from MeshCentral** until the EasyRMM agent
  exists: nodes in device groups EasyRMM created are mirrored into
  `devices` (name, hostname, operating system, platform, online, last
  seen), refreshed on MeshCentral's events and every five minutes. The
  EasyRMM agent will attach to the same rows through `mesh_node_id`.
* **Certificates.** MeshCentral reads the certificate its agents pin from
  the edge (`certUrl`). When the edge renews it, MeshCentral reloads it the
  first time an agent reports a mismatch (at most every two minutes) and
  the agents reconnect.

## Consequences
* Deployments need two hostnames under one parent domain, both with
  certificates browsers trust.
* A browser that sent no `Origin` and no Fetch Metadata would be treated
  as an agent on agent routes only, where MeshCentral demands its own
  authentication. Every current browser sends `Origin` on WebSocket
  handshakes and Fetch Metadata on navigations.
* Ending an EasyRMM session ends its remote sessions within about 15
  seconds, not instantly.
* Agents started with `meshagent connect` are temporary: MeshCentral
  deletes them when they disconnect, and they leave EasyRMM's device list
  too.
