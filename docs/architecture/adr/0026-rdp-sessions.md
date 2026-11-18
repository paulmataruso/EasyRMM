# ADR-0026: RDP sessions

* Status: Accepted (2026-11-16).
* Refines: ADR-0005 (MeshCentral identity and sessions), ADR-0022 (gateway
  relay restrictions).

## Context
Technicians asked to reach Windows devices over Remote Desktop as well as
MeshAgent's own desktop: RDP gives a Windows session of its own (not the
console's), the user's resolution, and Windows' own graphics and clipboard
handling. MeshCentral 1.3.1 has a web RDP client. The device page's
**RDP Connect** asks for credentials and opens `mstscrelay.ashx`; its first
message names the device and carries the credentials:

    ["infos", {"ip": "node//…", "port": 3389, "screen": {"width": …, "height": …},
               "domain": …, "username": …, "password": …, "options": {…}}]

MeshCentral then relays to itself (`meshrelay.ashx?p=10`) with a cookie
that names the device and its RDP port (the device's `rdpport`, else 3389;
the port the browser sends is ignored for a node ID), asks the agent for a
TCP tunnel to that port on the device itself, and speaks RDP over it. It
checks the remote-control right only. When `ip` is not a node ID it is an
encoded cookie, which can name any address the agent can reach.

ADR-0022 blocked `mstscrelay.ashx` with the other tunnels and said RDP would
be a session type of its own, with its own grant.

## Decision
* **RDP is a session kind** (`rdp`) beside desktop, terminal and files. It
  needs the remote desktop permission (`device.remote_desktop`), is
  granted, redeemed and audited like the others, and its grants are their
  own (`remote_grants.kind = 'rdp'`). The console offers it on Windows
  devices; the server does not restrict it by platform.
* **The gateway admits MeshCentral's RDP relay for RDP grants only.**
  `mstscrelay.ashx` passes the edge (with the grant cookie, like every
  page) only as a WebSocket, and the gateway reads the browser's side of
  it message by message (the control channel's reader, ADR-0022). The
  first message must be `infos` with `ip` a node ID of a device the
  session redeemed an RDP grant for; a cookie, any other device, another
  message first or a second `infos` closes the connection before
  MeshCentral sees it. Later messages (input, clipboard, pong) pass. The
  stand-alone RDP page (`/mstsc.html`), which connects by cookie, stays
  blocked. MeshCentral's own relay to itself does not pass the gateway,
  and the agent joins it with a tunnel id and a relay cookie as for any
  other session.
* **Credentials are typed for each session and never stored.**
  `allowSavingDeviceCredentials` is off, which removes MeshCentral's
  "Remember credentials" box and makes it ignore stored ones. The session
  view keeps the credentials in the page's memory while the session is
  connected, as MeshCentral's RDP client itself does, and forgets them
  when the session ends.
* **The RDP session follows the window.** The launch link adds `rdp=1`; the
  session view tuning (ADR-0025) then opens MeshCentral's RDP credentials
  dialog instead of connecting MeshAgent's desktop, shows only the RDP
  Connect button (and only MeshAgent's in a desktop session), and sizes the
  session to the view (widths a multiple of 4, 200 to 8192 pixels, as
  MeshCentral sizes it by default). When the view is resized by 32 pixels
  or more and stays still for a second, it disconnects and connects again
  at the new size with the same credentials; Windows reconnects the same
  logon session. A fixed size chosen in MeshCentral's desktop settings is
  kept. MeshCentral's RDP client cannot resize a running session, so this
  is a reconnect, which takes a moment.

## Consequences
* RDP reaches the device's own RDP port through its agent, so the device
  needs Remote Desktop enabled and no inbound firewall rule; nothing else
  on the device's network is reachable this way.
* The resize reconnect blanks the view for a moment and, like any RDP
  reconnect, signs the session in again (a Windows logon event).
* MeshCentral's web RDP client is written against Windows' RDP server. It
  does not complete a connection to xrdp (0.9 and 0.10 reject its channel
  join sequence), so RDP to Linux devices running xrdp does not work; the
  console does not offer it there.
* What was verified through the preview with a real MeshAgent: the RDP
  dialog opening by itself, the buttons, the relay refused without an RDP
  grant, and with one the agent's tunnel to the RDP port and the TLS
  handshake with the RDP server. A complete session against Windows has
  not yet been run.
