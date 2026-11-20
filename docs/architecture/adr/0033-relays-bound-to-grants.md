# ADR-0033: Relays bound to their grants

* Status: Accepted (2026-11-16). Amends ADR-0014 and ADR-0022. Follows the
  [security review](../../security/security-review.md) of the remote-access gateway.

## Context
ADR-0022 checks a browser's relay connection against the EasyRMM session's
grants, and refuses TCP and UDP routing wherever it can be asked for. The
security review found four ways around the grant model that ADR-0022 left
open. Each was checked against MeshCentral 1.3.1 and MeshAgent in the
integration test.

* **Tunnels were not bound to grants.** MeshCentral pairs the two ends of a
  relay by the tunnel id alone, and the browser asks for the agent's end
  separately, with a `tunnel` message on the control channel naming a device
  and the relay address the agent joins. The gateway checked the browser's
  relay but not the tunnel message. So a technician holding a terminal grant
  for device X could open the relay for X, then ask device Y's agent to join
  it. MeshCentral checks the address's `nodeid` against the message only when
  the address has one, and lets the address name another server outright.
  The agent also takes the session type from the browser's first relay
  message, not from the address, so a terminal relay could become a desktop.
  MeshCentral's per-site rights still applied, but the session escaped the
  per-device, per-kind grant and its audit entry.
* **Other device messages reached the agent.** MeshCentral routes every
  `msg` to the agent for any user with remote-control rights. For process
  lists and kills, service control, opening web pages, message boxes,
  clipboard reads and system details, MeshAgent checks no session-type right.
  Every EasyRMM technician with any remote permission at a site holds
  remote control there. With the check removed, the integration test's
  terminal-only session got the agent's CPU and memory details.
* **The agent path served a user's file download.** The gateway forwards
  agent routes to MeshCentral's main port. Besides the agent's WebSocket,
  that port answers a plain GET of `devicefile.ashx` with a user's
  MeshCentral cookie (`c`, from the `authcookie` command) by downloading a
  file from the device. Without browser headers this needed no EasyRMM
  session at all. With the check removed, the integration test downloaded
  the device's `/etc/hostname` this way. On the browser path the download
  had no device or kind check either.
* **MeshCentral reads `tcpport[]` as `tcpport`.** Its web server (Express 4)
  parses queries with `qs`, which turns `tcpport[]=22` and `tcpport[0]=22`
  into `tcpport`. The gateway compared whole key names, so these spellings
  passed ADR-0022's routing check.

`uploadfilebatch.ashx` was also reachable. It pushes files to every
device the user can reach at once, with no EasyRMM session on any of them,
and the views that use it are hidden in EasyRMM.

## Decision
* **Tunnel requests are checked against grants.** On the control channel,
  every `msg` of type `tunnel` must:
  * be for this server's relay (`*/meshrelay.ashx?…`);
  * carry exactly `p`, `nodeid`, `id` and optionally `rauth`, with no
    brackets, fragments or control characters;
  * name the same device as the message;
  * be for a device and session type the EasyRMM session holds a grant on.

  Anything else closes the channel. An accepted request records its tunnel
  id for that session, device and protocol for two minutes, with at most 64
  waiting per session. The browser's relay connection records its id the
  same way, and may not take an id recorded for another session, device or
  protocol.
* **The agent joins only recorded tunnels.** An agent-path relay that names
  a device must name a recorded tunnel, for that device and protocol.
  Relays MeshCentral asks for itself (web RDP, device file downloads) name
  no device. The only ways to them are MeshCentral's own server-side checks
  and the gateway's RDP and download checks, since a tunnel request without
  a device is refused.
* **The session type cannot change on the relay.** On a browser relay, the
  first message that is not a JSON object must be the protocol the relay
  was admitted for. Until then the gateway reads each message whole; after
  it, the relay passes unread.
* **Device messages are an allowlist.** Tunnel requests are checked as
  above. Clipboard, wallpaper and signed-in-user messages (`getclip`,
  `setclip`, `deskBackground`, `userSessions`) need a desktop grant on the
  device. Every other `msg` type is dropped: it is not forwarded, a warning
  is logged, and the channel stays open. Control actions other than `msg`
  remain MeshCentral's to check. They need rights EasyRMM does not grant
  (agent console, power, wake, notifications, device management).
* **The agent path is what MeshCentral's agent port serves.** `agent.ashx`,
  `meshrelay.ashx`, `devicefile.ashx` and `agenttransfer.ashx` must be
  WebSockets; `meshagents` and `agentdownload.ashx` must be plain GETs.
  Anything else is refused.
* **Browser downloads need a files grant.** A browser's `devicefile.ashx`
  must be a GET naming exactly one device (`n`) the session holds a files
  grant on.
* **Uploads are refused** (`uploadfile.ashx`, `uploadfilebatch.ashx`).
* **Query keys are read as MeshCentral reads them.** Routing and credential
  keys are matched on the name before any bracket, in any case. Relay and
  download queries with bracketed keys are refused.

## Consequences
* MeshCentral's process, service and system-information views, and "end
  another user's session", do not work through EasyRMM. They were already
  hidden. Clipboard and session selection work in desktop sessions only.
* Tunnel ids live in the gateway's memory. A restart forgets them, and a
  browser waiting for its agent at that moment has to reconnect. EasyRMM
  runs one gateway per server, so no ids need sharing.
* A remote session costs one more grant lookup (the tunnel request) and
  reads its first few relay messages; the session's data is not inspected.
* The checks are written against MeshCentral 1.3.1 and MeshAgent from it.
  The end-to-end test runs a real agent and checks each refusal: an
  ungranted session type, a tunnel naming no device, a TCP port spelled as
  an array, a protocol switch on the relay, dropped device messages and
  file downloads with and without a files grant. It also checks a terminal,
  a web RDP connection and a granted download still work. A MeshCentral
  update has to pass it.
