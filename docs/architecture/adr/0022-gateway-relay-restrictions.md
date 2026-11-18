# ADR-0022: No TCP or UDP tunnels through the remote-access gateway

* Status: Accepted (2026-11-16). Refines ADR-0014. Amended (2026-11-16):
  a relay needs a grant of its own session type; MeshCentral's web RDP
  relay is admitted for RDP grants (ADR-0026). Amended by ADR-0033: tunnel
  requests and the agent's end of a relay are bound to grants, other device
  messages are dropped, and query keys are read as MeshCentral's parser
  reads them (`tcpport[]`).

## Context
MeshCentral relays bytes between a browser and an agent. Besides the
desktop, terminal and file sessions EasyRMM offers, the same relay can
carry a TCP or UDP connection that the agent opens to any port on the
device, or to any address the device can reach (the feature behind
MeshCentral Router and its web RDP, SSH and VNC). A browser asks for it
with routing instructions (`tcpport`, `tcpaddr`, `udpport`, `udpaddr`) in
any of three places:

* the relay URL (`meshrelay.ashx?…&tcpport=3389`);
* a relay cookie requested on the control channel (`getcookie` with
  routing fields), which the server encodes and later honors;
* a tunnel request sent to the agent over the control channel (`msg`,
  `type: "tunnel"`), with the fields beside it or inside the relay address
  it names.

MeshCentral checks only the remote-control right for these, not a session
type. Every EasyRMM user with a remote-access grant has that right on the
device, so a grant for a terminal also let its holder reach, say, the file
shares of every server on the customer's network. ADR-0014 refused the web
RDP, SSH and VNC pages, but not the relay underneath them.

Two further gaps let a request skip the gateway's browser checks:

* On the agent path (no `Origin`, no Fetch Metadata, no gateway cookie)
  `meshrelay.ashx` accepted a MeshCentral user's credentials (`auth`, the
  session cookie, `X-MeshAuth`), so a script holding a user's MeshCentral
  cookie could open a relay without a grant.
* `localrelay.ashx` makes MeshCentral itself connect to an address and relay
  it.

## Decision
* **Relays carry EasyRMM's session types only.** A browser's
  `meshrelay.ashx` request must name exactly one protocol of the terminal
  (1, and its PowerShell and logged-in-user variants 6, 8, 9), desktop (2)
  or files (5), and exactly one device. Routing instructions are refused in
  any letter case. The device must be one the caller's EasyRMM session
  redeemed a grant for (`remote_grants` joined to `devices.mesh_node_id`),
  of the relay's session type: a terminal grant opens terminal relays only,
  so the kind the audit log records is the kind used. The gateway checks
  this before forwarding; MeshCentral then applies its own rights as
  before.
* **The control channel is inspected.** The gateway reads the browser's
  side of `control.ashx` frame by frame, holds each message until its last
  frame, and forwards it only if it is a JSON object with no routing field
  at the top level and no routing instruction inside a `value` string (the
  tunnel's relay address). Anything else closes the channel; the agent
  never sees the message. Compressed or unmasked frames, frames out of
  sequence and messages over 8 MiB also close it. The gateway strips
  `Sec-WebSocket-Extensions`, so browsers never compress. Ping, pong and
  close frames pass straight through.
* **The agent path carries no user credentials.** Requests without browser
  headers lose `Cookie` and `X-MeshAuth`, and an agent-path
  `meshrelay.ashx` request with routing instructions or user credentials
  (`auth`, `user`, `pass`, `key`, `token`) is refused. Agents join relays
  with the tunnel id and a relay cookie only.
* **`localrelay.ashx` is refused**, like the other features EasyRMM does
  not offer.
* Refusals answer 403 with the gateway's "Not available" page and are
  logged at warning level with the reason; a failed grant lookup answers
  500.

## Consequences
* MeshCentral Router, port mapping and the web SSH and VNC clients do not
  work through EasyRMM. RDP is a session type of its own with its own grant
  (ADR-0026), not a general tunnel.
* Every control channel message from the browser is buffered and parsed
  once. Those messages are small (the largest is clipboard text); the relay
  channels carrying the session itself are not inspected, so desktop
  latency is unchanged.
* The checks are written against MeshCentral 1.3.1. A MeshCentral update
  that adds a new way to ask for routing has to be reviewed against this
  record; the integration test asks a live MeshCentral and agent for a
  tunnel in each known way and expects a refusal, and a terminal next to
  them to keep working.
