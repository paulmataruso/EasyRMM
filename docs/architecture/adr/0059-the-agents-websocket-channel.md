# ADR-0059: The agent's WebSocket channel

* Status: Proposed (2026-11-21). Not implemented.
* Refines: [ADR-0009](0009-agent-protocol.md) (its WebSocket, "authenticated
  by a signed challenge", as the primary channel) and
  [ADR-0017](0017-scripts-and-jobs.md) (job delivery: the signed poll stays
  the only way jobs reach an agent).
* Builds on: [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (signed
  requests), [ADR-0058](0058-signed-settings-that-reach-the-agent.md)
  (signed settings: the transport is one), and ADR-0057 (proposed:
  rotating the job key).
* Part of [the feature plan](../feature-plan.md): feature 8.

## Context
The owner asked to "implement websockets", with the operator choosing in a
device's settings which transport it uses.

ADR-0009 planned a WebSocket as the agent's primary channel with HTTPS
polling as the fallback; ADR-0017 delivered jobs over a signed long poll
first, "the WebSocket channel later". What exists:

* **Jobs already arrive at once on one server.** The agent's job worker
  holds a long poll at all times: it asks again as soon as an answer
  arrives (`agent/jobs/worker.go`). The server holds each poll for up to
  25 seconds (`agentproto.PollWait`) and answers as soon as a run for the
  device is queued or canceled on that instance (the `hub` in
  `server/internal/jobs/service.go`, `Poll` in `delivery.go`). In the
  2,000-agent drill a job reached a waiting agent in 231 ms at the median
  (`docs/development/drills.md`).
* **Everything else waits for the heartbeat.** Agent updates (ADR-0027),
  the EasyPatch agent's install (ADR-0031), an uninstall (ADR-0050) and,
  with ADR-0058, settings travel in the heartbeat answer, every 60 seconds
  (`agent/runner/runner.go`).
* **Held polls are most of the traffic.** Each is a signed request whose
  nonce is written to PostgreSQL (`FinishSigned` in
  `server/internal/agents/signed.go`) and a claim transaction
  (`claim` in `delivery.go`). The 2,000-agent hour made 287,866 long polls
  and 119,785 heartbeats; agent nonces were the largest table.
* **Presence is a guess**: a device is online if it reported within three
  minutes (`devices.AgentOnlineWindow`), whatever happened since.
* **Several servers**: the hub is in-process, so a job queued on one
  instance reaches a poll held on another only when that poll ends, up to
  25 seconds later, as ADR-0017 says.
* **The edge** (`server/internal/app/edge.go`) offers `h2` and
  `http/1.1`, has a 10-second header timeout and no read timeout, since it
  carries long polls and WebSockets (`bodyTimeout` in
  `server/internal/httpapi/agentapi/agentapi.go`). `http.Server.Shutdown`
  neither closes nor waits for hijacked connections such as WebSockets
  (net/http's documentation), so their own code must close them.
* **Agents pin no TLS key**: they trust the system's roots or a CA file,
  and their HTTP client clones Go's default transport, so it follows
  `HTTPS_PROXY` from the service's environment (`agent/client/client.go`).
  TLS-inspecting firewalls at MSPs' customers read everything; some refuse
  WebSocket upgrades, some accept them and then hold or cut the
  connection. Connections cannot be bound to TLS: in offload mode NGINX
  terminates it (`docs/deployment/nginx.md`).
* **MeshAgent, for contrast,** holds a WebSocket of its own to MeshCentral
  (`/agent.ashx`) through the same edge (`agentRoutes` in
  `server/internal/remote/gateway.go`). MeshCentral authenticates it and
  keeps it alive every 300 seconds (`agentPong` in
  `server/internal/meshcentral/config.go`), which is why the NGINX guide
  raises proxy timeouts to an hour. It shows that a persistent WebSocket
  through the edge works; but it carries MeshCentral's protocol, which
  EasyRMM can neither read nor sign into, and it has no fallback: where a
  network blocks it, remote access is unavailable. EasyRMM's agent must
  keep working wherever HTTPS does.

## Decision

### Wake-only
* **The connection carries signals, not work.** The server sends *wake*
  ("ask for jobs now", "check in now"), keepalives, and why it closes the
  connection. Jobs, cancellations, instructions and settings still travel
  only in the signed answers to the agent's signed HTTPS requests, the job
  poll and the heartbeat. On a wake the agent makes the request it would
  make anyway.
* **So one path delivers**, the one that is already at least once, with
  redelivery, the start check and the agent's journal (ADR-0017). A lost
  wake, a dropped connection or a hostile middlebox can delay a job; none
  can lose, forge or repeat one.
* **What it buys**: what the heartbeat answer carries arrives at once
  (a settings change, a removal, an EasyPatch install, an update asked for
  one device); a live device stops holding long polls (slice 2), removing
  most agent requests; and the console knows who is connected now.

### Full delivery: not now
* **Not planned.** Pushing signed jobs and instructions over the
  connection would save one round trip per wake, milliseconds, and cost a
  second delivery path with its own acknowledgements, redelivery and
  replay rules, agent messages signed one by one with the device key, and
  backpressure: a copy of what the poll already guarantees. Heartbeats
  stay HTTPS too.
* **Reconsidered on evidence only**: if the 10,000-agent drill shows that
  the HTTPS requests left (heartbeats and woken polls), not the
  connections, limit a server, or a feature needs the server to reach an
  agent faster than a round trip. That is an ADR of its own; the message
  envelope below has a version and types for it.

### The connection
* **`GET /api/agent/v1/connect`**, an HTTP/1.1 upgrade to a WebSocket with
  the subprotocol `easyrmm-agent.v1` and no compression, served by the
  agent API on the console's names and addresses like every agent route
  (not on MeshCentral's). The server refuses an upgrade without the
  subprotocol, so a later version can be told apart.
* **HTTP/1.1, on a connection of its own.** The agent dials it offering
  only `http/1.1`; WebSockets over HTTP/2 (RFC 8441) are not used, since
  proxies and inspecting firewalls handle HTTP/1.1 upgrades far more
  widely. It uses the same trusted roots or CA file and the same proxy as
  its HTTPS requests, so the connection takes the route the agent's
  requests take.
* **Windows and Linux agents**, the platforms where the agent runs jobs
  (`supported()` in `agent/cmd/easyrmm-agent/main.go`).

### Authentication
* **The agent's credentials, as for every request**: the upgrade carries
  `Authorization: EasyRMM-Agent device=…, ts=…, nonce=…, sig=…`, signed
  with the device key over `GET`, the path and an empty body (ADR-0015).
  Its nonce is used once and its time is within five minutes; the header
  is checked before anything else; only enrolled devices connect, not one
  removed by force (ADR-0050); the request counts against the device's
  limits.
* **Never a URL token** (proxies log URLs) **and never a cookie**: the
  route reads none, and a browser cannot set the header, so a web page
  cannot open an agent's connection on someone's session.
* **No challenge to sign.** The agent signs nothing on the connection; a
  challenge it signed could be made into a signing oracle. This replaces
  ADR-0009's signed challenge. The server proves itself in every message.

### Messages
* **Signed by the server, every one.** Text frames of JSON in the form of
  the other signed instructions, `{"payload", "signature"}`: the payload
  in base64, signed with the job key over `EASYRMM-CHANNEL-SIG-V1\n` + the
  payload. The payload has `v` (1), `type`, `deviceId`, `connId` (16
  random bytes the server issues), `seq` (1, 2, 3…), `sentAt`, and the
  type's fields.
* **Types**, all from the server:
  * `hello`, first: the nonce of the agent's own upgrade request, which
    binds the connection to it;
  * `tick`: a keepalive every 30 seconds, with the server's time;
  * `wake`: `what`, `jobs` or `checkin`, and a `reason` for the log
    (`job`, `cancel`, `settings`, `removal`, `easypatch`, `update`);
  * `closing`: a `reason` (`restart`, `refresh`, `replaced`, `removed`)
    and `reconnectWithin`, in seconds.
* **The agent closes the connection** at the first message that does not
  verify with the key it trusts, names another device or connection,
  breaks the sequence (a gap, a repeat), or exceeds 16 KiB, and when no
  `hello` arrives within 10 seconds. Nothing on the way can inject, replay
  or reorder a message; it can only end the connection, which the agent
  notices.
* **The agent sends no messages**, only WebSocket pings. The server closes
  a connection that sends one.
* **Cost**: one Ed25519 signature per message. 10,000 connections ticking
  every 30 seconds are about 330 signatures a second.
* **Rotation**: signed with a key the agent accepts at that moment, as
  ADR-0057 (proposed) settles for every signed instruction.

### Keepalives and idle timeouts
* **Both ways, every 30 seconds**: the server's signed `tick` (each
  connection at a random phase of its own, so they do not come in
  bursts), and the agent's WebSocket ping. Each side closes the connection
  after 75 seconds without hearing from the other. The agent counts only
  verified messages: a pong a middlebox makes up does not keep it.
* **Below the usual idle timeouts**: NGINX's default `proxy_read_timeout`
  and an AWS application load balancer's idle timeout are both 60
  seconds, and traffic in both directions keeps a firewall's or a NAT's
  state for each direction fresh. The guide's NGINX settings (an hour)
  pass it unchanged.
* **At most 12 hours, give or take one at random**: the server then sends
  `closing` (`refresh`), so connections authenticate again and spread
  over servers added since.
* **Sleep**: when a computer wakes, its connection is usually dead. The
  agent notices that its clock jumped past the next tick and reconnects at
  once instead of waiting 75 seconds.

### Reconnecting, with jitter
* **After a connection ends without a signed `closing`**: a random wait up
  to 30 seconds, then exponential backoff with full jitter from 5 seconds
  up to 5 minutes (the agent's `MaxRetry`).
* **After `closing`**: a random wait within `reconnectWithin`, 60 seconds
  for `restart` and 5 minutes for `refresh`. On `removed` it does not
  reconnect; its heartbeat carries the rest. On `replaced` (another
  connection opened as this device) it logs that another computer may be
  using its identity and waits up to 5 minutes.
* **After the server's `503`**: its `Retry-After`.
* **While it is not connected** the agent works as today (below).

### Server limits
* **One connection per device.** A new one replaces the old (`closing`,
  `replaced`). More than six replacements in 10 minutes refuse that
  device's upgrades for 10 minutes (409 `connection_conflict`), and the
  device shows that its identity seems to be in use on more than one
  computer (a cloned machine); its polls and heartbeats are unaffected.
* **Per device**: an upgrade at most every 10 seconds after a burst of
  six, besides the limits on every signed request (ADR-0015).
* **Per server**: at most 200 upgrades a second, so a fleet reconnecting
  after a restart cannot crowd out everything else; beyond, 503
  `channel_busy` with a random `Retry-After` of 10 to 60 seconds.
* **Connections**: `EASYRMM_AGENT_CONNECTIONS_MAX`, 10,000 by default, the
  largest fleet the drills measure. Beyond it, 503 `channel_full` with a
  random `Retry-After` of 15 to 30 minutes; those agents work as with
  regular check-ins meanwhile.
* **File descriptors**: one per connection. Compose sets the server's
  `nofile` limit to 65,536. At start the server checks that the maximum,
  plus 4,096 for everything else, fits under its limit; if not it lowers
  the maximum and says so in its log and on Settings → Agent settings.
* **Memory**: one goroutine per connection, reading; ticks from one shared
  timer, not a goroutine each; a send queue of a few messages (wakes
  coalesce, so it does not grow), and a connection whose queue fills or
  whose write takes over 10 seconds is closed. The target is under 128 KiB
  per idle connection (1.25 GiB for 10,000), a gate of the load test on CI;
  the drills record the real figure.
* **No database connection** is held by a live connection; an upgrade
  costs what any signed request costs, a lookup and a nonce.
* **Shutdown**: when the server stops, every connection gets `closing`
  (`restart`) and is closed, before the edge's own graceful shutdown
  (`shutdown` in `edge.go`, 20 seconds).
* **Removal**: a device removed (ADR-0050) or deleted, or whose key was
  replaced, has its connection closed at once (`closing`, `removed`).

### What a wake makes the agent do
* **`checkin`**: a heartbeat now, at most one every 10 seconds; the next
  regular heartbeat counts from it. Sent when something the heartbeat
  answer carries becomes due: a settings change (ADR-0058; spread over a
  minute when an organization's or the platform's changed), a removal, an
  EasyPatch install, an update asked for one device.
* **`jobs`**: a poll now. Sent when a run is queued or canceled, from
  slice 2, when a live agent stops holding long polls; in slice 1 the long
  poll is still waiting and the server wakes it itself.

### Jobs are never lost: the fallback to polling
From slice 2:

* **Jobs are delivered only by the signed poll**, as rows that stay queued
  until claimed (ADR-0017). The connection only decides when the agent
  asks.
* **Not live** (connecting, failed, fallen back, *Regular check-ins*, an
  agent of an earlier release): the agent holds long polls exactly as
  today.
* **Live** (its `hello` verified): no long poll is held. The agent polls
  without waiting (`{"noWait": true}`: the server answers at once, empty
  or not) when it connects, at each `jobs` wake, and when a heartbeat
  answer says `jobsWaiting`; and again while answers bring runs (at most 8
  come in one). `jobsWaiting` is set when the device has runs to deliver
  or cancellations to send, as the poll's claim would find them (the
  partial index `job_runs_open_idx`), and computed only for agents that
  report being live.
* **The moment the connection ends**, the agent goes back to long polls,
  without waiting to reconnect.
* **Bounds**: a lost wake delays a job until the next heartbeat at most;
  a connection that died silently, until the agent notices, 75 seconds at
  most. Redelivery after two minutes, the start check and the journal are
  unchanged.
* **Mixed versions**: `noWait` is sent only while live, which only a
  server with this channel makes possible; the heartbeat's `transport`
  report follows ADR-0058's rule for new request fields; older agents
  ignore `jobsWaiting`, as they read answers leniently.

### The transport, a setting per device
`agent.transport` (ADR-0058), with three choices, worded for technicians:

| Choice (value) | Its line in the console |
|---|---|
| **Automatic (recommended)** (`automatic`) | A live connection, so changes reach the device at once. If the network blocks it, the device checks in regularly instead and tries again every hour. |
| **Live connection** (`live`) | A live connection, retried whenever it fails. While it is down, the device checks in regularly. |
| **Regular check-ins** (`poll`) | No live connection, for networks that block or inspect them. Jobs still arrive within seconds; other changes at the next check-in. |

* **Where**: on the device's Settings tab, the owner's "device settings";
  also on its site, its organization and the platform, inherited as
  ADR-0058 says. Site Administrators and above (`device.configure`); the
  platform's value by Super Administrators.
* **Defaults**: the platform's default is *Automatic* from slice 2 on;
  in slice 1 it is *Regular check-ins*, so nothing changes until someone
  chooses another transport for a device. An agent without a document, or
  of an earlier release, uses no live connection.
* **Enforcement**: the platform or an organization may enforce a
  transport, for a customer whose security team forbids persistent
  connections, for example.
* **At once**: changed to *Regular check-ins*, the agent closes its
  connection and holds long polls again; changed from it, it connects.

### Automatic's fallback
* **A failure** is a connection attempt that fails while the agent's HTTPS
  heartbeats succeed: an upgrade refused with anything but `101` (the
  server's own `429` and `503` answers mean "later" and do not count), no
  verified `hello` within 10 seconds, a message that does not verify, or
  a connection that ends within a minute without a signed `closing`, which
  is what TLS inspection often does. An attempt while HTTPS fails too (the
  server down for an upgrade, the network out) counts for nothing: that is
  not a network blocking WebSockets.
* **Three failures in 10 minutes**: *Automatic* falls back to regular
  check-ins and tries once more after an hour, give or take 6 minutes at
  random; a connection that lasts a minute makes the device live again and
  clears the count.
* ***Live connection* never falls back**; it keeps retrying with the
  backoff above.
* **The agent reports its state** in each heartbeat (`transport`): the
  choice it applies, whether it is live and since when, whether it fell
  back and when it tries again, its failures and its last error (at most
  300 characters).

### Several servers
From slice 3:

* **Wakes through PostgreSQL.** The transaction that queues or cancels a
  run, or makes a heartbeat instruction due, calls
  `pg_notify('easyrmm_agent_wake', '<what>:<device>')`, delivered only on
  commit, so a wake never arrives before its row. A settings change
  notifies its scope (`checkin:organization:<id>`, and so on); each
  instance wakes its own matching connections.
* **Each instance listens** on one connection outside the pool, and wakes
  its long polls from it as well: a job queued on one server reaches a
  poll held on another at once. The in-process hub stays, fed by it.
* **One connection per device across instances**: an instance that
  accepts a connection notifies `replaced:<device>:<connId>`, and the
  instance holding the older one closes it; `removed:<device>` closes a
  removed device's connection wherever it is.
* **A notification lost** while an instance reconnects its listener
  delays a job until the device's next heartbeat (`jobsWaiting`); nothing
  is sent again in bulk.
* A pooler in transaction mode between EasyRMM and PostgreSQL would break
  `LISTEN`; the deployment has none, and the guide will say so.

### What the console shows
* **A device's Overview**: *Connection*: *Live since 10:42*, *Regular
  check-ins*, *Fell back to regular check-ins at 10:42: the network
  refused the live connection (HTTP 403); trying again at 11:42*,
  *Connecting: 12 attempts since 10:42 (…)*, or *This agent's version has
  no live connection*; and *Last wake*, when and why. Its Settings tab
  shows the transport with the same state under it.
* **Devices**: a *Connection* column (Live, Check-ins, Fell back,
  Connecting) and a filter for devices that fell back.
* **Settings → Agent settings** (Super Administrators): connected now, per
  server, against its maximum; upgrades refused as full or busy in the
  last hour; wakes sent in the last hour; the number of devices that fell
  back, linking to them.
* **Where it is kept**: `agent_connections`, one row per live connection
  (device, server instance, connection ID, since, last wake and why),
  written on connect, disconnect and wake; `server_instances`, where each
  instance records itself every 30 seconds, and the rows of an instance
  silent for two minutes are deleted, so a server that crashed does not
  leave devices shown as live. Both are platform tables, read by the
  device API after the device itself was read in the caller's scope. The
  agent's report goes to ADR-0058's `agent_device_state`.

### Windows and Linux
* **One implementation in Go** for both (`agent/channel`), with
  `github.com/coder/websocket`, already a dependency of the server (ISC,
  in THIRD_PARTY_NOTICES.md); it runs in the agent's Windows service, its
  systemd unit, and `run` for machines without systemd.
* **Trust and proxies as for its HTTPS**: Windows' certificate store or
  Linux's CA bundle, or the CA file; `HTTPS_PROXY` from the service's
  environment. An inspecting firewall whose root the computer trusts is
  trusted here as it is for HTTPS, which is why every message is signed.
* **Stopping the service** closes the connection normally, and the server
  forgets it at once.

## Testing
* **Unit** (`internal/agentproto`, `agent/channel`, the server's channel):
  signing and verifying; refused: forged, replayed, reordered, another
  device's, another connection's, a `hello` for another nonce, oversized;
  keepalive timeouts; backoff and jitter within their bounds; the fallback:
  what counts with HTTPS up and down, three in 10 minutes, the hourly
  retry, *Live connection* never falling back; changes of transport; sleep
  detected through an injected clock.
* **On CI's Windows runner**: the agent's channel tests (part of
  `go test ./agent/...`), and the Windows agent build against a test
  server built from the same protocol code over TLS: connect, wake, check
  in, a dropped connection, reconnect, a normal close when the service
  stops.
* **Integration** (PostgreSQL): `checkin` wakes after a settings change, a
  removal and an EasyPatch install; a removal closes the connection;
  replacements and their guard; every limit. From slice 2: a run queued
  wakes a live agent's poll at once; a job queued while the
  connection is cut is delivered by the long poll; with wakes dropped on
  purpose, by `jobsWaiting` at the next heartbeat; a hundred random cuts,
  and every run runs exactly once. From slice 3: two server instances
  on one database, a job queued on one reaching a poll and a connection
  held on the other, one connection per device across both.
* **Bundle end to end**, with real agents on host networking only, never
  bridge networking:
  * agents on *Automatic*, *Live connection* and *Regular check-ins* each
    receive a job and a settings change; the console shows their
    connection and last wake;
  * **a proxy that kills idle connections**: a CONNECT proxy written for
    the test, on the host's network, used by a second real agent through
    `HTTPS_PROXY` in its unit's environment. Go never proxies loopback
    addresses, so that agent enrolls through the host's own non-loopback
    address, which the test adds to the deployment's IP addresses. With a
    45-second idle limit the connection lasts ten minutes (the keepalives
    hold it); cutting every tunnel at 40 seconds makes *Automatic* fall
    back within 10 minutes while jobs keep arriving; cutting all tunnels
    at once loses no job;
  * **an inspecting proxy**: the same program terminating TLS with a CA
    the machine trusts, and an agent enrolled to trust the system's roots:
    it passes the connection; it refuses upgrades (fallback); it accepts
    them and holds every frame (no `hello`: fallback); it injects a wake
    (the connection closed); it cuts connections at 30 seconds (fallback);
  * **NGINX in offload mode** as the guide sets it up: live; without the
    `Upgrade` headers: fallback;
  * **a server restart** with agents live: each gets `closing`, all
    reconnect within a minute, spread; a job queued during the restart
    runs once.
* **Load**: on CI, a test opening 5,000 signed connections (devices
  written to the database with keys of their own, without enrolling; only
  connections, no heartbeats or inventories, which is what a CI runner
  cannot hold for thousands of agents), which
  measures the time to connect them, the server's memory per connection
  (the 128 KiB gate), a wake to all 5,000 (median and 99th percentile) and
  the spread of a restart's reconnections; and 500 agents of
  `tools/agentsim`, which gains `-transport`, on the bundle's deployment
  for 10 minutes with jobs. On the owner's host, 2,000 and 10,000 agents for
  an hour on each transport, recorded in `drills.md` beside the existing
  2,000-agent run: requests, nonce rows, CPU and memory.
* **Then the owner's instance**: one device set to *Live connection*
  first, then the platform's default.

## Slices
After ADR-0057 and ADR-0058's three slices. Each merges and is verified on
its own:

1. **The channel, beside the long poll.** The route, the signed messages,
   the limits, shutdown and removal, `agent_connections` and
   `server_instances`; the agent's client with its keepalives,
   reconnection and the fallback; `agent.transport`, *Regular check-ins*
   by default; `checkin` wakes; the agent's report; the device's
   *Connection* and *Last wake*; `agentsim -transport`. The long poll is
   untouched. Verified by unit, Windows, integration and bundle tests and
   the CI load test.
2. **The live connection replaces the held poll.** `jobs` wakes, `noWait`,
   `jobsWaiting`, polls on connect and on wakes, long polls again the
   moment the connection ends; *Automatic* becomes the default; the
   *Connection* column and its filter, Settings → Agent settings. Verified
   by the tests that jobs survive cuts and lost wakes, the bundle again,
   and the drills.
3. **Several servers**: wakes and long polls through `LISTEN` and
   `NOTIFY`, one connection per device across instances. Verified by the
   two-instance integration tests.

## Consequences
* Changes reach a live device at once; the server stops holding its polls
  and knows that it is connected.
* Jobs keep one path. The channel can delay a job but not lose, forge or
  repeat one, and a device whose network blocks WebSockets loses nothing
  but promptness for what the heartbeat carries.
* Every transport keeps the HTTPS heartbeat at the device's interval, and
  online stays based on it (ADR-0058): a dropped connection alone never
  makes a device offline. The plan's 10-minute heartbeat for *Live
  connection* is not needed.
* Each live device holds a connection and a file descriptor on a server;
  how many is a setting, 10,000 by default.
* ADR-0009 is refined: the WebSocket is an optional channel that wakes the
  agent, authenticated by the signed upgrade, not a signed challenge; the
  signed poll and heartbeat stay the primary channel. Full delivery over
  the connection, and heartbeats over it, are not built.
