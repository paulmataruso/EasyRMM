# ADR-0059: The agent's WebSocket channel

* Status: Proposed (2026-11-21). Not implemented.
* Revised 2026-11-21 after an independent review: features the server
  lists, what *Automatic* counts as a failure, several servers before the
  held poll is dropped, presence confirmed by the heartbeat, descriptors
  and NGINX, the hold, what ADR-0057 must provide, and tests. Revised
  again after its second check: a new connection replaces a confirmed one
  only once confirmed itself, times compared on the agent's clock, a
  clone guard that fires, crashes told apart by the server's instance,
  404 as "not supported", and message types sent only to agents that
  list them. Revised a third time after the final check: which heartbeats
  confirm, conflicts defined by order and by pings, open feature lists,
  a stop after repeated unlisted messages, and metrics on extra
  heartbeats.
* Refines: [ADR-0009](0009-agent-protocol.md) (its WebSocket, "authenticated
  by a signed challenge", as the primary channel) and
  [ADR-0017](0017-scripts-and-jobs.md) (job delivery: the signed poll stays
  the only way jobs reach an agent, and a job queued on one server
  instance still reaches a device whose poll another holds promptly,
  l. 73–75).
* Builds on: ADR-0009 (amended, PR #52: protocol levels and listed
  features), [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (signed
  requests), [ADR-0050](0050-removing-a-device.md) (removal),
  [ADR-0052](0052-the-host-updater.md) (the hold),
  [ADR-0058](0058-signed-settings-that-reach-the-agent.md) (signed
  settings: the transport is one), and ADR-0057 (proposed: rotating the
  job key; what this ADR needs from it is under *What this needs from
  ADR-0057*).
* Part of [the feature plan](../feature-plan.md): feature 8.

## Context
The owner asked to "implement websockets", with "the user" choosing "in the
device settings what they want to use".

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
* **Redelivery is found by the next poll.** A run delivered but not
  started is due again after two minutes (`RedeliverAfter`), a
  cancellation every minute (`CancelResend`); `claim` in `delivery.go`
  finds both when the device next polls. The sweeper runs every 30
  seconds (`SweepInterval`).
* **Everything else waits for the heartbeat.** Agent updates (ADR-0027),
  the EasyPatch agent's install (ADR-0031), an uninstall (ADR-0050) and,
  with ADR-0058, settings travel in the heartbeat answer, at the device's
  interval (`agent/runner/runner.go`; 60 seconds today, 30 to 300 with
  ADR-0058).
* **Held polls are most of the traffic.** Each is a signed request whose
  nonce is written to PostgreSQL (`FinishSigned` in
  `server/internal/agents/signed.go`) and a claim transaction
  (`claim` in `delivery.go`). The 2,000-agent hour made 287,866 long polls
  and 119,785 heartbeats; agent nonces were the largest table.
* **Presence is a guess**: a device is online if it reported within three
  minutes (`devices.AgentOnlineWindow`; with ADR-0058, three of its own
  intervals), whatever happened since.
* **Several servers**: the hub is in-process (`hub.notify` after a job is
  queued, `server/internal/jobs/jobs.go`), so a job queued on one instance
  reaches a poll held on another only when that poll ends, up to 25
  seconds later, as ADR-0017 says.
* **Requests evolve by level** (ADR-0009, amended, PR #52). A poll's body
  is `PollRequest`, an empty struct (`internal/agentproto/jobs.go`); a
  server of level 1 refuses `{"noWait": true}` with 400 (`decode` in
  `server/internal/httpapi/agentapi/agentapi.go` before PR #52), and the
  worker only backs off after a failed poll (`Run` in
  `agent/jobs/worker.go`). A level-2 server ignores the field. Either way
  an agent that stopped holding long polls because it believed the server
  answered `noWait` would receive no job; where the agent's behaviour
  depends on a server feature, the server must list it.
* **The edge** (`server/internal/app/edge.go`) offers `h2` and
  `http/1.1`, has a 10-second header timeout and no read timeout, since it
  carries long polls and WebSockets (`bodyTimeout` in
  `server/internal/httpapi/agentapi/agentapi.go`). `http.Server.Shutdown`
  neither closes nor waits for hijacked connections such as WebSockets
  (net/http's documentation), so their own code must close them.
* **The hold** (ADR-0052): while the updater's hold exists, the server
  answers its health check and nothing else. PR #51 implements it as a
  file, `/run/easyrmm-updater/hold`, looked at every second, and answers
  every other request 503 with the code `held` and `Retry-After: 60`
  (`server/internal/updater/hold.go` on its branch). It gates requests; a
  connection hijacked before the hold outlives it unless closed.
* **A crashed server is back in seconds**: Compose restarts it
  (`restart: unless-stopped` on the server in
  `deploy/docker-compose.yml`), without a hold and without a `closing`
  to anyone.
* **Descriptors per device, before any channel**: MeshAgent's WebSocket
  into the edge and the gateway's own to MeshCentral (`agentRoutes` and
  the proxy in `server/internal/remote/gateway.go`), the agent's HTTPS
  connection (its client tries HTTP/2, so heartbeats and polls share it)
  and, in offload mode, NGINX's upstream connections for requests in
  flight, a held poll among them: about four per device in the server.
  NGINX holds every proxied connection twice, as a client and an upstream
  connection, and the guide sets neither `worker_connections` (NGINX's
  default is 512, the Debian and Ubuntu packages' configuration 768) nor
  `worker_rlimit_nofile` (`docs/deployment/nginx.md`). Compose sets no
  `ulimits` for the server (`deploy/docker-compose.yml`); Go raises the
  soft `RLIMIT_NOFILE` to the hard limit at start, so a fixed `nofile`
  there could lower it.
* **Suspend stops the monotonic clock** on Linux: Go's timers run on it, so
  a 75-second timer armed before a suspend fires 75 seconds of awake time
  later.
* **Agents pin no TLS key**: they trust the system's roots or a CA file,
  and their HTTP client clones Go's default transport, so it follows
  `HTTPS_PROXY` from the service's environment (`agent/client/client.go`).
  TLS-inspecting firewalls at MSPs' customers read everything; some refuse
  WebSocket upgrades, some accept them and then hold or cut the
  connection. Connections cannot be bound to TLS: in offload mode NGINX
  terminates it (`docs/deployment/nginx.md`).
* **The signed request covers the request, not a connection.** The
  device signs the method, the path, the time, a nonce and the body's hash
  (`message` in `internal/agentproto/agentproto.go`); the nonce is used
  once and the time is good for five minutes (`FinishSigned`).
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
  one device); a live device stops holding long polls (slice 3), removing
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

### Features the server lists
Every change follows ADR-0009 (amended, PR #52); nothing here has a
fallback of its own, and no 400 is read as "not supported".

* **The server lists its features** in every heartbeat answer
  (`features`) and in `hello`. The list is open: an agent ignores names
  it does not know.
  * `channel`: the route below exists. The agent connects only while its
    last heartbeat answer listed it, so it opens no connection before a
    successful heartbeat in its process, and none to a server rolled back
    to a release without the channel;
  * `poll.noWait` (from slice 3): the poll takes `noWait`, and heartbeat
    answers carry `jobsWaiting`. A live agent stops holding long polls
    only while its connection's `hello` listed it.
* **The server names its instance**: heartbeat answers and `hello` carry
  `instance`, the ID the instance draws at every start (`server_instances`,
  below), so the agent can tell a server that restarted from one that is
  still serving (*Automatic's fallback*).
* **404 means "not supported here"** (ADR-0009): an upgrade answered 404
  counts as nothing, and the agent does not connect again until a
  heartbeat made after the 404 lists `channel`.
* **The agent's new fields** (`transport` in the heartbeat, `noWait` in
  the poll) were added after level 2, so it sends them only while its last
  heartbeat answer was of level 2 or higher; a level-2 server without the
  feature ignores them and holds the poll as today.
* **The channel's messages go only to agents that list them**, like any
  signed instruction (ADR-0009). The agent lists `channel.v1` in its
  signed report's `accepts` (ADR-0058's `capabilities`): the four types
  below, with `v` 1 and the values of `what` and `reason` this ADR names.
  A later type or value comes with a capability of its own (`channel.v2`,
  or one named for it), and the server sends it only to agents that list
  it. So the agent connects only once a heartbeat that carried its
  report, the second of its process at the earliest (ADR-0058), was
  answered listing `channel`; the server refuses an upgrade from a device
  whose last report lists no `channel.v1` with 404.
* **The transport** reaches the agent in ADR-0058's document, which goes
  only to agents that report taking it.

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
* **Budgets are spent only by verified upgrades**: the device's limits, as
  for every signed request (ADR-0015), and the server's 200 upgrades a
  second (below), so upgrades naming devices they cannot sign for crowd
  no one out.
* **Never a URL token** (proxies log URLs) **and never a cookie**: the
  route reads none, and a browser cannot set the header, so a web page
  cannot open an agent's connection on someone's session.
* **No challenge to sign.** The agent signs nothing on the connection; a
  challenge it signed could be made into a signing oracle. This replaces
  ADR-0009's signed challenge. The server proves itself in every message;
  the agent proves the connection is its own in its signed heartbeat
  (below).

### Presence confirmed by the heartbeat
The upgrade's signature does not cover the connection, and the agent
signs nothing after it. Something on the path that holds back one upgrade
request (good for five minutes; the first use wins) could open the
connection as the device and keep it until its refresh, up to 13 hours,
while the real agent's own attempt is refused as `replayed`. So:

* **The agent reports the connection it holds** in its signed heartbeat's
  `transport` report: the `connId` from `hello` and when the connection
  began. After a `hello` the agent checks in at once (within the
  `checkin` limit, below), so a real connection is confirmed within
  seconds. The agent closes its old connection, and stops pinging it,
  before it opens a new one, so it never holds two.
* **Which heartbeats count.** A heartbeat without `transport` (the first
  of a process, ADR-0009) neither confirms nor contradicts. The device's
  heartbeats are taken in the order of their signed times: one signed
  before the last heartbeat processed for the device confirms and
  contradicts nothing, though it may show a conflict (*Server limits*).
* **Only a confirmed connection is live.** The console shows *Live* only
  for an `agent_connections` row that the device's heartbeat confirmed;
  `jobsWaiting` (slice 3) is computed for the same.
* **A new connection is pending until confirmed.** It gets its `hello`
  and ticks but no wakes; the device's confirmed connection, if it has
  one, keeps carrying them and is not replaced. Only when a heartbeat
  names the new one does it become the device's connection, and the old
  one is replaced (`closing`, `replaced`). The agent checks in at once
  after a `hello`, so a real connection waits seconds for its first
  wake; a wake due meanwhile reaches it through `jobsWaiting` or the
  heartbeat itself. An upgrade replayed by something on the path, even
  within its five minutes, therefore evicts no one: the real agent's next
  heartbeat names its own connection and the replayed one is closed
  (next point).
* **A contradicted connection is closed.** A heartbeat contradicts a
  connection when it does not name it (it names another `connId`, or
  none) although it was signed more than 60 seconds after the
  connection's upgrade request was. Both times are the agent's own, from
  the two signed requests, so a clock off by up to the five minutes the
  server allows (`Fresh` in `internal/agentproto`, checked in
  `signed.go`), or a heartbeat delayed on the way, cannot make a real
  connection look contradicted; the 60 seconds cover the agent's wait for
  the `101` and the `hello`. A pending connection that is contradicted is
  closed at once. A confirmed one is sent nothing for up to 40 seconds,
  then `closing` (`replaced`): if it pinged meanwhile (as the clone guard
  counts pings, below), a live agent holds it while the device's
  heartbeat says otherwise, which is the clone guard's business; if not,
  it was dead. A connection no
  heartbeat confirms within two of the device's intervals is closed too.
* **`replayed` is a warning sign.** An upgrade answered 401 `replayed`
  means someone else used the agent's request: the agent logs it and
  reports it in its heartbeat, the device shows it, and under *Automatic*
  it is a failure (below).
* **The clone guard counts only conflicts between confirmed connections**
  (below).

### Messages
* **Signed by the server, every one.** Text frames of JSON in the form of
  the other signed instructions, `{"payload", "signature"}`: the payload
  in base64, signed with the job key over `EASYRMM-CHANNEL-SIG-V1\n` + the
  payload. The payload has `v` (1), `type`, `deviceId`, `connId` (16
  random bytes the server issues), `seq` (1, 2, 3…), `sentAt`, and the
  type's fields.
* **Types** (`channel.v1`), all from the server:
  * `hello`, first: the nonce of the agent's own upgrade request, which
    binds the connection to it, the server's `features` and its
    `instance`. It is sent at once after the `101`, before the server
    writes anything for the connection (its `agent_connections` row, the
    clone guard's count): a
    slow database can delay the upgrade's answer, which costs what any
    signed request costs (reading the device, writing its nonce), but
    never a `hello` after it;
  * `tick`: a keepalive every 30 seconds, with the server's time;
  * `wake`: `what`, `jobs` or `checkin`, and a `reason` for the log
    (`job`, `cancel`, `redeliver`, `settings`, `removal`, `easypatch`,
    `update`);
  * `closing`: a `reason` (`restart`, `refresh`, `replaced`, `removed`)
    and `reconnectWithin`, in seconds.
* **The agent closes the connection** at the first message that does not
  verify with the keys it trusts, names another device or connection,
  breaks the sequence (a gap, a repeat), or exceeds 16 KiB, and when no
  `hello` arrives within 10 seconds of the `101`. Nothing on the way can
  inject, replay or reorder a message; it can only end the connection,
  which the agent notices. A verified message of a type, `v` or value
  the agent did not list is a server's bug, not the network's: the agent
  closes the connection, reports it, and counts nothing. After three such
  refusals from one `instance`, it stops connecting until a heartbeat
  answer names another instance or its own build changes, and reports
  why; the device meanwhile works as with regular check-ins.
* **The agent sends no messages**, only WebSocket pings. The server closes
  a connection that sends one.
* **Cost**: one Ed25519 signature per message. 10,000 connections ticking
  every 30 seconds are about 330 signatures a second.
* **Keys**: signed, per device, with a key that device reported
  (*What this needs from ADR-0057*).

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
* **Sleep**: when a computer wakes, its connection is usually dead. Every
  5 seconds the agent compares how far the wall clock moved
  (`time.Now().Round(0)`, which drops the monotonic reading) with the
  monotonic time elapsed; when the wall clock moved more than 30 seconds
  further, the computer slept, and the agent reconnects at once instead of
  waiting out its 75 seconds. A wall clock stepped by NTP triggers the
  same check: one needless reconnect, which is not counted as a failure.

### Reconnecting, with jitter
* **After a connection ends without a signed `closing`**: a random wait up
  to 30 seconds, then exponential backoff with full jitter from 5 seconds
  up to 5 minutes (the agent's `MaxRetry`).
* **After `closing`**: a random wait within `reconnectWithin`, 60 seconds
  for `restart` and 5 minutes for `refresh`. On `replaced` (another
  connection opened as this device) it logs that another computer may be
  using its identity and waits up to 5 minutes.
* **On `removed`** it does not reconnect while its heartbeat answers carry
  an uninstall; its heartbeat carries the rest. A removal can be canceled
  while nothing was confirmed (ADR-0050), so once a heartbeat answer
  carries none, it reconnects as after any end.
* **After the server's own `429` or `503`**, one with the server's code
  (`rate_limited`, `channel_busy`, `channel_full`, `held`): its
  `Retry-After`, at most 30 minutes, since the header is not signed. A
  `429` or `503` without one of those codes is treated like any other
  refusal.
* **After a `404`**: no attempt until a heartbeat made after it lists
  `channel` (*Features the server lists*). Something on the path that
  answers 404 to every upgrade therefore gets one attempt per heartbeat,
  counted as nothing; the device meanwhile works as with regular
  check-ins.
* **While it is not connected** the agent works as today (below).

### Server limits
* **One connection per device**, and at most one pending beside it. A
  confirmed connection is replaced only by one a heartbeat confirmed
  (*Presence confirmed by the heartbeat*); a newer pending one replaces an
  older pending one.
* **The clone guard.** One agent's heartbeats move only forward, in
  their signed times and in the connections they name: it sends one
  heartbeat at a time, and closes a connection before it opens the next.
  Two computers with one identity each hold a connection and each
  heartbeat on its own clock, so the device's heartbeats keep going back
  and forth. A **conflict** is either of:
  * two heartbeats processed within one of the device's intervals that
    name two different connections out of order: the one processed
    later was signed earlier, or names the older connection;
  * a confirmed connection that pings after a heartbeat contradicted it
    (above), by naming another connection or none: a ping that arrives
    at least 5 seconds after the contradiction, so not one already on
    its way, and before that connection sent any close frame. A
    half-open connection, which can last 75 seconds after a network
    change, never pings, and an agent closes its old connection before
    opening a new one, so one agent reconnecting counts nothing.

  Nothing about a pending connection counts, so a replayed upgrade or an
  agent reconnecting after a network change is never a conflict. The
  conflicts are counted in the database (ADR-0058's
  `agent_device_state`), so the count holds across server instances and
  restarts. **Three in 30 minutes** refuse that device's upgrades for 30
  minutes (409 `connection_conflict`), and the device shows that its
  identity seems to be in use on more than one computer (a cloned
  machine); its polls and heartbeats are unaffected. Two clones take the
  connection from each other at most five minutes apart (the wait after
  `replaced`), each time a conflict, so they are flagged within about
  fifteen minutes, usually sooner.
* **Per device**: an upgrade at most every 10 seconds after a burst of
  six, besides the limits on every signed request (ADR-0015).
* **Per server**: at most 200 verified upgrades a second, so a fleet
  reconnecting after a restart cannot crowd out everything else; beyond,
  503 `channel_busy` with a random `Retry-After` of 10 to 60 seconds.
* **Per organization**: at most the live connections the platform allows
  it (ADR-0058's limits; none but the server's by default); beyond, 503
  `channel_full`.
* **Connections**: `EASYRMM_AGENT_CONNECTIONS_MAX`, 10,000 by default, the
  largest fleet the drills measure. Beyond it, 503 `channel_full` with a
  random `Retry-After` of 15 to 30 minutes; those agents work as with
  regular check-ins meanwhile.
* **File descriptors, measured, on Linux.** A live device costs the
  server one descriptor more than the four or so it already holds. On
  Linux, where the deployment runs, the server reads its soft
  `RLIMIT_NOFILE` (raised by Go to the hard limit) and counts the
  descriptors it has open (`/proc/self/fd`, every 5 seconds, plus the
  connections accepted since), and refuses upgrades with 503
  `channel_full` while fewer than the larger of 4,096 and a quarter of the
  limit remain, whatever the maximum says. Compose keeps setting no
  `ulimits`, so the hard limit the container gets is not lowered. The
  server logs when this gate closes and opens; Settings → Agent settings
  shows the descriptors open against the limit. The server built for
  Windows, which only the Windows test harness runs, has neither
  `RLIMIT_NOFILE` nor `/proc`: there the configured maximum is the only
  bound, and the console says the descriptors are not measured.
* **NGINX in offload mode** holds about six descriptors per device with a
  live connection: MeshAgent's WebSocket, the agent's HTTPS requests in
  flight and its live connection, each as a client and an upstream
  connection. The guide sets `worker_connections` to at least six per
  device (one worker may take most connections) and
  `worker_rlimit_nofile` above it, with the figures for 1,000 and 10,000
  devices; slice 3's release note, which makes *Automatic* the default,
  says so.
* **Memory**: one goroutine reading and one writing per connection; ticks
  come from one shared timer, which only puts a tick on each connection's
  queue, never blocking; the queue holds a few messages (wakes coalesce,
  so it does not grow), and a connection whose queue is full, or whose
  write takes over 10 seconds, is closed. A stalled peer holds up only its
  own writer. The target is under 128 KiB per idle connection, both
  goroutines' stacks included (1.25 GiB for 10,000), a gate of the load
  test on CI; the drills record the real figure.
* **No database connection** is held by a live connection.
* **Shutdown and the hold**: when the server stops, and when the updater's
  hold appears while it runs (ADR-0052; PR #51 looks for the file every
  second), every connection gets `closing` (`restart`) and is closed, on
  shutdown before the edge's own graceful shutdown (`shutdown` in
  `edge.go`, 20 seconds). Upgrades during a hold get 503 `held`.
* **Removal**: a device removed (ADR-0050) or deleted, or whose key was
  replaced, has its connection closed at once (`closing`, `removed`).

### What a wake makes the agent do
* **`checkin`**: a heartbeat now, at most one every 10 seconds; the next
  regular heartbeat counts from it. Like every extra heartbeat in this
  ADR (after a `hello`, on a wake, to classify a failure), it carries
  `metrics` only if 0.8 of the interval has passed since the last
  heartbeat that did (ADR-0058), and then always: wakes, a connection cut
  every 90 seconds on *Live connection* (which never falls back), or
  settings written again and again move the regular schedule but never
  stop metrics. Sent when something the heartbeat
  answer carries becomes due: a settings change (ADR-0058), a removal, an
  EasyPatch install, an update asked for one device. **Every `checkin`
  wake goes through one queue per server**, at most 100 a second, a
  device queued again before its wake went out woken once; a change that
  reaches more than 100 devices (the platform's, an organization's, a
  large site's) is also spread over at least a minute.
* **`jobs`**: a poll now. Sent when a run is queued or canceled, from
  slice 3, when a live agent stops holding long polls; before, the long
  poll is still waiting and the server wakes it itself. A `jobs` wake
  that arrives while a `noWait` poll is in flight makes the agent poll
  again as soon as that one is answered, since the run may have been
  queued after its claim.
* **Redeliveries wake too** (slice 3): every 30 seconds the sweep sends a
  `jobs` wake (`redeliver`) to each live device with a run due again
  (`RedeliverAfter`) or a cancellation due to be sent again
  (`CancelResend`), since a live device holds no poll that would find
  them.

### Jobs are never lost: the fallback to polling
From slice 3:

* **Jobs are delivered only by the signed poll**, as rows that stay queued
  until claimed (ADR-0017). The connection only decides when the agent
  asks.
* **Not live** (connecting, failed, fallen back, *Regular check-ins*, an
  agent of an earlier release, or a connection whose `hello` did not list
  `poll.noWait`): the agent holds long polls exactly as today.
* **Live** (its `hello` verified and listing `poll.noWait`): no new long
  poll is held. The long poll in flight when the connection comes up is
  left to finish, never canceled: an answer canceled after its claim would
  leave its runs `sent` until redelivery. The agent then polls without
  waiting (`{"noWait": true}`: the server answers at once, empty or not),
  at each `jobs` wake, and when a heartbeat answer says `jobsWaiting`;
  and again while answers bring runs (at most 8 come in one).
  `jobsWaiting` is set when the device has runs to deliver or
  cancellations to send, as the poll's claim would find them (the partial
  index `job_runs_open_idx`), and computed only for devices whose
  heartbeat confirms a live connection.
* **The moment the connection ends**, the agent goes back to long polls,
  without waiting to reconnect.
* **Bounds, for a live device**: a lost wake delays a job until the
  device's next heartbeat (`jobsWaiting`), one interval, 5 minutes at
  the longest; a lost poll answer, until its runs are due again and the
  next sweep wakes the device, about two and a half minutes (a lost
  cancellation, about one and a half), or one interval more if that wake
  is lost too; a connection that died silently, until the agent notices,
  75 seconds at most, sooner after a sleep. Redelivery, the start check
  and the journal are unchanged.
* **Mixed versions**: `noWait` is sent only on a connection whose `hello`
  listed `poll.noWait`, so a current agent live on a server of slice 1 or
  2 holds long polls as before; older agents ignore `jobsWaiting`, as
  they read answers leniently.

### The transport, a setting per device
`agent.transport` (ADR-0058), with three choices, worded for technicians:

| Choice (value) | Its line in the console |
|---|---|
| **Automatic (recommended)** (`automatic`) | A live connection, so changes reach the device at once. If the network blocks it, the device checks in regularly instead and tries again every hour. |
| **Live connection** (`live`) | A live connection, retried whenever it fails. While it is down, the device checks in regularly. |
| **Regular check-ins** (`poll`) | No live connection, for networks that block or inspect them. Jobs still arrive within seconds; other changes at the next check-in. |

* **Where**: on the device's Settings tab, the owner's "device settings";
  also on its site, its organization and the platform, inherited as
  ADR-0058 says.
* **Who**: on one device, technicians and above (`device.edit`, decided
  in review after the owner's "the user can choose in the device
  settings"); at a site or an
  organization, Site Administrators and above (`device.configure`); the
  platform's value, Super Administrators. A value enforced above the
  device wins over a technician's.
* **Defaults**: the platform's default is *Automatic* from slice 3 on;
  before, it is *Regular check-ins*, so nothing changes until someone
  chooses another transport for a device. An agent without a document, or
  of an earlier release, uses no live connection.
* **Enforcement**: the platform or an organization may enforce a
  transport, for a customer whose security team forbids persistent
  connections, for example.
* **At once**: changed to *Regular check-ins*, the agent closes its
  connection and holds long polls again; changed from it, it connects.

### Automatic's fallback
* **What fails.** An attempt fails when the upgrade is refused with
  anything but `101` (but for the server's own "later" answers below and
  a `404`, which means "not supported here" and counts nothing), no `101`
  comes within 30 seconds or no verified `hello` within 10 seconds after
  it, a message does not verify, or the upgrade is answered `replayed`. A
  connection fails when it ends without a signed `closing`, whatever its
  age, the agent's own close after 75 silent seconds included. Ends the
  agent causes for its own reasons (a sleep it detected, a change of
  transport, the service stopping, a message of a type it did not list)
  do not fail.
* **Counted only against a server still serving.** Each failure is
  classified by a signed heartbeat made after it: at once, or, when the
  agent made one in the last 10 seconds, as soon as those 10 seconds have
  passed. A heartbeat made before the failure never classifies it. The
  failure counts only if that heartbeat succeeds and its answer names
  the same `instance` as the server the agent was dealing with: the
  `hello`'s, for a connection that ended; the last heartbeat answer's
  before the attempt, for an attempt that failed. A heartbeat that fails
  (the server down, the network out) or names another instance (the
  server restarted, after a crash as after a stop: Compose brings a
  crashed server back within seconds) counts nothing.
* **Several instances behind one name**: a heartbeat may reach another
  instance than the connection did, and then counts nothing, so
  *Automatic* falls back more slowly there, never because of a restart.
* **Nothing counts across a restart or a hold.** After a `closing`
  (`restart`), and after any answer `held`, nothing counts until the first
  heartbeat that succeeds after it. With the instance check, a stopped
  or crashed server, an upgrade's backup of minutes (ADR-0052), a held
  start and the rush of reconnections after any of them never move the
  fleet to regular check-ins; when the server is back, `hello` goes out
  before any write.
* **"Later" answers.** A `429` or `503` with the server's code
  (`rate_limited`, `channel_busy`, `channel_full`, `held`) means "later":
  not a failure, its `Retry-After` honoured up to 30 minutes. A middlebox
  can copy those codes, so three "later" answers in a row count as one
  failure. A `429` or `503` without them is a refusal like any other.
* **Three counted failures within 30 minutes**: *Automatic* falls back to
  regular check-ins and tries once more after an hour, give or take 6
  minutes at random, with a new count. Counting over 30 minutes, not by a
  connection's age, catches a box that cuts every connection after a few
  minutes or holds its frames after `hello` (cutting at 90 seconds: fallen
  back within about 5 minutes); a connection that ends less often than
  that costs a reconnect now and then.
* **During a declared key rotation** (ADR-0057) a message that does not
  verify still ends the connection, but counts nothing.
* ***Live connection* never falls back**; it keeps retrying with the
  backoff above.
* **The agent reports its state** in each heartbeat (`transport`): the
  choice it applies, whether it is live, since when and the `connId`,
  whether it fell back and when it tries again, its failures, its last
  error (at most 300 characters), the last `replayed` and the last
  message it refused as unlisted.

### Several servers
From slice 2, before a live device stops holding its long poll (slice 3),
so that ADR-0017's promise holds at every slice: a job queued on one
instance reaches a device whose poll another holds at once.

* **Wakes through PostgreSQL.** The transaction that queues or cancels a
  run, or makes a heartbeat instruction due, calls
  `pg_notify('easyrmm_agent_wake', '<what>:<device>')`, delivered only on
  commit, so a wake never arrives before its row. A settings change
  notifies its scope (`checkin:organization:<id>`, and so on); each
  instance wakes its own matching connections, spread as above.
* **Each instance listens** on one connection outside the pool, and wakes
  its long polls from it as well. The in-process hub stays, fed by it.
* **One connection per device across instances**: an instance on which a
  heartbeat confirms a connection, or contradicts one, notifies
  `confirmed:<device>:<connId>` or `contradicted:<device>:<connId>`, and
  the instance holding the connection concerned applies the rules above,
  the clone guard's included;
  `removed:<device>` closes a removed device's connection wherever it is.
* **A notification lost** while an instance reconnects its listener
  delays a job until the device's next long poll (25 seconds) or, for a
  live device, its next heartbeat (`jobsWaiting`); nothing is sent again
  in bulk.
* A pooler in transaction mode between EasyRMM and PostgreSQL would break
  `LISTEN`; the deployment has none, and the guide will say so.

### What the console shows
* **A device's Overview**: *Connection*: *Live since 10:42* (confirmed
  only), *Regular check-ins*, *Fell back to regular check-ins at 10:42:
  the network refused the live connection (HTTP 403); trying again at
  11:42*, *Connecting: 12 attempts since 10:42 (…)*, *Someone else used
  this device's connection request at 10:42*, or *This agent's version
  has no live connection*; and *Last wake*, when and why. Its Settings tab
  shows the transport with the same state under it.
* **Devices**: a *Connection* column (Live, Check-ins, Fell back,
  Connecting) and a filter for devices that fell back.
* **Settings → Agent settings** (Super Administrators): connected now, per
  server, against its maximum and its descriptor limit; upgrades refused
  as full or busy in the last hour; wakes sent in the last hour; the
  devices that fell back and those flagged as cloned, linking to them.
* **Where it is kept**: `agent_connections`, one row per connection
  (device, server instance, connection ID, since, when a heartbeat
  confirmed it, last wake and why), written after `hello`, on
  confirmation, disconnect and wake; `server_instances`, where each
  instance records itself every 30 seconds under an ID it draws anew at
  every start, the `instance` its answers carry. An instance deletes its
  own rows when it stops; the rows of an instance silent for two minutes
  are deleted by any instance. A
  crashed instance's rows show no one as live meanwhile, since *Live*
  needs the device's heartbeat to confirm the connection. Both are
  platform tables, read by the device API after the device itself was
  read in the caller's scope. The agent's report and the clone guard's
  count go to ADR-0058's `agent_device_state`. `database.md` gains their
  entries with the slice that adds them.

### Windows and Linux
* **One implementation in Go** for both (`agent/channel`, new), with
  `github.com/coder/websocket`, already a dependency of the server (ISC,
  in THIRD_PARTY_NOTICES.md); it runs in the agent's Windows service, its
  systemd unit, and `run` for machines without systemd.
* **Trust and proxies as for its HTTPS**: Windows' certificate store or
  Linux's CA bundle, or the CA file; `HTTPS_PROXY` from the service's
  environment. An inspecting firewall whose root the computer trusts is
  trusted here as it is for HTTPS, which is why every message is signed.
* **Stopping the service** closes the connection normally, and the server
  forgets it at once.

### What this needs from ADR-0057
The channel's messages are signed with the job key. ADR-0057 (proposed, in
its own review) must provide, and slice 1 does not start until it does:

* agents report the key IDs (ADR-0057's generations) they accept, in their
  signed heartbeat;
* the server signs, per device, with a key that device reported: its
  channel messages as its instructions and ADR-0058's documents;
* the agent applies a hand-over before anything else in an answer;
* the channel opens only after a successful heartbeat in the agent's
  process (so the agent's keys are reported first; *Features the server
  lists* makes it so);
* at a cut-over the server sends `closing` (`refresh`) to live
  connections, spread over its 5 minutes, so each reconnects under the
  key it now trusts;
* messages that fail verification during a declared transition do not
  count as *Automatic*'s failures (above).

## Testing
* **Unit** (`internal/agentproto`, `agent/channel`, the server's channel):
  signing and verifying; refused: forged, replayed, reordered, another
  device's, another connection's, a `hello` for another nonce, oversized;
  keepalive timeouts; backoff and jitter within their bounds;
  `Retry-After` capped; the fallback: each failure classified by a
  heartbeat made after it (HTTPS up, HTTPS down, the same instance,
  another instance), never by one made before, the next one waiting out
  its 10 seconds; nothing counted after `closing` (`restart`) or `held`
  until a heartbeat succeeds; a `404` counting nothing and stopping
  attempts until a later heartbeat lists `channel`; "later" with and
  without the server's codes and three in a row as one failure; every end
  counted whatever its age, the agent's own ends not counted; a verified
  message of an unlisted type closing the connection and counting
  nothing; three in 30 minutes, the hourly retry, *Live connection* never
  falling back; changes of transport; sleep detected from the wall and
  monotonic clocks, both injected; connecting only after a heartbeat with
  the agent's report was answered listing `channel`; `noWait` only when
  `hello` lists `poll.noWait`; the long poll in flight left to finish; a
  wake during a `noWait` poll making another; feature names the agent
  does not know ignored; three unlisted messages from one instance
  stopping connections until the instance or the build changes; the old
  connection closed, its pings stopped, before a new one opens; `metrics`
  still arriving about once an interval with `checkin` wakes every half
  interval, and with a connection cut every 90 seconds on *Live
  connection*.
* **On CI's Windows runner**: the agent's channel tests, part of
  `go test ./agent/...`. **Windows end to end** through the Windows
  harness the plan builds (the server built for Windows with the runner's
  PostgreSQL, a Windows agent enrolling; "Test harnesses to build"):
  connect, wake, check in, a dropped connection, reconnect, a normal close
  when the service stops. Until the harness exists, the Windows paths are
  marked unverified in IMPLEMENTATION_STATUS; no test server built from
  the protocol code stands in for it.
* **Integration** (PostgreSQL): `checkin` wakes after a settings change, a
  removal and an EasyPatch install, spread above 100 devices; a removal
  closes the connection, and a canceled one lets it reconnect; a hold
  closes every connection with `restart`; `hello` sent with the database
  slowed on purpose; `checkin` wakes merged per device in the queue; a
  connection never confirmed is never *Live* and gets no wakes; a pending
  connection never replacing a confirmed one, and one a heartbeat
  contradicts closed; the contradiction judged on the agent's clock, with
  that clock four minutes ahead and behind and a heartbeat delayed a
  minute on the way, never closing a real connection; the clone guard:
  two simulated agents with one identity flagged within 15 minutes, with
  their clocks the same and minutes apart, one agent reconnecting after
  network changes and half-open connections never flagged, a ping within
  5 seconds of a contradiction or after a close frame not counted, a
  replayed upgrade never counted, the count across two instances; a
  heartbeat without `transport`, or signed before the last one
  processed, neither confirming nor contradicting; the per-server budget untouched by unverified upgrades;
  upgrades refused with 404 for a device whose report lists no
  `channel.v1`, and no type sent that the report does not list; every
  limit, the descriptor gate with a lowered `RLIMIT_NOFILE` (on Linux),
  the per-organization cap; a restarted instance's stale rows showing no
  one live. From slice 2: two server instances on one database, a job queued
  on one reaching a long poll held on the other at once, one connection
  per device across both. From slice 3: a run queued wakes a live agent's
  poll at once; a job queued while the connection is cut is delivered by
  the long poll; with wakes dropped on purpose, by `jobsWaiting` at the
  next heartbeat; with a poll's answer dropped after its claim, by the
  sweep's wake within `RedeliverAfter` and 30 seconds; a hundred random
  cuts, and every run runs exactly once; **the current agent against the
  previous slice's server** (a `hello` without `poll.noWait`): it keeps
  long polls while live and receives every job.
* **Bundle end to end**, with real agents on host networking only, never
  bridge networking:
  * agents on *Automatic*, *Live connection* and *Regular check-ins* each
    receive a job and a settings change; the console shows their
    connection and last wake; a technician changes one device's
    transport;
  * **a proxy that kills idle connections**: a CONNECT proxy written for
    the test, on the host's network, used by a second real agent through
    `HTTPS_PROXY` in its unit's environment. Go never proxies loopback
    addresses, so that agent enrolls through the host's own non-loopback
    address, which the test adds to the deployment's IP addresses. With a
    45-second idle limit the connection lasts ten minutes (the keepalives
    hold it); **cutting every tunnel at 90 seconds** makes *Automatic*
    fall back within 10 minutes while jobs keep arriving, and so does
    cutting at 40 seconds; cutting all tunnels at once loses no job;
  * **a proxy answering 503 to upgrades**, without the server's code:
    *Automatic* falls back; with a copied `channel_busy` and a
    `Retry-After` of a day: the wait is cut to 30 minutes and three such
    answers count as one failure;
  * **an inspecting proxy**: the same program terminating TLS with a CA
    the machine trusts, and an agent enrolled to trust the system's roots:
    it passes the connection; it refuses upgrades (fallback); it accepts
    them and holds every frame (no `hello`: fallback); it holds every
    frame after `hello` (the agent's idle closes: fallback); it injects a
    wake (the connection closed); it cuts connections at 30 seconds
    (fallback); it replays an upgrade it held back while the real agent
    is live (the replayed connection gets no wakes and is closed at the
    device's next heartbeat; the real one is untouched and nothing is
    counted) and while it is not (never *Live*; closed after the device's
    heartbeat; the real agent connects next); it answers 404 to upgrades
    (nothing counted; one attempt per heartbeat);
  * **NGINX in offload mode** as the guide sets it up, carrying more
    connections than NGINX's default `worker_connections` (1,000, from
    `agentsim`): live; without the `Upgrade` headers: fallback;
  * **a server restart, and an upgrade's hold, with agents on
    *Automatic***: each gets `closing`, all reconnect within a minute,
    spread, and none falls back; a job queued during the restart runs
    once;
  * **three crashes in 30 minutes**: the server killed and brought back
    by Compose's restart policy three times, with agents on *Automatic*:
    no `closing`, every end classified against the new instance, and none
    falls back.
* **Load**:
  * On CI, 5,000 signed connections opened from a separate process
    (`tools/agentsim` with connections only; devices written to the
    database with keys of their own, without enrolling; no heartbeats or
    inventories, which a CI runner cannot hold for thousands of agents)
    against the server running as a process of its own, which measures
    the time to connect them; the server's memory per connection, from
    its own process (resident memory and Go's heap, before and after: the
    128 KiB gate); two wakes, timed from the commit to each connection's
    receipt (median and 99th percentile): a job queued on all 5,000
    devices, which is 5,000 `jobs` wakes, unspread, and a platform
    settings change, which is 5,000 `checkin` wakes spread at 100 a
    second; and the spread of a restart's reconnections.
  * On the bundle's deployment, 500 agents of `tools/agentsim`, which
    gains `-transport`, for 10 minutes with jobs.
  * On the owner's host, 2,000 and 10,000 agents for an hour on each
    transport, recorded in `drills.md` beside the existing 2,000-agent
    run: requests, nonce rows, CPU, memory and descriptors.
* **Coverage floors** in `scripts/ci/check-coverage.sh` for `agent/channel`
  and the server's channel package, at their measured coverage and no
  lower than their neighbours' (`agent/jobs` 80, `agent/client` 90).
* **Then the owner's instance**: one device set to *Live connection*
  first, then the platform's default.

## Slices
After ADR-0057 and ADR-0058's three slices. Each merges and is verified on
its own:

1. **The channel, beside the long poll.** The route, the signed messages,
   `features` and `instance`, `channel.v1` in the agent's report, the
   limits (per device, per server after verification, per organization,
   descriptors on Linux), shutdown and the hold, removal,
   `agent_connections` and `server_instances`; the agent's client with its
   keepalives, the sleep check, reconnection and the fallback;
   confirmation by the heartbeat, pending connections and the clone
   guard; `agent.transport`, *Regular check-ins* by default, technicians on
   one device; `checkin` wakes through the queue; the agent's report; the
   device's *Connection* and *Last wake*; `agentsim -transport`; the
   NGINX guide's sizing. The long poll
   is untouched. Verified by unit, integration and bundle tests, the CI
   load test, and on Windows as above.
2. **Several servers**: wakes and long polls through `LISTEN` and
   `NOTIFY`, one connection per device across instances. Long polls are
   still held. Verified by the two-instance integration tests.
3. **The live connection replaces the held poll.** `poll.noWait`, `jobs`
   wakes and the sweep's, `noWait`, `jobsWaiting`, polls on connect and on
   wakes, long polls again the moment the connection ends; *Automatic*
   becomes the default, with a release note sizing NGINX; the
   *Connection* column and its filter, Settings → Agent settings.
   Verified by the tests that jobs survive cuts, lost wakes and lost
   answers, the test against the previous slice's server, the bundle
   again, and the drills.

## Consequences
* Changes reach a live device at once; the server stops holding its polls
  and knows, from the device's own heartbeat, that it is connected.
* Jobs keep one path. The channel can delay a job but not lose, forge or
  repeat one, and a device whose network blocks WebSockets loses nothing
  but promptness for what the heartbeat carries.
* Every transport keeps the HTTPS heartbeat at the device's interval, and
  online stays based on it (ADR-0058): a dropped connection alone never
  makes a device offline. The plan's 10-minute heartbeat for *Live
  connection* is not needed.
* Restarts, crashes, upgrades and holds do not move a fleet on
  *Automatic* to regular check-ins; boxes that cut or hold connections
  do, within minutes. A replayed upgrade evicts no one, and two computers
  with one identity are flagged within about fifteen minutes.
* Each live device holds a connection and a file descriptor on a server,
  and about six in NGINX in offload mode; how many a server takes is a
  setting, 10,000 by default, and its descriptors bound it at run time.
* ADR-0009 is refined: the WebSocket is an optional channel that wakes the
  agent, authenticated by the signed upgrade and confirmed by the signed
  heartbeat, not a signed challenge; the signed poll and heartbeat stay
  the primary channel. Full delivery over the connection, and heartbeats
  over it, are not built.
