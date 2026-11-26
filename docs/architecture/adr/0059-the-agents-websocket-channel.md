# ADR-0059: The agent's WebSocket channel

* Status: Proposed (2026-11-21); refreshed 2026-11-26 against the code
  after ADR-0069 and the dev-scope guard (see *Refresh, 2026-11-26*, which
  wins where it disagrees with what follows). Not implemented.
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
  heartbeats. Minor fixes after that check: an agent's clock stepped
  back, "unlisted" defined, the console's *Stopped* state and *Live
  connection*'s exceptions, and the 40 seconds before `replaced`.
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

## Refresh, 2026-11-26 (decided in review)

This section was added after ADR-0069, ADR-0070, ADR-0072 and the dev-scope
guard landed, and after the owner asked "Lets get the websockets stuff
setup as well". **Where it contradicts the sections below, it wins**; the
sections it supersedes carry a pointer to it. Everything it does not touch
(authentication, signed messages, keepalives, reconnection, limits,
presence, several servers, the console, tests) stands and is built in the
slices at the end.

### What was stale
* **Wake-only and "Full delivery: not now" are reversed.** The channel
  now carries work, not only signals: job pushes, `logs.follow` and
  `logs.verbose` (and the live log lines they ask for), repair
  instructions, settings pushes and wakes. The heartbeat and the signed
  poll stay, unchanged, as the fallback and the only path when no
  channel is up. Authority is unchanged (*What does not change*).
* **ADR-0057 and ADR-0058 are still proposed and unbuilt** (no per-device
  job-key generations, no `agent.transport`, no `capabilities` in the
  report), yet *What this needs from ADR-0057* blocked slice 1 on them.
  The channel does not wait: it signs with the server's one job key the
  agent already trusts (`SetKey`, `HeartbeatResponse.JobKey`) and takes
  the key IDs of ADR-0057 when that lands (a `closing` of `refresh` at a
  cut-over is already specified). The transport is a **server-wide
  setting** until ADR-0058 lands: `EASYRMM_AGENT_CHANNEL` (`on`, the
  default, or `off`), which decides whether `features` lists `channel`.
  The per-device choice (*The transport, a setting per device*) is built
  with ADR-0058; it is not a slice here. Until then an agent needs no
  setting: it connects when its last heartbeat answer listed `channel`.
* **The agent's capability list** is the heartbeat request's new field
  `channel: ["v1"]` (additive, read leniently by older servers), not
  ADR-0058's `capabilities`; job capabilities stay in the poll's
  `accepts` (ADR-0064).
* **`poll.noWait` is dropped** (*Jobs are never lost*, slice 3 as
  written). A push replaces the held poll: the server claims and sends.
  When a heartbeat answer says `jobsWaiting`, a live agent makes one
  ordinary poll, which answers at once if work exists. No new request
  field, so no level problem (ADR-0009).
* **`logs.follow` is real.** ADR-0069 shipped `LogInstructions`
  (`verboseUntil`, `followUntil`, clamped by `MaxVerbose` 24 h and
  `MaxFollow` 15 min from receipt) in the heartbeat answer and in the
  answer to `POST /api/agent/v1/agent-logs`, and the agent sends batches
  every `LogFollowEvery` (2 s) while followed, else `LogEvery` (30 s).
  The "Amended by ADR-0069" note at the end said the channel "carries
  nothing from the agent"; that changes for log batches only, below.
* **Repairs are signed instructions in the heartbeat answer**
  (`HeartbeatResponse.Repair`, `SignedRepair`), produced by
  `recovery.Service.AgentHeartbeat`, which also settles the agent's
  `RepairReport`. The server's own Dispatch has already checked
  `publishes()` (the recovery copy's SHA must be a build the server
  publishes for that organization, platform and architecture) before it
  stores a step. The old text knew none of this.
* **The agent runner** (`agent/runner/runner.go`) applies a heartbeat
  answer in one place (update, EasyPatch install, uninstall, repair,
  logs, MeshAgent settings, interval); the channel must feed the same
  code, never a second implementation.
* **Dev scope.** `server/internal/devscope` (`Allowed(org)`) did not
  exist. A new automatic behavior reaches only the organization in scope
  while one is set; see *Dev scope*.
* **The websocket library exists**: `github.com/coder/websocket` v1.8.15
  is in `go.mod` (used for MeshCentral and remote sessions). The channel
  uses it on both sides, pinned there; no other is added. The `net/http`
  edge (`app/edge.go`) needs no change: its `IdleTimeout` and
  `ReadHeaderTimeout` do not apply once a connection is hijacked.
* **NGINX**: `docs/deployment/nginx.md` already forwards `Upgrade` and
  `Connection` for MeshAgent; the agent's route gets the same location
  settings (*Behind the reverse proxy*).

### What does not change (authority and trust)
* **Every instruction on the channel is the object the heartbeat answer
  or the poll answer would carry, byte for byte**: `SignedRepair`,
  `SignedUpdate`, the signed jobs of `PollResponse`, `LogInstructions`,
  the settings fields. They keep their own signatures (job key,
  `EASYRMM-…` domains) and their own checks on the agent. The channel's
  envelope adds the server's signature on the frame (*Messages*), which
  authenticates the frame; it never replaces the instruction's own.
* **Builds are still checked where they are decided.** A push of a
  repair or update takes the step the server stored after its
  `publishes()` check (and the agent's own SHA-256 check of what it
  downloads); the push path has no way to name a hash.
* **RBAC and audit are not on the channel.** Who may ask for a repair, a
  job or a follow is decided by the existing API (`access.Caller`, the
  audit log) when the request is made; the channel only moves what that
  decision stored. A push writes no audit row of its own; the existing
  rows (repair requested, job queued, logs followed) stand, and the
  channel adds a log line and a metric per push.
* **No instruction exists only on the channel.** Each is stored first
  (job runs, repair steps, the follow window in `agentlogs`, settings) and
  is therefore also found by the next heartbeat or poll. A push can be
  lost, late or repeated; it cannot be the only copy.
* **Agent-to-server frames** are log batches only (below), each signed
  with the device key; everything else the agent says stays on its signed
  HTTPS requests.

### What the channel carries (`channel.v1`, additions)
Server to agent, all with the envelope of *Messages* (`hello`, `tick`,
`wake`, `closing` as written there), plus:

| Type | Fields | Agent does | Stored first in |
|---|---|---|---|
| `jobs` | a `PollResponse` (`jobs`, `cancel`) | feeds the worker as a poll answer; the journal dedupes; `start` and `result` stay signed HTTPS | `job_runs` (claimed `sent`) |
| `logs` | a `LogInstructions` | the same function that handles the heartbeat's `logs` | the follow window in `agentlogs` |
| `repair` | a `SignedRepair` | the same function that handles `HeartbeatResponse.Repair`; reports in its next heartbeat, and asks for one at once when done | `recovery` step |
| `settings` | `heartbeatSeconds`, `meshAgent` (the `settingsSha256`), later ADR-0058's documents | the same function that applies them from a heartbeat answer | the device's settings |
| `wake` | `what`: `checkin` or `jobs` | a heartbeat, or one poll, now | whatever made it due |

Agent to server, signed by the agent (`EASYRMM-CHANNEL-AGENT-V1\n` + `connId` +
`seq` + payload, the device key, `connId` from `hello`, `seq` from 1):

| Type | Fields | Server does |
|---|---|---|
| `logs.batch` | a `LogBatch` (at most 64 KiB, at most one a second) | stores it through the same `agentlogs` function as the HTTPS route (same validation, same dedupe by device and sequence), and answers `logs.ack` (highest stored `seq`, plus the follow window) |

* **Why agent frames are signed here, though ADR-0059 had none.** Log lines
  are shown to technicians; on the proxy's plain hop they could be
  injected. Signing costs one Ed25519 signature a second per followed
  device, only while someone watches. A frame that fails, repeats or
  skips a `seq`, or comes at more than one a second, closes the
  connection (1008). The HTTPS route stays and is used whenever the
  channel is down; both write the same rows, so a batch sent on both is
  stored once.
* **How `jobs` is pushed.** One goroutine per connection waits on the
  jobs hub (`hub.subscribe(device)`, as `Poll` does today), on `hello`,
  and on the sweep, and runs the same `claim(ctx, device, accepts)` with
  the `accepts` the device last kept (`keepAccepts`), then sends the
  result as `jobs`. Claiming marks the runs `sent`, as a poll does, so a
  push that never arrives is redelivered after `RedeliverAfter` (2
  minutes), a cancellation after `CancelResend`, exactly as a lost poll
  answer. The agent acknowledges with `start`, the start check
  (ADR-0017), so there is no second acknowledgement path. A write that
  fails or takes over 10 s closes the connection and the agent returns to
  long polls at once. The sweep (every 30 s) runs the claim for live
  devices, so redeliveries need no wake.
* **How `repair`, `settings` and `logs` are pushed.** The code that
  decides, `recovery.Dispatch` after it stores a step, the logs service
  when a technician opens or closes the follow or verbose switch,
  and the settings and site-change code, calls `channel.Push(device,
  kind)` after its transaction commits; a failure to push is never an
  error (the heartbeat finds it). The pushed body is built by the same
  function the heartbeat answer uses (a new `instructions(ctx, device)` in
  `agentapi` that `heartbeat` also calls, so there is one builder).
  `recovery.AgentHeartbeat`, which settles reports and hands out steps,
  is split so a push reads the pending step without settling anything.
* **A repair is pushed once.** The step's `sent_at` is set when pushed, as
  when answered in a heartbeat; the agent's report in its next heartbeat
  settles it, and a step not reported in time is handled by the existing
  waits (`waitFor`, `maxRunning`).
* **`update`, `easyPatchInstall` and `uninstall`** stay on `wake` plus
  heartbeat: they are the rare, high-impact instructions, and an answer
  to a signed heartbeat confirms who is asking (decided in review; they
  can move to a push with a one-line change later).

### Dev scope
`devscope.Allowed(orgID)` is checked, on the server, in each of:
* the heartbeat's `features`: `channel` is listed only to a device whose
  organization is allowed, and the upgrade of any other answers 404, so an
  organization outside the scope never opens a channel while a scope is
  set;
* `channel.Push` for every kind, before it sends (a device already
  connected when a scope is set stops receiving pushes; its heartbeat
  and poll carry them as they do today, and the server closes its
  connection with `closing` `refresh` within a minute);
* the sweep and the wake queue (the same call), so they spend nothing on
  devices outside it.
The agent side has nothing to check: it does what the server sends. A test
sets the scope to one organization and proves that a device of another
organization neither connects nor receives a push, while its heartbeat
and poll still work.

### Behind the reverse proxy and TLS
* **The route** is `GET /api/agent/v1/channel`, on the same listener and
  TLS certificate as the rest of the agent API, so the agent's pinned CA
  (ADR-0015) verifies it as it does every request. There is no second
  port and no plain WebSocket (`ws://`): the agent refuses any URL that is
  not `https`.
* **Direct deployments** need nothing; the `net/http` edge serves the
  upgrade. **NGINX** (`docs/deployment/nginx.md`): the location for
  `/api/agent/` gets `proxy_http_version 1.1`, `Upgrade` and `Connection`
  from `$connection_upgrade`, `proxy_read_timeout` and `proxy_send_timeout`
  of 1 h (above the 75-second keepalive window, so NGINX never cuts a
  live connection), and `proxy_buffering off`. The guide's sizing of
  `worker_connections` stays as written.
* **What the server sees**: `httpapi.ClientIP` as for every request. The
  signed upgrade does not depend on the proxy; a proxy that strips
  `Upgrade` makes the upgrade answer 200 or 400, which the agent counts
  as a failed attempt (*Automatic's fallback*) and works as today.
* **Compression** is off (`websocket.CompressionDisabled`): signed frames
  gain nothing, and per-message compression costs memory per connection.

### Reconnects, backoff and limits, as built
* **Reconnects and backoff**: as in *Reconnecting, with jitter*, kept: a
  random wait up to 30 s then exponential backoff with full jitter from 5
  s to 5 min; a signed `closing` sets the wait; 404 waits for a heartbeat
  that lists `channel`; `429`/`503` with the server's code honour
  `Retry-After` (at most 30 min). A sleep (wall clock jumps by over 30 s)
  reconnects at once. The agent never reconnects faster than the 10-second
  per-device upgrade limit.
* **Per device**: one live connection (a second, once confirmed, replaces
  the first with `replaced`); an upgrade at most every 10 s after a burst
  of six; **server frames at most 20 a second (burst 50)**, beyond that
  the push is dropped and the heartbeat carries it; **agent frames at
  most one a second**.
* **Frame sizes** (this changes the 16 KiB rule in *Messages*): the agent
  accepts up to **1 MiB** for `jobs`, `repair` and `settings` (a signed
  script job is the largest instruction; slice 4 checks the real maximum
  against `agentproto` and fixes the number), and still 16 KiB for the
  others; the server reads at most **64 KiB** from the agent.
* **Per server**: 200 verified upgrades a second (503 `channel_busy`),
  `EASYRMM_AGENT_CONNECTIONS_MAX` 10,000 (503 `channel_full`), the
  descriptor gate on Linux; one reader and one writer goroutine per
  connection, a small bounded outbound queue, no database connection held,
  all as in *Server limits*.
* **Per organization**: no limit of its own until ADR-0058.

## Decision

### Wake-only
_Superseded by *Refresh, 2026-11-26*: the channel also carries job pushes, `logs`, `repair` and `settings`._

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
_Reversed by *Refresh, 2026-11-26*; kept for the reasons it weighed. The cost it names is met by storing every instruction first, using the existing claim, `start` and journal, and keeping the heartbeat and poll as the fallback._

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
  below, with `v` 1, the fields and the values of `what` and `reason`
  this ADR names. A message with a type, field, `v` or value the agent
  did not list is **unlisted**. A later type, field or value comes with a
  capability of its own (`channel.v2`, or one named for it), and the
  server sends it only to agents that list it. So the agent connects
  only once a heartbeat that carried its report, the second of its
  process at the earliest (ADR-0058), was answered listing `channel`;
  the server refuses an upgrade from a device whose last report lists
  no `channel.v1` with 404.
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
  heartbeats are taken in the order of their signed times, the only
  order the signed request carries (its header has the device, the time,
  a nonce and the signature, `internal/agentproto`; no counter): one
  signed before the latest heartbeat processed for the device, whose time
  ADR-0058's `agent_device_state` keeps, confirms and contradicts nothing,
  though it may show a conflict (*Server limits*).
* **An agent's clock stepped back** stalls this until it passes that
  time again: at most about 10 minutes, since both heartbeats were within
  five minutes of the server's clock (`MaxSkew`), one ahead and the other
  behind at worst. Meanwhile its confirmed connection stays confirmed and
  keeps its wakes, a new one stays pending, and the two intervals a
  pending connection has to be confirmed (below) count from the stall's
  end. A stall is not an *Automatic* failure, and no conflict: the
  heartbeats name the connection they named before, or a pending one.
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
  but the pongs that answer its pings, which keep proxies' and NATs'
  idle timers from closing it, then `closing` (`replaced`). The 40 seconds
  stop 5 seconds short of the agent's 75 on purpose: its last `tick` can
  be 30 seconds old, and 30 and 40 make 70, so the signed `closing`
  reaches it before it would call the connection dead and count a
  failure (*Keepalives*). If it pinged meanwhile (as the clone guard
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
  which the agent notices. A verified unlisted message (a type, field,
  `v` or value the agent did not list, *Features the server lists*) is a
  server's bug, not the network's: the agent
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
  their signed times (but for a clock stepped back, which counts nothing,
  above) and in the connections they name: it sends one
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
  heartbeat whose metrics the server accepted (ADR-0058), and then
  always: wakes, a connection cut
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
| **Live connection** (`live`) | A live connection, retried whenever it fails, after any wait the server asks for. While it is down, the device checks in regularly. |
| **Regular check-ins** (`poll`) | No live connection, for networks that block or inspect them. Jobs still arrive within seconds; other changes at the next check-in. |

* ***Live connection* retries, but for three cases**: it waits out a
  "later" answer's `Retry-After` (at most 30 minutes, *Automatic's
  fallback*); after a 404 it tries again only once a heartbeat answer
  lists `channel`; and after three unlisted messages from one instance
  it stops until a heartbeat answer names another instance or its own
  build changes (*Messages*). The console shows each.
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
  transport, the service stopping, an unlisted message) do not fail.
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
  this device's connection request at 10:42*, *Stopped at 10:42: the
  server sent messages this agent does not take, a server bug (the last
  one shown); trying again when the server restarts or the agent is
  updated*, or *This agent's version has no live connection*;
  and *Last wake*, when and why. Its Settings tab shows the transport
  with the same state under it.
* **Devices**: a *Connection* column (Live, Check-ins, Fell back,
  Connecting, Stopped) and a filter for devices that fell back or
  stopped.
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
_Not a blocker any more (*Refresh, 2026-11-26*): the build signs with the one job key until ADR-0057 lands; this list is what ADR-0057 adds then._

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
  message with an unlisted type, field, `v` or value, each in turn,
  closing the connection and counting nothing; three in 30 minutes, the
  hourly retry, *Live connection* never falling back; changes of
  transport; sleep detected from the wall and monotonic clocks, both
  injected; connecting only after a heartbeat with the agent's report
  was answered listing `channel`; `noWait` only when
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
  heartbeat without `transport`, or signed before the latest one
  processed, neither confirming nor contradicting; the agent's clock
  stepped back nine minutes: its confirmed connection kept, a new one
  pending until its clock passes the stored time, no conflict and no
  failure counted; the per-server budget untouched by unverified upgrades;
  upgrades refused with 404 for a device whose report lists no
  `channel.v1`, and no type, field or value sent that the report does not
  list; every
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
  * On a drill host, 2,000 and 10,000 agents for an hour on each
    transport, recorded in `drills.md` beside the existing 2,000-agent
    run: requests, nonce rows, CPU, memory and descriptors. Never on the
    host of the owner's instance: `scripts/drill/soak.sh` deploys its own
    copy and needs every other deployment on the host stopped.
* **Coverage floors** in `scripts/ci/check-coverage.sh` for `agent/channel`
  and the server's channel package, at their measured coverage and no
  lower than their neighbours' (`agent/jobs` 80, `agent/client` 90).
* **Then the owner's instance**: one device set to *Live connection*
  first, then the platform's default.

## Slices
Refreshed 2026-11-26. ADR-0057 and ADR-0058 are not prerequisites. The
slices are written so builders work in parallel: **C0 first and small,
then S1 and A1 together, then the message kinds M1 to M5 together**, then
the tests and the hardening. Each merges and is verified on its own; the
HTTPS paths are untouched by every one, so a slice that is behind leaves
the product as it is.

**C0, the contract (one builder, first, about a day).**
`internal/agentproto/channel.go`: the route constant, the envelope
(`payload`, `signature`), the types and fields above as Go structs, the
signing domains (`EASYRMM-CHANNEL-SIG-V1\n`, `EASYRMM-CHANNEL-AGENT-V1\n`),
`Sign`/`Verify` helpers for both directions, the limits as constants
(frame sizes, rates, 75 s, 30 s, 10 s), `HeartbeatRequest.Channel`,
`HeartbeatResponse.Features` and `.Instance`, with golden-vector tests.
Additive only (a hotspot file). Nothing else depends on anything but this.

**S1, server endpoint and hub** (new package `server/internal/agentchannel`,
route wired in `agentapi.Handler` with `signedFor` for `GET`, empty body,
using `BeginSigned`/`FinishSigned` as the other routes do).
The upgrade, `hello` first, `tick`, `closing`, the registry (device to
connection), `Push(device, msg) bool`, per-device and per-server limits,
the descriptor gate, shutdown and the hold, removal closes the
connection, `features`/`instance` in heartbeat answers,
`EASYRMM_AGENT_CHANNEL`, `devscope.Allowed` in the upgrade and in
`Push`. Reads no instruction; knows nothing of jobs. Verified by unit tests
and an integration test with a test client that uses only `agentproto`.

**A1, agent client** (new package `agent/channel`, started by
`runner.go`, a small additive block).
Connect only after a heartbeat answer listed `channel`; verify every
frame; reconnect, backoff, jitter, the sleep check, 404 and
`Retry-After` handling, the stop after three unlisted messages; `wake`
handling; the connection state exposed to the runner (live or not); it
sends WebSocket pings only. Verified against the test server of S1's
fixture (a package-local fake built on `agentproto`, since S1 may not have
landed; the real pairing is T1).

**M1, wakes and settings** (needs S1, A1). `checkin` wakes through the
queue (at most 100 a second), `settings` pushes (heartbeat interval,
MeshAgent settings hash) built by the shared `instructions` function,
the agent applying them through the runner's existing answer code.
**M2, jobs.** The per-connection claim loop, `jobs` frames, the live
agent stops holding long polls while its `hello` listed `channel` and the
channel is live, `jobsWaiting` in heartbeat answers for live devices,
one ordinary poll on `jobsWaiting`, the sweep claiming for live devices,
the real maximum frame size. The poll is untouched.
**M3, repair.** Split `recovery.AgentHeartbeat` so a push reads the pending
step without settling reports; `Push` after Dispatch; the agent calls its
existing repair start and asks for a heartbeat when done.
**M4, logs, both directions.** `logs` pushes when the follow or verbose
switch changes (the logs service), the agent's `logs.batch` frames and the
server's `logs.ack` through the shared `agentlogs` ingest, signed agent
frames, rate limit, HTTPS fallback when the channel is down.
**M5, console and docs.** The device's connection state (from the hub on
one instance; the table in H1 for several), Settings → Agent settings
(connections open, descriptors), the NGINX location settings and sizing
in `docs/deployment/nginx.md`, the metrics, the release note. No new
page; the device page shows a *Live connection* line only (ADR-0072).

**T1, end to end, agent and server over the channel** (integration build
tag, real PostgreSQL, the real server `app` and the real agent runner and
worker; no fake of ours in the path). Cases, each against both the channel
and the heartbeat alone:
* a job queued reaches a connected agent with no poll held, and its result
  returns; the same job with the channel disabled arrives by long poll;
* the connection cut mid-job, mid-push and mid-claim: the job runs once
  (journal), is redelivered after `RedeliverAfter` if its push was lost,
  and a cancellation is found;
* the server refusing upgrades (404, `channel_busy`), the connection
  killed every few seconds, and the proxy holding the upgrade: the agent
  falls back to the heartbeat and the poll within one interval and
  loses nothing (**the fallback test**: heartbeat answer carries the
  repair, the settings and the log window; poll carries the jobs);
* a repair stored with a build the server does not publish is never
  pushed, and one that is published arrives on the channel and is
  reported;
* `logs.follow`: a technician opens Logs, `logs` is pushed, lines arrive
  over `logs.batch` within a few seconds, close it and the agent returns
  to its 30-second batches; a forged, replayed or too-fast agent frame
  closes the connection;
* a forged, replayed, reordered, oversized or wrongly signed server frame
  closes it on the agent; three unlisted messages stop it;
* `devscope.Set(orgA)`: a device of org B neither connects nor receives a
  push and still works by heartbeat and poll; clearing the scope restores
  it; RBAC and audit rows of the API calls that caused a push are the same
  with and without the channel;
* limits: per-device upgrade rate, the 10,000 and 200 gates (with small
  numbers set by environment), the descriptor gate by a lowered limit.
**T2, load and Windows.** The 10,000-connection run on a drill host
(never the owner's instance) with the memory figure of *Server limits*;
`GOOS=windows` build and the Windows agent harness; `agentsim -channel`.

**H1 to H3, hardening, after the above, each with its own tests** (the
sections as written in this ADR): H1 presence confirmed by the heartbeat,
pending connections, `agent_connections`, `server_instances` and the
clone guard; H2 several servers through `LISTEN`/`NOTIFY`, one connection
per device across instances; H3 *Automatic's fallback* in full and, with
ADR-0058, `agent.transport` per device, the *Connection* column and its
filter. Until H1 the server trusts its own registry for "connected" and
the console says so; online is still decided by heartbeats.

**Order of work and conflicts.** C0, then S1 and A1 in parallel (disjoint
packages), then M1 to M5 in parallel (each in its own package: `agentchannel`
kind files, `agent/channel` handlers, and one additive block each in
`runner.go`, `agentapi.go` and the services they call), then T1 and T2.
`runner.go`, `agentapi.go` and `agentproto` are hotspots: blocks only, never
reorderings.

## Owner decisions
None are open. Decided in review: the channel carries work and the
heartbeat stays the fallback; ADR-0057 and ADR-0058 are not prerequisites;
a server-wide switch until ADR-0058; `update`, `easyPatchInstall` and
`uninstall` stay on the heartbeat; agent log frames signed; `noWait`
dropped. To confirm when the owner next looks: that the per-device
*Connection* choice waits for ADR-0058.

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
  the fallback channel. Since 2026-11-26 the connection also carries
  instructions (jobs, repairs, settings, log windows), each stored first
  and also found by the heartbeat or poll; heartbeats over it are not
  built.

* Amended by ADR-0069 (slice L1, 2026-11-23), refreshed 2026-11-26: log
  records travel over signed HTTPS (`POST /api/agent/v1/agent-logs`), and
  the instruction `logs.follow {until}` (and `verbose`) travels in the
  answers the agent already receives. The channel carries the same
  `LogInstructions` as a `logs` push and, while someone follows, the
  agent's signed `logs.batch` frames; the HTTPS route stays the fallback
  and writes the same rows.
