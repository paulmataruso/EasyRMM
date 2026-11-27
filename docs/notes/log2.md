# ADR-0060 slice 2: the log collector and the log store (branch `ws/log2`)

Licence: FSL-1.1-ALv2, licensor DHI Technical Services LLC.

## What is built

**Agent**

* `agent/logcollect`: the collector. `easyrmm-agent collect --spool DIR
  [--audit-socket FILE]` (a subcommand of the agent's own binary, as the ADR
  says, rather than a second binary) reads, redacts (`internal/logredact`),
  seals blocks and writes them to the spool. It never opens the agent's state
  or key, opens no socket but the audit socket, and sends nothing.
  * Linux readers: the journal through `journalctl --output=json` with
    journald's own cursor (`linux.journal`, and `linux.auth` for sshd, sudo,
    su, login and the like), auditd's log through descriptors the agent passes
    over a Unix socket in the spool (SCM_RIGHTS), read by `inode:offset` with
    `ReadAt`, so rotations lose nothing (`linux.audit`; an `EXECVE` record's
    arguments go to the sensitive field `cmdline`, never the message).
  * Windows reader: `winevents.NewChannelSource` (new, beside the Defender
    one) reads Security, System, Application, Defender and PowerShell by
    record ID; `ParseWindowsEvent` turns the XML into an event (`CommandLine`,
    `ScriptBlockText` and the like are sensitive fields).
  * Spool: one file per block, written atomically, sequence numbers from the
    clock's microseconds (rising even if the spool is wiped), size cap that
    drops the oldest blocks, cursors in `cursors.json`, moved only after the
    blocks are written.
  * Limits: `GOMAXPROCS(1)`, a Go memory limit, and on Windows a job object
    (hard CPU cap of 20 %, 256 MiB, kill on close) plus background mode. On
    Linux `Unit()` writes the ADR's unit (`DynamicUser`, empty
    `CapabilityBoundingSet`, `ProtectSystem=strict`, `AF_UNIX` only,
    `IPAddressDeny=any`, `CPUQuota=20%`, `MemoryMax=256M`, the agent's state
    inaccessible, `SupplementaryGroups=systemd-journal`).
    `easyrmm-agent collect-unit install|remove` writes and starts it, or
    stops and removes it.
* Transport: `Uploader` (in the agent, which holds the key) sends the spool's
  blocks oldest first, up to 8 per signed request, through
  `client.CollectedLogs` to `POST /api/agent/v1/collected-logs`, and deletes
  what the server acknowledged. A 404 or 503 keeps the blocks and backs off.
  It is started by `startCollected` only when the collector's spool exists,
  so a computer with no collector installed is untouched. It goes over the
  signed HTTPS request, not the heartbeat and not the channel: ADR-0059's
  channel carries only wakes and pushes today.
* Wire: `internal/agentproto/collectedlogs.go`. Blocks carry no facts on the
  wire: the server computes them.

**Blocks** (`internal/logblock`, shared by agent and server): events as JSON
lines, DEFLATE, a codec name per block, hourly facts, retention classes
(`security` 365 days, `operational` 90, `debug` 7) chosen by source name.
Limits on events, bytes, messages and fields are enforced on sealing and
again on opening.

**Server**

* `server/internal/logstore`: the store. Its own migrations directory
  (`migrations/90620_log_store.sql`, run only against the log database by
  `logstore.Migrate`, with goose and its own version table).
  * Schema: `log_streams` (acked sequence per device), `log_blocks`
    partitioned by LIST (retention class) then RANGE (`start_time`, monthly),
    each with a default partition, `log_hourly_facts`. `easyrmm_logs_ensure_partitions`
    and `easyrmm_logs_purge` are SECURITY DEFINER; purging drops monthly
    partitions wholly past retention and deletes past-retention rows in the
    others. The runtime role `easyrmm_logs_app` has no DELETE and no DDL.
  * RLS on all three tables from the same session settings as the main
    database (`database.Scope`), forced, with owner policies for the
    functions.
  * Ingest: stream row locked, repeats skipped by sequence, each block opened
    and re-sealed so count, bounds and facts are the server's own, refusals
    (bad source or class, undecodable, ends in the future, older than its
    retention, over `DailyBytes` = 256 MiB per device per 24 h) counted and
    passed over so one bad block never blocks the stream. `devscope.Allowed`
    gates ingest (404 to the agent for an organization held back).
  * Read: `Service.Read` and `Timeline` check `log.view` on the device's site;
    command lines and script text (`Sensitive`) are returned and searched only
    with `log.view_sensitive`.
  * A store that is unconfigured, unreachable or not yet migrated is
    `ErrUnavailable`: console 503 `logs_unavailable`, agent 503 (or 404 when
    not configured), nothing else affected. The pool does not connect at start;
    `Store.Start` migrates in the background (retrying every minute) and then
    runs partitions and retention hourly.
* `httpapi/collectedlogsapi`: `GET /api/v1/devices/{id}/collected-logs`
  (`since`, `until`, `source` (comma list), `q`, `limit`) and
  `.../collected-logs/timeline`.
* `config`: `EASYRMM_LOGS_DATABASE_URL`, `EASYRMM_LOGS_DATABASE_MIGRATION_URL`
  (optional; `_FILE` forms work). `app.Build` opens the store.

**Web**: a "Collected logs" tab on the device page (same `log.view`
permission): time range, source filter, search, a timeline of hourly bars
(click a bar to narrow to it), events newest first with details, "Load older
events", and a plain message when the store is unavailable.

**Deployment**: `logs-postgres` in `deploy/docker-compose.yml` (loopback port
15433, its own roles and database from `docker/postgres/logs-init`, data under
`${EASYRMM_LOGS_ROOT:-${EASYRMM_DATA_ROOT:-/srv/easyrmm}-logs}/postgres`), and
the two server variables, empty by default.

## Differences from the ADR and the brief

* **DEFLATE, not zstd.** The ADR chose DEFLATE (standard library, no new
  dependency); the module has no zstd library. Blocks name their codec, so
  zstd can be added without rewriting stored data. No preset dictionaries yet.
* **`easyrmm-agent collect`, not `agent/cmd/easyrmm-collect`.** One signed
  binary, as the ADR says.
* **Compose service is behind `profiles: ["logs"]`.** The ADR wants it in
  every deployment with `logs-db-init`, `setup.sh --logs-root`,
  `EASYRMM_LOGS_STORE_ID`, the finished-restore marker and the status file.
  None of that is here, and without `setup.sh` making its secrets the
  container could not start, so it is opt-in until the integrator takes the
  rest of the ADR's deployment half. No store identity or restore marker yet.
* The store is one table of blocks per class and month; the ADR's per-organization
  storage shares, size cap, free-disk floor and ballast file are not built
  (only the per-device daily byte limit).
* Detections, forwarding, configuring logging, the jobs launcher's `easyrmm-jobs`
  user, sealing with job marking, and the `log.view_sensitive` removal of
  already-stored fields are not part of this branch.

## Not done / for the integrator

* **Windows service, virtual account, channel access lists (`wevtutil sl
  /ca:`), and the WFP filter** are not built; only the reader and the job
  object are. They need the Windows runner (slice 3). The Windows code
  cross-builds and vets (`GOOS=windows`) but was **not run on Windows**.
* **Nothing installs the collector automatically.** `collect-unit install`
  is manual on Linux. Wiring it to a switch and `devscope.Allowed(org)` on
  the server's side of "turn collection on" belongs with the switches (the ADR's
  "Two switches" and Configuring logging). The only automatic behaviour added is
  the server's ingest check.
* **The Linux unit and collector were not run under systemd here.** The
  `InaccessiblePaths=` for `/run/systemd/resolve` and `/run/dbus` are included
  as the ADR describes but whether `journalctl` still works without them is
  unverified (the ADR says to verify and drop them if not). Unit tests cover the
  unit's text, the parsers, the readers on files and the descriptor passing
  over a real Unix socket.
* Migration number: `90620_log_store.sql` goes in `server/internal/logstore/migrations/`,
  its own directory and goose version table, so renumbering is cosmetic.
  It must not be moved into `server/migrations/`.
* `scripts/ci/check-coverage.sh` has no floor for the new packages
  (`agent/logcollect` 76 %, `internal/logblock` 80 % from unit tests;
  `server/internal/logstore` is covered by integration tests).
* A journal cursor journald no longer knows (after a vacuum) makes
  `journalctl` fail and the reader report an error every pass; a reset is not
  built.
* A page of the console read whose last event shares its timestamp with the
  next (`Next` is exclusive) can skip same-instant events at the boundary.
* `setup.sh --upgrade`, `.env` values and the updater (ADR-0052's amendments)
  are untouched.

## Tests

* Unit: `go test ./agent/logcollect ./internal/logblock` (blocks, spool,
  collector, journal and audit parsing and readers including rotation by
  inode, descriptor passing, uploader, unit text, Windows event XML).
* Integration (need `EASYRMM_TEST_DATABASE_URL`, `-tags integration`):
  `server/internal/logstore` (ingest once and repeats, refusals, daily quota,
  dev scope, reads with sensitive gating, RLS by organization and site,
  partitions and retention, runtime role's lack of DELETE/DDL, unavailable
  store) and `server/internal/app` `TestCollectedLogsAPI`,
  `TestCollectedLogsWithoutAStore` (agent client to console, as admin,
  technician and read-only).
* Web: `web/src/pages/devices/collectedLogs.test.tsx`.
