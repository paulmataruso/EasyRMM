# ADR-0068: Remote Windows event viewer and event log management

* Status: Proposed (2026-11-21). Not implemented.
* Nothing here was decided by the owner. Everything marked as decided was
  decided in review, and the owner can overturn it; the
  [owner questions](#owner-questions) list what is the owner's.
* Amends, each gaining an *Amended by ADR-0068* line when this is
  implemented:
  * [ADR-0017](0017-scripts-and-jobs.md): the job kinds
    `eventlog_query`, and in later slices `eventlog_manage` and
    `eventlog_export`.
  * [ADR-0060](0060-collecting-logs.md) (proposed): its classification of
    sensitive fields and `log.view_sensitive` are built here first, as
    the plan asks; the list gains PowerShell's module logging fields and
    the *Windows PowerShell* log ([Sensitive data](#sensitive-data)); its
    Logs tab gains *On the computer*; a log cleared through EasyRMM still
    opens its *Log cleared* alert ([Clearing a log](#clearing-a-log)).
  * [ADR-0063](0063-who-sees-job-output-and-arguments.md): its refusal
    bound counts `eventlog.refused`; a result read asks for
    `log.view_sensitive` as well when the query asked for sensitive
    data, as ADR-0063 foresaw ("The output endpoint would then ask for
    both").
  * ADR-0067 (the registry editor, accepted on its branch
    `docs/adr-0067-registry` and not merged, so cited without a link):
    F2 gains a second permission a kind may require when its input says
    so, and in slice 5 a file a run may hand back.
  * [ADR-0054](0054-hardening-windows-computers-and-servers.md#the-job)
    (proposed): "one change at a time on a device" covers
    `eventlog_manage`.
* Builds on: [ADR-0007](0007-hash-chained-audit-log.md) (the audit log),
  [ADR-0009](0009-agent-protocol.md#evolving-the-protocol-amended-2026-11-21)
  (evolving the protocol), [ADR-0020](0020-windows-agent.md) (the Windows
  agent), [ADR-0027](0027-agent-updates.md) (agent updates),
  [ADR-0063](0063-who-sees-job-output-and-arguments.md) (guarded output,
  definer functions, the refusal bound),
  [ADR-0064](0064-remote-powershell-management.md#older-agents-and-the-poll)
  (the poll's `accepts`; Windows tests as LocalSystem),
  [ADR-0065](0065-hardware-health.md#the-five-states-f1s-rule) (the words
  for states), ADR-0067's F2 (kinds with an input and a result, the
  `builtin` executor, the quick lane), and these proposed ADRs:
  [ADR-0055](0055-lets-encrypt-in-one-step.md#step-up-authentication)
  (step-up), [ADR-0060](0060-collecting-logs.md) (the event model, the
  classification, `log.view_sensitive`, detections) and
  [ADR-0054](0054-hardening-windows-computers-and-servers.md) (W1's reader
  of who owns a setting; its Windows machines under KVM).
* Requirements: feature 9, "Remote Windows Event Viewer and Event Log
  Management", of the
  [owner's requirements of 2026-11-21](../requirements/2026-11-21-msp-features.md#9-remote-windows-event-viewer-and-event-log-management).
  Every bullet is placed in [The requirements](#the-requirements). The
  [plan](../feature-plan-msp.md#9-remote-windows-event-viewer-and-event-log-management)
  lists it as feature 9, step 16 of its [order](../feature-plan-msp.md#order),
  on [F2](../feature-plan-msp.md#f2-fixed-script-job-kinds-whose-results-are-hidden-by-kind).
* **Where this differs from the plan**, each argued where it is decided:
  1. **Code in the agent, not a fixed script.** The plan's "fixed script
     leaves them out on the computer" becomes ADR-0067's `builtin`
     executor: `easyrmm-agent.exe builtin eventlog`, Go calling the
     Event Log API.
  2. **Kinds per purpose**, not one `eventlog` kind: `eventlog_query` in
     slice 1; `eventlog_manage` and `eventlog_export` with the slices
     that need them, since retention, readers, lane and the change lock
     differ (ADR-0067's reason for two registry kinds).
  3. **Results kept one hour**, where the plan has "fetched, shown and
     dropped": F2 stores a result in the database for its asker; the
     hourly purge removes it within two.
  4. **Recurring IDs and occurrences over time on demand** in slice 2,
     counted on the computer, where the plan has them only from ADR-0060's
     counts in slice 3. Slice 3 still adds history beyond the computer's
     own logs.
  5. **Event Viewer's Keywords as well as text.** The requirement's
     "keyword" is read as text in the event, matched after the query as
     the plan says; Event Viewer's Keywords (a bit mask such as *Audit
     Failure*) are offered too, in the query.
  6. **Pages of up to 100 events and 1.75 MiB**, bounded on bytes as well
     as count.
  7. **One audit record per query, not per page**, with the count on the
     run and the text's length rather than the text (ADR-0067's rule).
  8. **Management slices** (channel settings, `.evtx` export, clearing)
     that the plan's slices do not have, from the requirement's title.
  9. **The sensitive list grows**: PowerShell's module logging (4103) and
     the *Windows PowerShell* log, which ADR-0060 does not collect by
     default and which on-demand queries reach.

## Context
Each repository claim was checked at `main` `6e977bd`.

### What exists
* **No event log feature.** No Go code calls the Event Log API, and no
  device tab shows events: a device's tabs are Overview, Hardware,
  Software, Patches and Hardening, the last for Linux only
  (`web/src/pages/devices/DeviceDetailPage.tsx:61-68`). A technician
  reads a computer's logs through a SYSTEM terminal (`device.terminal`,
  `server/internal/rbac/rbac.go:33`, held by Technicians, `:145-148`) or
  remote desktop; only the session is recorded.
* **Permissions.** `log.view` and `log.view_sensitive` do not exist
  (`rbac.go:23-61`). `job.view_sensitive` does (`:40-42`), held by
  Technicians and above and not Read-Only (`:145-148`, `:179-183`). A
  site-scoped role never gets `org.manage`, `user.manage` or
  `patch.configure`, whatever its definition says (`:286`): the place an
  organization-wide-only permission goes.
* **Jobs.** Three kinds, `script`, `software` and `hardening`
  (`server/migrations/00027_hardening.sql:16`). The agent runs four jobs
  at once (`agent/jobs/worker.go:40`); a run's process is put in its job
  object after it starts (`agent/jobs/exec_windows.go:121-131`). The poll
  request is empty (`internal/agentproto/jobs.go:81`): ADR-0064's
  `accepts` is not built. A poll answer holds at most 8 jobs
  (`MaxPollJobs`, `:19-20`) and a result body at most 4 MiB
  (`MaxResultBody`, `:21-23`).
* **F2 is not built.** ADR-0067 defines it and builds it in its slice 1,
  step 15 of the plan's order, one step before this feature: the table of
  kinds; `job_inputs` and `job_runs.result`, which the server's database
  role cannot select; the `builtin` executor, a child process of the
  agent's own program in the run's job object with a 512 MiB memory
  limit, given its input in a file and writing a result file of JSON
  lines of at most 2 MiB; `job.structured` and `builtin.<name>.v<N>` in
  `accepts`; a quick lane of 2 slots; `MaxResultBody` raised to 8 MiB.
  This ADR uses those as ADR-0067 defines them and does not repeat them.
* **Guarded output.** ADR-0063 is implemented (PR #81): output and
  arguments are read through `SECURITY DEFINER` functions, refusals are
  recorded within a bound of 20 per caller in 10 minutes counted over two
  actions (`easyrmm_job_refusal`,
  `server/migrations/00028_job_output_access.sql:84-114`, the count at
  `:104-106`).
* **The agent** is built without cgo for Windows on x64 and ARM64
  (`Makefile:129`) and for Linux (`:133`), and supports Windows 10 and
  Windows Server 2016 and later
  ([ADR-0020](0020-windows-agent.md#one-agent-built-for-windows)). It
  loads `kernel32.dll` lazily (`exec_windows.go:23`). `golang.org/x/sys`
  v0.50.0 (`go.mod:17`) has the Event Log API's error codes but none of
  its functions, so the calls are loaded from `wevtapi.dll` the same way.
* **Clocks.** The agent's requests are refused when their time is more
  than 5 minutes from the server's (`MaxSkew`,
  `internal/agentproto/agentproto.go:44-45`). The inventory reports the
  computer's time zone (`TimeZoneKeyName`,
  `agent/inventory/windows.go:117-118`).
* **The audit log** keeps at most 16 KiB of details per record
  (`server/internal/audit/audit.go:72`).
* **ADR-0060** (proposed, step 26) collects filtered sources into a store
  of its own, with fleet search, export, forwarding and detections;
  `log.view` (Site Administrators and above) and `log.view_sensitive`
  (Organization Administrators and above, organization-wide grants
  only). It keeps no raw XML and drops the rendered message for the
  Security log and for events with a sensitive field
  ([The collector](0060-collecting-logs.md#the-collector)). It classifies
  sensitive fields by name
  ([What is collected](0060-collecting-logs.md#what-is-collected)).

### What Windows offers
Checked against Microsoft's documentation for this ADR; the pages are in
[References](#references).

* **Querying.** `EvtQuery` takes a channel or a file and an XPath query
  or a structured XML query; "If your XPath contains more than 20
  expressions, use a structured XML query"; its handle must be used on
  the thread that created it. Flags read forward (the default) or in
  reverse, and `EvtQueryTolerateQueryErrors` runs a query even when part
  of it fails. "You can retrieve events only in a forward direction from
  Debug and Analytic channels and from .evt and .etl log files."
* **The XPath subset** has the child and attribute axes; `or`, `and`,
  `=`, `!=`, `<=`, `<`, `>=`, `>` and parentheses; and three functions:
  `position`, `Band` (bitwise AND) and `timediff`. There is no
  `contains()`. A structured query (`QueryList`) holds `Select` and
  `Suppress` elements per path. The result set "does not contain a
  snapshot": events written while it is read can appear in it.
* **Reading.** `EvtNext` returns event handles in batches, with a
  timeout; `EvtRender` gives an event's XML or values; `EvtCancel` stops
  a pending `EvtNext`, `EvtQuery`, `EvtExportLog` or `EvtClearLog` from
  another thread, which then returns `ERROR_CANCELLED`.
* **Messages.** `EvtFormatMessage` formats the event's message, level,
  task, opcode, keywords, channel or provider names from the provider's
  metadata (`EvtOpenPublisherMetadata`, locale 0 meaning the calling
  thread's). Its metadata may be NULL for events forwarded by the Windows
  Event Collector, because "Forwarded events include a RenderingInfo
  section that contains the rendered message strings". Microsoft's sample
  treats `ERROR_EVT_MESSAGE_NOT_FOUND` and
  `ERROR_EVT_MESSAGE_ID_NOT_FOUND` as no message. A provider's tasks,
  with their values and message IDs, are in its metadata
  (`EvtPublisherMetadataTasks`).
* **The event's fields** (`System`): Provider (name and GUID, or an
  event source name for legacy providers), EventID (16 bits, with
  Qualifiers holding the high 16 bits for legacy providers), Version,
  Level, Task, Opcode, Keywords (a 64-bit mask), TimeCreated's
  `SystemTime`, EventRecordID, Correlation, Execution, Channel, Computer
  (the fully qualified name by default) and Security's `UserID` (a SID).
* **Levels**: 0 LogAlways, 1 Critical, 2 Error, 3 Warning, 4
  Informational, 5 Verbose (.NET's `StandardEventLevel`, which mirrors
  Windows' values).
* **Channels.** `EvtOpenChannelEnum` and `EvtNextChannelPath` list every
  channel registered providers define, sorted by name. A channel's
  configuration (`EVT_CHANNEL_CONFIG_PROPERTY_ID`) holds whether it is
  enabled (which "cannot be set" for Application, System or Security),
  its type (Admin, Operational, Analytic, Debug), its access list, its
  maximum size, retention and auto-backup. `EvtGetLogInfo` gives a log's
  record count, oldest record number, size and whether it is full, but
  not the count, the oldest record or *full* for Debug and Analytic
  channels. Channel names are under 255 characters and cannot contain
  `>`, `<`, `&`, `"`, `|`, `\`, `:`, `` ` ``, `?`, `*` or characters below
  31.
* **Analytic and Debug channels** are disabled by default; "enabling the
  channel clears the channel of existing events", and a circular one must
  be disabled to be queried. Each uses an ETW session of its own, of which
  there are few.
* **Size and retention.** The maximum size is at least 1 MiB and log
  files are multiples of 64 KiB. Retention true keeps a full log's events
  and discards new ones; false overwrites the oldest. Auto-backup, only
  with retention, writes `Archive-<channel>-<timestamp>.evtx` files in
  `%windir%\System32\winevt\Logs`, with "no limit to the number of backup
  files".
* **Settings, clearing, exporting.** `EvtSetChannelConfigProperty` changes
  a copy that `EvtSaveChannelConfig` applies. `EvtClearLog` clears a
  channel, saving it first to an absolute path when given one.
  `EvtExportLog` writes a query's events to a new `.evtx` file, which
  "must not exist"; `EvtArchiveExportedLog` adds the messages, so the file
  can be read where the provider is not installed.
* **Sensitive content.** With command line auditing, "any user with access
  to read the security events will be able to read the command line
  arguments", and arguments "can contain sensitive or private information
  such as passwords". Script block logging (4104) records scripts, which
  may hold credentials; Protected Event Logging encrypts them with CMS;
  module logging (4103) records pipeline execution details. Sysmon logs
  each process's full command line (event 1) and WMI filters and consumers
  (19, 20), with timestamps in UTC.
* **1102**, "The audit log was cleared", is written to the Security log
  by Microsoft-Windows-Eventlog, naming who cleared it.
* **Event 41** (Kernel-Power) marks a restart without a clean shutdown,
  with the bug check code in decimal; the same page describes 1074 (a
  restart and who asked), 6006 (a clean shutdown), 6008 (an unexpected
  one) and volmgr 46 (crash dump not initialized), and notes that "The
  time shown in the .evtx file is adjusted to your system's time".
* **Every function above** is available from Windows Vista and Windows
  Server 2008, so on every Windows version the agent supports.
  `SystemTimeToTzSpecificLocalTimeEx`, which converts UTC to a zone's
  local time with its dynamic daylight saving rules, from Windows 7 and
  Windows Server 2012.

## Decision

### In short
*Decided in review.*

* **A Logs tab** on Windows devices, its mode *On the computer*: the
  computer's channels; a query over one or several by level, ID,
  provider, task category, Event Viewer's keywords and time, with text
  matched after it; newest first, in pages, with a cursor; each event's
  fields, message and XML; refresh and copy. Slice 1, step 16.
* **Code in the agent.** A builtin of ADR-0067's F2,
  `easyrmm-agent.exe builtin eventlog`, calls the Event Log API from Go,
  in a child process inside the run's job object. No PowerShell.
* **Every bound on the computer**: events returned, events read, time,
  bytes and memory, each saying where it stopped. The Event Log service's
  own work during a query is bounded by time only.
* **Sensitive data enforced twice**: on the computer and on the server,
  by one Go package. The Security log, and sensitive fields with the
  messages and XML that repeat them, need `log.view_sensitive`.
* **Permissions**: `eventlog.view` for Technicians and above;
  `log.view_sensitive` for Organization Administrators and above from
  organization-wide grants, as ADR-0060 defines it; later,
  `eventlog.manage` and `eventlog.clear_security`.
* **Audit**: one record per query, without event data; results kept one
  hour, for the person who asked only.
* **Later slices**: presets, counts, saved searches and export (2); both
  modes with ADR-0060 (3); channel settings (4); `.evtx` files and large
  exports (5); clearing a log (6).

### The kinds
*Decided in review.* Each is an entry in ADR-0067's table of kinds.

#### Code in the agent, not a script
The work is Go in the agent's program, run as
`easyrmm-agent.exe builtin eventlog`, a child process in the run's job
object, as ADR-0067's registry builtin is, with its input in
`EASYRMM_JOB_INPUT` and its result in `EASYRMM_JOB_RESULT`. Its command
line names the builtin and nothing else.

Why not a fixed PowerShell script calling `Get-WinEvent`, as the plan's F2
first assumed:

* **The viewer would write into the logs it reads.** ADR-0060 turns on
  script block logging and collects 4104; each page would log the
  script's text as a script block, and where module logging is on, 4103
  records the cmdlets' parameters: the query's providers, IDs and times
  (about_Logging_Windows: module logging records pipeline execution
  details).
* **One set of rules.** The sensitive classification runs on the computer
  and on the server. A script would be a second implementation of it in
  another language; the builtin compiles the same Go package as the
  server.
* **The executor exists.** ADR-0067 builds `builtin` at step 15 and leaves
  `script` to "the first kind that chooses it"; choosing it here would
  build a second executor for one feature.
* **Scripts are restricted where fleets are best managed.** App Control
  runs scripts in Constrained Language Mode and `AllSigned` refuses an
  unsigned one (ADR-0067's reasons). Whether a script's calls to render
  an event's XML and message are allowed in Constrained Language Mode is
  not verified; the builtin removes the question.
* **Streaming and bounds.** The builtin reads events in batches of handles
  and writes each one before reading the next, so memory does not grow
  with the log; a script holds objects the runtime builds.
* **Start-up.** PowerShell's start adds about a second per run, to be
  measured (plan, F2); every page is a run.

#### Capabilities and versions
* **`job.structured` and `builtin.eventlog.v1`**, gated as ADR-0067 gates
  the registry: the claim delivers an event log run only to a poll whose
  `accepts` lists them; creating one for a device that lacks them is
  refused: "PC-12's agent cannot open the event viewer; update the
  agent". No fallback.
* **Each slice that adds operations adds an input version**
  (`builtin.eventlog.v2` for slice 2's, and so on), and the server sends
  an operation only to a device whose list has a version that knows it.
  A device on an older build keeps what it had.

#### Settings per kind

| | `eventlog_query` (slice 1) | `eventlog_manage` (slices 4, 6) | `eventlog_export` (slice 5) |
|---|---|---|---|
| Operations | `channels`, `query`, `event`, `provider`; slice 2 adds `summary` and `export` | `configure`, `undo`, `clear` | `evtx`, `jsonl` |
| Executor | `builtin` (`eventlog`) | `builtin` (`eventlog`) | `builtin` (`eventlog`) |
| Input and result kept | 1 hour (the hourly purge empties them within 2) | `EASYRMM_JOB_OUTPUT_RETENTION` (30 days by default) | the file 24 hours; input and result 1 hour |
| Job and runs kept | 7 days | `EASYRMM_JOB_RETENTION` (90 days by default) | 7 days |
| Input and result read by | the person who asked, holding `eventlog.view` and `job.view_sensitive` at the device's site, and `log.view_sensitive` in its organization when the query asked for sensitive data | holders of `eventlog.manage` and `job.view_sensitive` at the device's site | the person who asked, holding `eventlog.view`, `job.view_sensitive` and `log.view_sensitive` |
| Each read recorded | no: only the asker reads it, and the query's record covers it | no: it holds settings, never events | the download, `eventlog.export` |
| Waits for an offline device | 2 minutes | 15 minutes | 15 minutes |
| Timeout and lane | 60 seconds, quick | `configure` and `undo` 60 seconds, quick; `clear` 10 minutes, the normal lane | 10 minutes, the normal lane |
| In the Jobs list | under its filter only | under its filter only | under its filter only |
| Change lock | no | yes | no |

* **One query open per person and device, two per device.** A new filter,
  page or refresh from the same person cancels their run still open on
  that device (ADR-0054's runs the server cancels, which F2 extends); a
  third open query on one device is refused: "two searches are already
  running on PC-12".
* **The Jobs list** gains the filter *Event logs*; without it these jobs
  are left out, since each page is a job. Under `job.view` they show the
  device, who, when, the operation and the status; no channel, filter or
  event.

### One set of rules, one reader
*Decided in review.*

* **`internal/eventrules`**, beside `internal/agentproto`, compiled into
  the server and the agent: the event model (ADR-0060's fields, plus the
  message and XML this mode adds), the classification of sensitive
  fields and channels, the check of channel names, the query builder,
  the inputs and results of each version and the server's check of a
  result against its input; from slice 2, the presets. ADR-0060's
  collector and server use it when they are built. The result names the
  rules' version it used. A server and an agent of different releases
  each apply their own; the server applies its own to every request and
  every result ([Where it is enforced](#where-it-is-enforced)).
* **`agent/winevent`**, Windows only: the Event Log API from
  `wevtapi.dll`, loaded lazily as `kernel32.dll` is
  (`exec_windows.go:23`), with no cgo. Each function's binding lands with
  the slice that calls it. ADR-0060's collector reuses it.
* **The query runs on one locked thread** (`runtime.LockOSThread`), since
  a query handle belongs to the thread that made it; a watchdog
  goroutine calls `EvtCancel` at the time limit.

### Channels
The `channels` operation lists every channel (`EvtOpenChannelEnum`), up to
5,000, each with:

* its type (Admin, Operational, Analytic, Debug), whether it is enabled,
  whether it is a classic log, its maximum size, retention and
  auto-backup;
* for Admin and Operational channels, its record count, size, the time of
  its oldest event and whether it is full (`EvtGetLogInfo`), so that the
  console can say how far back the computer's history goes;
* *Unavailable: access denied* where Windows refuses (`ERROR_ACCESS_DENIED`).

The console groups them: *Windows Logs* (Application, Security, Setup,
System, ForwardedEvents), then the others by provider, split at the `/`
of a name such as `Company-Product-Component/Operational` (the naming
convention Microsoft's channel schema describes); Analytic and Debug
channels behind *Show analytic and debug logs*. The Security log is listed for everyone, marked *needs permission
to see the Security log* for those without `log.view_sensitive`. The list
is kept by the console for its session and refreshed on request; it costs
about a second of the run (to be measured).

### Queries

#### Filters into the query
The server builds the query from typed filters; nobody sends XPath
([Not chosen](#not-chosen)). Within a filter the values are alternatives
(or); between filters every one must hold (and).

| Filter | Into | Limits |
|---|---|---|
| Logs | one query per channel | 1 to 10 channels, names checked against Windows' rules |
| Level | `Level=1 or Level=2 …`; *Information* is 0 or 4, as Event Viewer counts it (to be confirmed) | the six levels |
| Event IDs | `EventID=…`, ranges as `EventID>=a and EventID<=b`; exclusions in a `Suppress` | up to 32 IDs or ranges to include and 32 to exclude |
| Provider | `Provider[@Name='…']` | up to 16 |
| Task category | `Task=…` | up to 16, with exactly one provider, since a task's number means something only within its provider |
| Keywords (Event Viewer's) | `Band(Keywords, mask)` | one mask, chosen from the provider's named keywords (`EvtPublisherMetadataKeywords`) or the standard ones such as *Audit Success* and *Audit Failure* (their masks to be confirmed) |
| Time | `timediff(@SystemTime) <= …` for *last hour, 12 hours, 24 hours, 7 days, 30 days*; `@SystemTime>='…' and @SystemTime<='…'` for a custom range (the form Event Viewer writes; to be confirmed on the runners) | any range; UTC |
| Text | matched after the query (below) | 1 to 256 characters |

* **Always a structured query**, one `QueryList` per channel with its
  `Select` and its `Suppress`, so the 20-expression limit of a plain XPath
  never applies. A filter Windows still finds too complex
  (`ERROR_EVT_FILTER_TOO_COMPLEX`) is shown as *Windows refused the filter
  as too complex: use fewer IDs or providers*.
* **Never `EvtQueryTolerateQueryErrors`**: a part of a filter that failed
  would be dropped without a word, and events that do not match would be
  shown as matching.
* **Escaping.** Values are XML-escaped in the `QueryList` and quoted in
  XPath with whichever quote they do not hold; a value holding both is
  refused. Channel names are checked against the characters Windows
  refuses.
* **Task names** for the filter come from the `provider` operation: the
  provider's levels, tasks, opcodes and keywords with their display names
  (`EvtPublisherMetadataTasks` and the others, formatted by
  `EvtFormatMessage`). Whether classic providers' categories appear there
  is to be confirmed; where they do not, the filter takes the number and
  the list shows the names seen in results.
* **Providers** are typed or picked from those in the results shown and
  in the channel's list. A full list per channel through
  `EvtOpenPublisherEnum` is to be confirmed in slice 1 (its page was not
  read for this ADR); without it, typing works.

#### Text, after the query
* **Matched by the builtin** after Windows returns an event, against its
  rendered message and the values of its data, as a substring ignoring
  case (Unicode simple case folding); not a regular expression, which
  would make cost depend on the pattern.
* **Never against what the caller may not see**: without
  `log.view_sensitive`, sensitive fields, and the message of an event that
  has one, are left out of the match, so the search cannot probe them (as
  ADR-0060's search does).
* **Bounded by the events read and the time**, like any page
  ([Bounds](#bounds)). Text forces every candidate's message to be
  formatted, so a text search reads far fewer events per second; the
  page says how far back it searched.

#### Several logs
Each channel is queried on its own, newest first, and the builtin merges
the streams by `TimeCreated`, taking the newest head each time. Each
channel's own events keep their order in the log. Analytic and Debug
channels can be read only oldest first, so they are queried alone, never
merged, and shown oldest first.

#### Order, pages and the cursor
* **Newest first** (`EvtQueryReverseDirection`), in the log's own order:
  the order events were written. Times can be out of order by a little
  (several writers, a clock that moved); the list never reorders events
  within a channel.
* **A page** holds up to 100 events, and stops earlier at 1.75 MiB of
  event lines, so that the whole result stays under F2's 2 MiB.
* **The cursor** is, per channel, the last record number returned; the
  next page adds `EventRecordID < n` for that channel. Record numbers only
  grow within a log, so events written while the person reads appear at
  the next refresh, not in the middle of the pages, and none repeats.
  The cursor is the server's: a page's input carries the query's ID, and
  the server checks it is a query of the same person on the same device,
  made within the hour, with the same filters.
* **Refresh** runs the first page again and shows *Read at* with the
  computer's clock.

#### Bounds
Every page, summary and export is bounded on the computer, and says which
bound stopped it:

| Bound | Value | When reached |
|---|---|---|
| Events returned | 100 per page | the page is full; *More* continues |
| Bytes | 1.75 MiB of event lines (F2's result is at most 2 MiB) | the page stops with what fits |
| Events read | 100,000 per page (1,000,000 per summary) | *Searched N events back to T; more may match* |
| Time | the builtin stops itself at 45 seconds of the run's 60 (30 for `channels`, `event` and `provider`), cancelling `EvtNext` with `EvtCancel` | as above |
| Memory | F2's 512 MiB job-object limit; batches of 32 handles closed after each is written; at most 256 providers' metadata cached | the child is stopped by the job object, and the lines written so far are sent |
| One event | message 4,096 characters and each value 1,024 in a page; the `event` operation gives message up to 256 KiB, values up to 64 KiB, XML up to 1 MiB | the value is cut and marked |

**The Event Log service's own work is outside the job object.** Windows
filters events in the Event Log service, so a query over a large log costs
that service's processor time until the page fills, the log ends or the
builtin cancels; the job object does not count it. Bounded by the time
limit, one query per person and device, and two per device; slice 1
measures it on a log filled to 256 MiB on the runners
([Testing](#testing)).

### Events

#### Fields
Each event in a page carries:

* the log it was read from, and the channel it names (`System/Channel`),
  which differ for forwarded events;
* its record number; the provider's name and GUID; the event ID and, for
  classic providers, its qualifiers; the version; the level with its name;
  the task with its name (the *Task Category*); the opcode; the keywords
  as a hexadecimal mask with their names;
* `TimeCreated` exactly as recorded, in UTC to the 100 ns the XML carries
  ([Times](#times));
* the computer's name as recorded;
* the user: `Security/@UserID`, and the account name the computer
  resolves it to (below);
* the process and thread IDs;
* the event's data: `EventData`'s named values; for classic events, their
  unnamed values in order; `UserData` flattened to paths and values;
  binary data as hexadecimal;
* the message, or why there is none (below);
* the names of fields withheld ([Sensitive data](#sensitive-data)).

Strings with NUL characters or lone surrogates go as ADR-0067's results
carry them: the displayed text with replacement characters, and the exact
UTF-16 bytes beside it, so that nothing reaches `jsonb` that it refuses
and nothing is silently changed. The `event` operation adds the XML as
Windows renders it (`EvtRenderEventXml`), unchanged.

#### Messages
* **`EvtFormatMessage`** with the provider's metadata, opened once per
  provider and run, with locale 0, the calling thread's: messages come in
  the language Windows gives the builtin running as SYSTEM (to be
  confirmed: the system's default). A provider without that language
  (`ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND`) is asked again in English
  (`0x409`), marked. Buffers are retried at the size Windows asks for, up
  to the bounds above.
* **No description.** When the provider's metadata or message is missing
  (`ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND`, `ERROR_EVT_MESSAGE_NOT_FOUND`,
  `ERROR_EVT_MESSAGE_ID_NOT_FOUND`): *Description unavailable: the
  provider's message file is not on this computer*, with the event's
  values listed. A message whose inserts could not be
  resolved (`ERROR_EVT_UNRESOLVED_VALUE_INSERT`,
  `ERROR_EVT_UNRESOLVED_PARAMETER_INSERT`) is shown as Windows returned
  it, marked *incomplete*; what Windows returns in that case is to be
  confirmed on the runners.
* **Forwarded events** are formatted with no metadata, from their
  `RenderingInfo`; one without it shows *Description unavailable: the
  subscription forwarded events without their text* (to be confirmed
  with a Windows Event Collector, [Testing](#testing)).
* **Protected Event Logging.** A script block encrypted with CMS is shown
  as *Encrypted (Protected Event Logging)*. EasyRMM never decrypts it:
  the key belongs to whoever reads the logs centrally, not to the
  computer or EasyRMM.
* **Text from computers is text**, never HTML or Markdown, as in ADR-0060.

#### Users and computers
* **The account** behind `UserID` is looked up on the computer
  (`(*windows.SID).LookupAccount` in `x/sys`), once per SID per run, at
  most 64 per page, within the time limit; a SID that does not resolve,
  or would take too long (a domain account with no domain controller in
  reach), is shown as the SID. Accounts in the event's data (a sign-in's
  target user) are shown as the event recorded them.
* **The computer's name** is what the event recorded, the fully qualified
  name by default. Forwarded events name the computer that wrote them,
  and the console says so.

#### Times
* **Preserved.** Each event's `SystemTime` is kept and shown exactly as
  Windows recorded it, in UTC. EasyRMM never corrects it.
* **Shown** in the viewer's time zone by default, named on the page, with
  a switch to *the computer's time*: the builtin gives each event its
  offset from UTC on the computer at that instant, converted with
  `SystemTimeToTzSpecificLocalTimeEx` and the computer's dynamic time
  zone, daylight saving included: the local time Microsoft notes Event
  Viewer adjusts to. UTC is one click away.
* **The computer's clock.** Each result's first line carries the
  computer's clock when it ran; the page shows the difference from the
  server's when over 30 seconds. An agent further out than 5 minutes
  cannot talk to the server at all (`MaxSkew`). Events written while a
  clock was wrong keep the time it had.

### Sensitive data
*Decided in review, on the plan's decision, which the owner is asked to
confirm ([Owner questions](#owner-questions)).*

#### What needs `log.view_sensitive`
* **The Security log, whole.** Its events are sign-ins, privilege use,
  process creation with command lines and account changes; ADR-0060 drops
  its messages, and on demand they would be shown in full. An event is
  in the Security log by the channel it names (`System/Channel`), so the
  rule follows it into ForwardedEvents and into exported files.
* **Sensitive fields by name**, ADR-0060's list, in any channel:
  `CommandLine` and `ParentCommandLine` (4688, Sysmon 1);
  `ScriptBlockText` (4104); `TaskContent` and `TaskContentNew` (4698 to
  4702); `ImagePath` (7045); `ServiceFileName` (4697); 5861's `CONSUMER`
  and `PossibleCause`; Sysmon 19's `Query` and 20's `Destination`.
* **And what repeats them**: an event with a sensitive field is shown
  without its message and without its XML, since both repeat the field,
  as ADR-0060 keeps it without its message.

Without the permission, each such field shows *hidden: needs permission to
see command lines and scripts*, the message and XML *hidden* likewise;
the event's other fields are shown.

#### Fields added to the list
On demand reaches channels ADR-0060 does not collect by default. Two are
known to hold command lines and parameter values, so the list gains, for
every user of it (ADR-0060 included):

* **PowerShell module logging, 4103**, in the PowerShell Operational logs:
  its `Payload` and `ContextInfo` fields (field names to be confirmed on
  the runners), which hold the cmdlets' parameters and the host's command
  line;
* **the *Windows PowerShell* log**, whose classic events (400, 403, 600,
  800) carry the host's command line in unnamed values (to be confirmed):
  every value of every event in it.

The list only ever grows by review, and a custom source can mark more
fields, never fewer (ADR-0060's rule).

#### Where it is enforced
* **The input says** whether the person asked for sensitive data:
  `sensitive: true` only when they hold `log.view_sensitive` in the
  device's organization from an organization-wide grant and chose the
  Security log or *Show command lines and scripts*. It is off by
  default for those who may.
* **On the computer**, with `sensitive: false`, the builtin refuses the
  Security channel, drops every event whose channel is Security (from
  ForwardedEvents, say), and writes sensitive fields, and the message and
  XML of their events, as withheld; the text match skips them. Sensitive
  values never reach the result file.
* **On the server**, with its own rules: a result for an input without
  `sensitive` that holds a Security event fails the run and is recorded as
  `eventlog.refused_on_device`; sensitive values, messages and XML the
  server's list classifies, which an agent of an older release let
  through, are removed before the result is stored, and counted on the
  run. A result is stored only after this check.
* **When it is read**, the definer function asks for `log.view_sensitive`
  again if the input had `sensitive: true`, so someone who lost the
  permission within the hour no longer reads it (an amendment of
  ADR-0067's function: a kind may require a second permission when its
  input says so).
* **Exports, copies and links** carry only what the reader was shown.

### States
In ADR-0065's words, for each page and channel:

| What happened | State | Shown as |
|---|---|---|
| Events returned | *Reported* | the events |
| The whole range searched, nothing matched | *Reported* | *No events match from T1 to T2* |
| A bound reached before the range's start | *Reported*, incomplete | *Searched N events back to T; more may match* and *Continue* |
| The channel is not on the computer (`ERROR_EVT_CHANNEL_NOT_FOUND`) | *Not found* | *No log named X on PC-12* |
| An event asked for by its record is no longer there | *Not found* | *This event is no longer in the log: it was overwritten or cleared* |
| Windows refuses access (`ERROR_ACCESS_DENIED`) | *Unavailable* | *Access denied to X* |
| An enabled circular Analytic or Debug channel | *Unavailable* | *Windows reads this log only while it is disabled* |
| The Event Log service not running (error code to be confirmed) | *Unavailable* | *The Event Log service is not running* |
| The agent lacks `builtin.eventlog` | *Unavailable* | *Update the agent* |
| The Security log or a sensitive field without the permission | *Refused by EasyRMM* | *Needs permission to see the Security log*, or the field hidden |
| A Linux device | *Unsupported* | no tab; the journal is ADR-0060's |
| The device offline | *Unknown* | *Offline since T*; nothing sent |
| No answer within 2 minutes, or a result without its last line | *Unknown* | *PC-12 did not answer*; lines received are shown, marked incomplete |

This is the requirement's "distinguish between events that could not be
retrieved and events that do not exist": *No events match* is said only
when the whole range was searched.

### Permissions
*Decided in review.*

| Permission | What | Who | Slice |
|---|---|---|---|
| `eventlog.view` | the Logs tab, every channel but Security, without sensitive fields | Technicians and above, at their sites | 1 |
| `log.view_sensitive` | ADR-0060's: the Security log and sensitive fields, in this mode and in ADR-0060's | Organization Administrators and above, from organization-wide grants only | 1 |
| `eventlog.manage` | channel settings, and clearing any log but Security | Site Administrators and above, at their sites | 4 |
| `eventlog.clear_security` | clearing the Security log | Organization Administrators and above, from organization-wide grants only | 6 |

* **Reading a result** needs `job.view_sensitive` as well, by F2's rule.
* **Organization-wide only**: `log.view_sensitive` and
  `eventlog.clear_security` join the permissions a site-scoped role never
  gets (`rbac.go:286`).
* **Why Technicians may query.** A Technician holds `device.terminal` at
  the same sites (`rbac.go:145-148`), a SYSTEM shell from which every log
  can be read; the viewer adds structure, bounds and a record of each
  query. ADR-0060's `log.view` is for fleet search and history and stays
  at Site Administrators, so on-demand queries get a permission of their
  own rather than lowering it (plan).
* **Why the Security log needs more than `log.view`.** This mode shows the
  original message and XML that ADR-0060 drops, so it is stricter than
  `log.view` for the Security log (plan, Risks). A Site Administrator
  sees collected sign-ins under ADR-0060 and not the Security log here.
* **Why management is not a Technician's.** Reading is what
  troubleshooting needs. Settings change what the computer keeps, and a
  clear destroys the record of other people's actions; neither is a
  routine click. The owner is asked ([Owner questions](#owner-questions)).
* **Read-Only** gets none of them: events carry user names, addresses and
  programs.
* **Step-up** ([ADR-0055](0055-lets-encrypt-in-one-step.md#step-up-authentication))
  for every `eventlog_manage` change and every `.evtx` download.
* [rbac.md](../../security/rbac.md) gains each permission with its slice.

### Audit
*Decided in review.*

| Action | When | Details |
|---|---|---|
| `eventlog.query` | a query's first page, a `channels`, `event`, `provider`, `summary` or `export` operation is created | device; operation; channels; levels, IDs, providers, tasks, the keywords mask, the time range; the text's length, not the text; whether sensitive data was asked for; the limits |
| `eventlog.refused` | the server refuses a request (the Security log without the permission, a refused channel name, a cursor not the caller's) | what was asked and the rule, within ADR-0063's bound |
| `eventlog.refused_on_device` | a result breaks the rules (a Security event when none was allowed, the wrong channel or range) | the rule broken; the system as actor, the person who asked in the details |
| `eventlog.export` | an export is downloaded (slices 2 and 5) | format, event count, size, whether sensitive, the query's record |
| `eventlog.configure` | a channel setting is changed or undone (slice 4) | device, channel, setting, value before and after, when the session stepped up, the warnings shown |
| `eventlog.clear` | a clear is created (slice 6) | device, channel, record count and size before, the backup's name, size and SHA-256 once reported, the typed confirmation matched, when the session stepped up |

* **No event data in any record.** The audit log outlives results, is
  forwarded (ADR-0023) and is read by every holder of `audit.view`; a
  message, a value or a hash of either would carry what the permissions
  protect (ADR-0064's hash rule).
* **Pages are not recorded**: a page with a cursor belongs to its query,
  whose record covers it, as ADR-0060 records a search and not its pages.
  The count read and returned is on each run.
* **The text's length only**, as ADR-0067 records a registry search: a
  searched user name or password is itself sensitive.
* **Refusals are bounded**: the migration that replaces
  `easyrmm_job_refusal` (`00028:84-114`) for ADR-0067 also counts
  `eventlog.refused` in its 20 per caller in 10 minutes (`:104-106`). If
  this slice is built first, it makes that replacement.
* Filters fit the 16 KiB of details (`audit.go:72`): 10 channel names of
  under 255 characters, 64 IDs or ranges and 16 providers are far below
  it.

### Offline devices, timeouts and load
*Decided in review.*

* **Offline.** The tab says when the device was last seen and sends
  nothing while it is offline. A query sent to a device that then stops
  answering is *Unknown* after 2 minutes.
* **Timeouts.** The run has 60 seconds; the builtin stops itself at 45
  and writes what it has, with the cursor where it stopped. If it is
  stopped anyway, the lines it wrote are sent (F2).
* **Leaving.** When the person changes the filter or leaves the tab, their
  open run is cancelled; the agent calls `EvtCancel`, then the job object
  ends the child.
* **Load on the computer.** The child is in the run's job object (memory,
  cancel); the Event Log service's own work is not
  ([Bounds](#bounds)). Two queries at most per device.

### The console
*Decided in review.*

* **A Logs tab** on a Windows device's page, for holders of
  `eventlog.view` at its site, beside Hardening
  (`DeviceDetailPage.tsx:61-68`), with one mode, *On the computer*, until
  ADR-0060 adds *Collected* (slice 3).
* **A header that stays in view**: the device's name, organization and
  site, whether it is online, *Read at*, Refresh, and the time zone shown.
* **The channel tree**, the filter bar ([Filters](#filters-into-the-query)),
  a list (level, time, provider, ID, task category, the log when several)
  and a details pane: *General* (the message), *Details* (fields, and the
  XML for those who may see it).
* **Copy** copies the event as text, the fields shown then the message,
  or its XML; only what is on the screen, and not recorded: it is already
  shown.
* **Links** to an event, by device, log, record number and time, open its
  details for whoever may see it.

### Presets, counts and saved searches
Slice 2. *Decided in review.*

* **Presets** for the requirement's diagnostics, each a saved filter in
  `internal/eventrules`, shared with features 10 and 2 (plan, How it
  relates). The IDs for unexpected shutdowns, Kernel-Power 41 and
  volmgr 46 are from Microsoft's page on event 41; every other provider
  and ID below is a candidate, to be confirmed against a Microsoft page
  listed in slice 2's pull request before it ships:

| Preset | Log and provider | IDs |
|---|---|---|
| Unexpected shutdowns | System: Kernel-Power 41, 6008; 1074 (User32) and 6006 | 41 and 6008; 1074 and 6006 shown beside them as the planned and clean ones |
| Blue screens | System: Kernel-Power 41 with a nonzero `BugcheckCode`; volmgr 46 | candidates: WER-SystemErrorReporting 1001 (to be confirmed) |
| Disk and storage errors | System: disk, Ntfs, volmgr, storage controllers | candidates: disk 7, 11, 51, 153; Ntfs 55, 98 (to be confirmed) |
| Windows Update failures | System: WindowsUpdateClient | candidate: 20 (to be confirmed) |
| Service crashes | System: Service Control Manager | candidates: 7031, 7034, 7023, 7024, 7000, 7009 (to be confirmed) |
| Application crashes | Application: Application Error, Application Hang, Windows Error Reporting | candidates: 1000, 1002, 1001 (to be confirmed) |
| Authentication failures | Security (needs `log.view_sensitive`) | candidates: 4625, 4771, 4776 (to be confirmed) |
| Driver errors | System: errors and criticals from drivers' providers | candidates: Service Control Manager 7026, Kernel-PnP 219 (to be confirmed) |
| Hardware errors and WHEA | System: WHEA-Logger | candidates: 1, 17, 18, 19, 46, 47 (to be confirmed) |
| Network connectivity problems | System and the NetworkProfile Operational log | candidates: DNS Client 1014, NetworkProfile 10001 (to be confirmed) |

* **Counts** (`summary`): for a filter and range, counts per provider, ID
  and level, the 100 largest, and counts per hour (ranges of up to 7
  days) or per day (up to 90), read with a render context for system
  values only (`EvtCreateRenderContext`), so that no message is formatted.
  Bounded at 1,000,000 events read and 45 seconds, saying how far back it
  counted. This answers *Identify recurring event IDs* and *Compare event
  occurrences over time* from the computer's own logs; slice 3 adds
  ADR-0060's history.
* **Archived logs**: the `Archive-<channel>-<timestamp>.evtx` files
  auto-backup writes in `%windir%\System32\winevt\Logs` are listed with
  their channel and can be searched like it, through `EvtQueryFilePath`.
  Only those names in that folder: a query never names another path.
* **Saved searches**: a person's own filters with a name, up to 50 each,
  in a table under row-level security by user; never results. Shared
  ones are the presets; others are not built until asked.

### Export
*Decided in review.*

* **Slice 2, CSV and JSON lines**, of the selected events or of a filter,
  built by the server from results it holds and checked:
  * **selected events**, from the person's own result, within its hour;
  * **a filter**, through an `export` operation that writes compact events
    (fields, data and the message cut to 1,024 characters, no XML) up to
    F2's 2 MiB: a few thousand events, and the file says where it stopped
    and offers the next part.
  CSV cells beginning with `=`, `+`, `-`, `@`, a tab or a carriage return
  get a leading `'`, as ADR-0060's exports do. Only what the person may
  see; recorded as `eventlog.export`.
* **Slice 5, files**: F2 gains a file a run hands back, for `.evtx` and for
  large exports.
  * **The capability** `job.files`. The builtin writes the file in the
    run's private folder; the agent compresses it with gzip and uploads it
    after the run, in signed requests of 1 MiB to a new agent endpoint,
    with the SHA-256 of the whole in the result.
  * **Stored in PostgreSQL**, in rows of 1 MiB under row-level security,
    as signed builds are kept as `bytea`
    (`server/migrations/00026_signed_agent_builds.sql:19`) and as
    ADR-0066 (accepted, not merged) keeps attachments: one place to back
    up and restore.
  * **At most 64 MiB compressed** per file; the builtin measures before
    uploading and stops with *the export would be N; narrow the time
    range*. One export at a time per device, three per person. Kept 24
    hours, then purged.
  * **`.evtx`**: `EvtExportLog` with the query into a new file, then
    `EvtArchiveExportedLog` so that the messages travel with it, both
    packed in one `.zip`. A `.evtx` cannot be masked, so every `.evtx`
    needs `log.view_sensitive` and step-up.
  * **JSON lines of up to 100,000 events** (ADR-0060's export bound), which
    the server decompresses, checks line by line with its rules as it
    checks a result, and stores again; CSV made from it on download.
  * **Downloads** as ADR-0066 serves attachments: as a download only,
    recorded first.

### Channel settings
Slice 4, after step-up (ADR-0055's slice 5b2, plan step 17). *Decided in
review.*

* **What can be set**: the maximum size (1 MiB to 4 GiB; Windows rounds to
  64 KiB); the retention mode, one of the three combinations Windows
  allows (auto-backup only with retention): *overwrite as needed*
  (retention off), *archive when full* (retention and auto-backup on),
  *do not overwrite* (retention on, auto-backup off);
  enabling or disabling a channel other than Application, System and
  Security, which Windows does not allow. Not offered: access lists, the
  file's path, isolation, Analytic and Debug publishing settings.
* **How**: `EvtOpenChannelConfig`, `EvtSetChannelConfigProperty`,
  `EvtSaveChannelConfig`; the result carries each value before and after,
  and *Undo* sets the old values back.
* **Warnings shown before the change**, and recorded:
  * *do not overwrite* stops a full log from recording; for the Security
    log it is refused without auto-backup (whether it can halt a computer
    with the policy that shuts down when auditing fails is to be
    confirmed);
  * *archive when full* keeps every archive, with no limit (Microsoft);
    the console shows the free space on the log's volume;
  * enabling an Analytic or Debug channel clears its events and takes an
    ETW session;
  * disabling a channel that holds security events (PowerShell, Sysmon,
    Defender, the Task Scheduler) stops its record; ADR-0060's sources
    are named.
* **Who owns the setting**: where W1's reader (ADR-0054) shows Group Policy
  or another manager sets it, the console says so before the change,
  which that owner may set back; where ADR-0060's *Configure logging*
  manages it on the device, the change is refused, pointing to its
  settings.
* **Sizes are checked** against the volume's free space plus 1 GiB.
* **One device at a time.** Setting sizes across a fleet is ADR-0060's
  *Configure logging*, for the channels it collects.

### Clearing a log
Slice 6, after slice 5. *Decided in review.*

* **Always saved first**: `EvtClearLog` with a backup path, a new `.evtx`
  in `%ProgramData%\EasyRMM\eventlog-backups`, a folder only SYSTEM and
  Administrators can read; refused when the volume lacks the log's size
  plus 1 GiB. The agent deletes backups after 30 days; until then they
  can be downloaded through slice 5 (`log.view_sensitive`, step-up).
* **Admin and Operational channels only.**
* **Step-up, and the device's and the log's names typed.**
* **`eventlog.clear_security` for the Security log**: Organization
  Administrators and above, from organization-wide grants. Clearing the
  Security log removes the record of every sign-in and change on the
  computer, EasyRMM's own sessions included, and is what someone covering
  their tracks does; it gets a permission of its own rather than riding
  on `eventlog.manage`.
* **Recorded** as `eventlog.clear`, with the backup's name and SHA-256.
* **Still an alert.** Windows records the clear (1102 in the Security
  log; 104 in the System log, to be confirmed). ADR-0060's *Log cleared*
  detection stays on for clears made through EasyRMM: the alert names
  the `eventlog.clear` record and its person instead of being
  suppressed. This amends ADR-0060's rule that "EasyRMM's own changes are
  not alerts" for this one detection: a stolen administrator account
  clearing logs through the console is what the alert is for.
* **Takes the change lock**, as every `eventlog_manage` run does.

### With ADR-0060
*Decided in review.*

* **Never duplicated**: one event model, one classification, one
  `log.view_sensitive`, one reader of the Event Log API, one set of
  states. Whichever is built first builds them; the other uses them.
* **Two modes of one tab** (slice 3):

| | On the computer (this ADR) | Collected (ADR-0060) |
|---|---|---|
| Where the events are | on the computer, read when asked | EasyRMM's log store |
| Which | every channel, the whole local history | the sources and filters collected |
| History | as far back as the computer keeps | ADR-0060's retention, after the computer is gone |
| Message and XML | yes, by the rules above | messages capped, dropped for Security and sensitive events; no XML |
| Across devices | no: one device | fleet search |
| Who | `eventlog.view` | `log.view` |
| Detections, forwarding | no | yes |

* **From a collected event to the computer**: a collected event keeps its
  device, channel, record number and time, so *Open on the computer* runs
  `event` for it, and a query over ten minutes either side in that
  channel. If the log has moved on: *Not found on the computer: it was
  overwritten or cleared since*.
* **Trends over history** come from ADR-0060's counts per code (plan);
  slice 2's counts cover what the computer still holds.

### Windows versions
Every Windows version the agent supports: Windows 10 and Windows Server
2016 and later, on x64 and ARM64
([ADR-0020](0020-windows-agent.md#one-agent-built-for-windows)). Every
Event Log API function used dates from Windows Vista and Windows Server
2008, and the time zone conversion from Windows 7 and Windows Server
2012. What differs between versions is which channels and providers
exist, which the channel list shows as it finds it. CI covers the images
GitHub names `windows-latest` and `windows-11-arm`; Windows 10, Windows
Server 2016, 2019 and 2022 are to be confirmed on real computers or
ADR-0054's machines before the guide lists them as verified.

### Linux
*Decided in review.* Not in this ADR. The requirement names Windows; the
plan gives Linux's journal to ADR-0060, which reads it with
`journalctl --follow --all --output=json` and the auditd log. An
on-demand journal view would be another builtin running
`journalctl --output=json --all --reverse` with a cursor (the
`sd-journal` library needs cgo, which the agent's builds do not use,
`Makefile:133`), and syslog files under `/var/log` would be read as text.
Whether it is wanted is the owner's ([Owner questions](#owner-questions)).
Until then a Linux device has no *On the computer* mode, and the API
answers *unsupported*.

### Not chosen
* **A `Get-WinEvent` script**: see [the kinds](#code-in-the-agent-not-a-script).
* **`wevtutil qe`** run by the agent: the query on its command line, where
  process auditing and other processes see it; text to parse; a process
  per page.
* **WMI's `Win32_NTLogEvent`**: classic logs only and no XML (to be
  confirmed); no operational channels.
* **Remote event log sessions** (`EvtOpenSession` from a server or a jump
  box): firewall rules and credentials EasyRMM does not have or want.
* **Running in the agent's own process**: a hang in the Event Log API
  would stop the agent (ADR-0067's reason).
* **XPath or Event Viewer's XML queries from the console**: the server
  would have to parse and check any query (paths in `Select` and
  `Suppress`, the Security log under another spelling) before sending
  it; typed filters can be checked completely. Event Viewer's custom views
  are not imported.
* **`EvtQueryTolerateQueryErrors`**: failures hidden as matches.
* **Regular expressions for text**: cost that depends on the pattern.
* **A live tail** (`EvtSubscribe`): ADR-0060's collector; not asked.
* **Keeping events on the server longer than an hour, or caching them**:
  on demand costs no storage beyond its hour; history is ADR-0060's.
* **Decrypting Protected Event Logging**: the key is not EasyRMM's.
* **A clear without a backup.**
* **The Security log for `log.view` holders**, without sensitive fields
  and messages: possible, but this mode's point is the original event; an
  owner question if wanted.

### What this does not fix
* **A Technician still has the terminal**, and can read the Security log
  with `wevtutil` as SYSTEM. The viewer's split binds the viewer, as
  ADR-0060's binds its search.
* **The classification catches field names**, not every secret: an
  application that writes a password into its message is shown to
  Technicians.
* **The Event Log service's work** during a query is outside the job
  object.
* **Results stay in database backups** made within their hour, as
  ADR-0063 says of output.
* **The computer's logs wrap**; history beyond them is ADR-0060's.
* **Group Policy sets back** channel settings it owns; the console warns.
* **Rules reach the computer with the agent's update**: a field added to
  the list holds on the server at once, and on the computer once it
  updates.

## The requirements
Feature 9 of the owner's requirements, bullet by bullet.

| Requirement | Where | Status after this ADR |
|---|---|---|
| Application | Channels (slice 1) | New |
| System | Channels (slice 1) | New |
| Security | Channels; Sensitive data (slice 1) | New, with `log.view_sensitive` |
| Setup | Channels (slice 1) | New |
| Forwarded Events | Channels; Messages (slice 1) | New: messages from `RenderingInfo`; forwarded Security events need `log.view_sensitive` |
| Microsoft-Windows operational and diagnostic logs | Channels (slice 1) | Operational: new. Analytic and Debug: listed and read oldest first where Windows allows; enabling them is slice 4 |
| Browse available event logs and inspect their contents | Channels; Queries (slice 1) | New: every channel, its size, records and oldest event |
| Filter by event ID | Filters (slice 1) | New: IDs, ranges, exclusions |
| Filter by severity | Filters (slice 1) | New: the six levels |
| Filter by event source/provider | Filters (slice 1) | New |
| Filter by event category | Filters (slice 1) | New: the provider's task, by name |
| Filter by date and time | Filters (slice 1) | New |
| Filter by keyword | Text; Filters (slice 1) | New: text after the query, and Event Viewer's keywords |
| Filter by log name | Filters (slice 1) | New |
| Support multiple filter conditions | Filters (slice 1) | New: and between filters, or within one |
| Search across multiple logs | Several logs (slice 1) | New: up to 10, merged by time |
| Support custom time ranges | Filters (slice 1) | New |
| Event ID | Fields (slice 1) | New, with qualifiers for classic events |
| Event level | Fields (slice 1) | New |
| Event source/provider | Fields (slice 1) | New |
| Event timestamp | Times (slice 1) | New: UTC as recorded; the viewer's or the computer's time |
| Event log name | Fields (slice 1) | New: the log read and the channel named |
| Event description | Messages (slice 1) | New: *Description unavailable* kept apart |
| Event data | Fields (slice 1) | New; sensitive fields by permission |
| Associated user where available | Users and computers (slice 1) | New: SID and account |
| Computer name | Users and computers (slice 1) | New, as recorded |
| XML event details | Fields; Sensitive data (slice 1) | New |
| Refresh event logs | Order, pages and the cursor (slice 1) | New: Refresh and *Read at* |
| Search historical events | Queries (slice 1); archived logs (slice 2); With ADR-0060 (slice 3) | The computer's whole history, its archives, then collected history |
| Export selected events | Export (slice 2) | New: CSV and JSON lines |
| Export filtered results | Export (slices 2 and 5) | A result's worth in slice 2; up to 100,000 events and `.evtx` in slice 5 |
| View raw XML | Fields (slice 1) | New |
| Copy event details | The console (slice 1) | New |
| Save frequently used searches | Saved searches (slice 2) | New: personal; presets shared |
| Identify recurring event IDs | Counts (slice 2); With ADR-0060 (slice 3) | New |
| Compare event occurrences over time | Counts (slice 2); With ADR-0060 (slice 3) | New |
| Unexpected shutdowns | Presets (slice 2) | New |
| Blue screen events | Presets (slice 2) | New |
| Disk and storage errors | Presets (slice 2) | New |
| Windows Update failures | Presets (slice 2) | New |
| Service crashes | Presets (slice 2) | New |
| Application crashes | Presets (slice 2) | New |
| Authentication failures | Presets (slice 2) | New, with `log.view_sensitive` (the Security log) |
| Driver errors | Presets (slice 2) | New |
| Hardware errors | Presets (slice 2) | New |
| Network connectivity problems | Presets (slice 2) | New |
| WHEA hardware errors | Presets (slice 2) | New |
| Security event logs may require elevated privileges | Permissions; Sensitive data | The agent reads as SYSTEM; EasyRMM's `log.view_sensitive` decides who sees |
| Large event logs without excessive resource consumption | Bounds | Bounded on the computer by count, events read, time, bytes and memory; the service's own work by time |
| Pagination for large result sets | Order, pages and the cursor | Pages with a cursor per channel |
| Preserve the original event timestamp and details | Times; Fields | Kept as recorded; XML unchanged |
| Distinguish events that could not be retrieved from events that do not exist | States | *No events match* only after the whole range; *incomplete*, *Unavailable*, *Unknown*, *Not found* apart |
| Support supported Windows versions | Windows versions | The agent's: Windows 10 and Server 2016 and later, x64 and ARM64 |
| "Event Log Management" (the title) | Channel settings (4); Export (5); Clearing (6) | Later slices; clearing is an owner question |

The requirements' overall expectations, where they bear on this feature:

| Expectation | Where | Status after this ADR |
|---|---|---|
| 1. Multi-tenant permission boundaries | Permissions | At each device's site, under row-level security; organization-wide grants for the Security log |
| 2. Execution history and results | The kinds; Audit | Queries recorded; results kept an hour for the asker; changes kept with their results |
| 3. Success, failure and meaningful errors | States | Every Windows error named; incomplete pages say why |
| 4. Organization, site, group and device targeting | — | One device; fleet search is ADR-0060's, fleet log sizes its *Configure logging* |
| 5. Reporting and notifications | — | None from on demand; ADR-0060's detections, including clears made here |
| 6. Permissions and audit records for sensitive operations | Permissions; Audit | New |
| 7. Healthy, unhealthy, unknown, unsupported and unavailable | States | *Reported*, *Unknown*, *Unsupported*, *Unavailable*, *Not found*, *Refused by EasyRMM*; healthy and unhealthy do not apply, since EasyRMM judges no event |
| 8. Offline and reconnecting endpoints | Offline devices | Nothing sent while offline; *Unknown* after 2 minutes; settings and clears wait 15 minutes |
| 9. Supported and unsupported environments | Windows versions; Linux | Windows 10 and Server 2016 and later with an agent that lists the builtin; Linux unsupported |
| 10. Real-world MSP operations, not demonstrations | Testing | Native code, so App Control and `AllSigned` do not take it away; verified on CI's Windows runners as LocalSystem and on a real Windows computer before the guide calls it verified |

## Slices
*Decided in review.* Each merges and is verified on its own, at every
level it touches.

1. **On demand, one device** (plan step 16, after ADR-0067's F2 at step
   15 and ADR-0064's `accepts` at step 6). Three pull requests:
   * **rules and server**: `internal/eventrules` (model, classification,
     query builder, inputs and results v1); `eventlog.view` and
     `log.view_sensitive` with the site-scope rule; the `eventlog_query`
     kind and its settings; the definer function's second permission;
     the refusal bound; `eventlog.query`, `eventlog.refused`,
     `eventlog.refused_on_device`;
   * **the builtin**: `agent/winevent` and `builtin eventlog` with
     `channels`, `query`, `event` and `provider`;
     `builtin.eventlog.v1`;
   * **the console**: the Logs tab, *On the computer*.

   *Verified*: integration tests; agent tests; the builtin on the Windows
   runners, x64 and ARM64, as LocalSystem; the end-to-end test; on a real
   Windows computer of the owner's test instance, a query's time from
   click to list, before the guide calls it verified. If F2 is not built
   by then, this slice builds it as ADR-0067 defines it.
2. **Presets, counts, archived logs, saved searches, export as CSV and
   JSON lines** (among step 28). `builtin.eventlog.v2`, `eventlog.export`.
3. **With ADR-0060** (after step 26): both modes in one tab; *Open on the
   computer*; trends from ADR-0060's counts.
4. **Channel settings** (among step 28, after step-up at step 17):
   `eventlog_manage`, `eventlog.manage`, `eventlog.configure`, undo, the
   change lock.
5. **Files**: `job.files`, the agent's upload, storage and purge;
   `eventlog_export`; `.evtx`; JSON lines up to 100,000 events.
6. **Clearing** (after 5): `clear`, `eventlog.clear_security`,
   `eventlog.clear`, ADR-0060's detection amended. Built only if the
   owner wants it ([Owner questions](#owner-questions)).

## Consequences
* Technicians can read a Windows computer's event logs from the console,
  without the Security log and command lines, with each query recorded;
  Organization Administrators can read those too.
* The agent gains `builtin.eventlog`, a child process of its own program
  reading the Event Log API from Go; an agent of the release before keeps
  running everything it ran, gets no event log job, and the console says
  to update it.
* `log.view_sensitive` and the classification of sensitive fields exist
  before ADR-0060 is built, which reuses them; the list gains 4103's
  fields and the *Windows PowerShell* log.
* Permissions gain `eventlog.view` and `log.view_sensitive`, then
  `eventlog.manage` and `eventlog.clear_security`; the audit log gains the
  six actions above; the refusal bound counts `eventlog.refused`.
* The jobs' kinds gain `eventlog_query`, then `eventlog_manage` and
  `eventlog_export`; F2 gains a second permission per input and, in slice
  5, files a run hands back.
* A query's Event Log service work is not capped by the job object;
  measured, bounded by time and by two queries per device.
* No PowerShell runs for the viewer, so it writes nothing into the
  PowerShell logs it reads.

## Testing
* **Integration tests** in Go against real PostgreSQL through `testdb`
  (`make test-db`), without mocks:
  * **Permissions**: every role on every endpoint; `log.view_sensitive`
    from a site-scoped grant ignored; a query asking for the Security log
    without it refused (`403`, recorded within the bound, counted with
    ADR-0063's actions).
  * **Results**: an input and its result read by the person who asked and
    refused to another Technician of the site, through `/result` and
    `/arguments`; a sensitive result refused to its asker once the
    permission is taken away; the purge emptying them after the hour and
    not before.
  * **The server's check**: results as an agent sends them, built in the
    test: a Security event in a result for an input without `sensitive`
    failing the run and recorded; a `CommandLine` value, the message and
    the XML of its event removed before storing and counted; an event
    from a channel not asked for, or outside the range, failing the run;
    a cursor not the caller's refused.
  * **The query builder**: a table of filters and the structured queries
    they make; quotes, `&`, `<` and `>` in providers; channel names with
    each refused character; the limits; *Information* as 0 or 4.
  * **Records**: one `eventlog.query` per query, none per page; no record
    holding an event's value (a random marker written into an event's
    text appears in no record, list or job answer); the text's length,
    not the text.
* **Agent tests** in Go on every platform: the input versions; the result
  lines; the builtin's entry refusing a non-Windows platform.
* **The builtin on CI's Windows runners, as LocalSystem.** A job in a
  matrix over `windows-latest` (x64) and `windows-11-arm` (ARM64) builds
  the agent's Windows test binary and runs it as LocalSystem through a
  scheduled task, as ADR-0064's and ADR-0067's tests do. Go tests of
  `agent/winevent` and the builtin, writing real events and reading them
  back:
  * **a test source**, registered under a random name with
    `x/sys/windows/svc/eventlog` (`InstallAsEventCreate`) and removed
    after: information, warnings and errors with known IDs and a random
    marker; queries by ID, range, exclusion, level, provider, time and
    text; newest first; pages with the cursor while the test keeps
    writing, with no event twice and none missing; a task category
    written with `ReportEvent` and found by its number;
  * **several logs**: the test source's events with Service Control
    Manager's in System, from a test service started and stopped, merged
    by time;
  * **messages**: the test source's formatted; *Description unavailable*
    after its registration is removed, with the values shown; a provider
    with task names formatted;
  * **sensitive fields from Windows itself**, with the marker in each:
    process creation auditing with command lines turned on and a process
    started (4688); script block and module logging turned on and a
    script run (4104, 4103); a test service created with `sc create`
    (7045); a permanent WMI subscription made and removed (5861); then,
    with `sensitive: false` and the server's check skipped, the marker
    absent from the result file's bytes, the Security log refused, and
    the text search not finding it; with `sensitive: true`, present;
    4103's field names and the *Windows PowerShell* log's layout recorded
    for the list;
  * **Protected Event Logging** with a test certificate: a 4104 shown as
    encrypted (to be confirmed on both images);
  * **bounds**: a classic test log filled to 256 MiB, searched for text
    that is not there: the page stopping at 45 seconds with the cursor and
    how far back it searched, the child's memory peak, and the Event Log
    service's processor time during the scan, printed; 100 events and the
    byte bound; an event with a 1 MiB value;
  * **channels**: every channel listed; an Analytic channel found on the
    image by its type, listed and its state shown;
  * **times**: fixed UTC instants in winter and summer converted for a
    zone with daylight saving set on the runner with `tzutil`;
  * **no PowerShell** and no `wevtutil` started by the builtin;
  * **slices 4 to 6** on the test log: sizes, retention modes, undo;
    Application, System and Security refused for enabling; an export and
    an archived export read back; a clear with its backup read back,
    and 104 written (confirming it).
* **Machine tests**, with ADR-0054's Windows machines under KVM: a domain
  account's SID resolved, and one unresolved with the domain controller
  stopped; ForwardedEvents through a Windows Event Collector subscription
  between two machines, with and without `RenderingInfo`; Sysmon's events
  (1, 19, 20); Group Policy setting a log's size; App Control on, the
  builtin still working.
* **Page tests** (`web/src/pages/devices/`): the tab only for Windows and
  `eventlog.view`; every state; hidden fields; the Security log marked for
  those without the permission; the time zone switch.
* **The browser end-to-end test** (`make e2e`), with the simulated agent
  (`web/e2e/agent.ts`) taught `job.structured` and `builtin.eventlog.v1`
  and answering with results the real builtin produced on a runner, with
  the runner's computer name, domain and machine SIDs replaced by
  placeholders when recorded (a test fails if a recorded result holds the
  runner's own name): a technician opens the Logs tab, queries System,
  opens an event and its XML; a Technician sees the Security log refused;
  an Organization Administrator reads it; a Read-Only user sees no tab;
  the audit log shows the records. The simulated agent is a stand-in: it
  does not run the builtin, which is tested on the runners and on a real
  computer.
* **Real computers**: queries, details and a page past the first on a real
  Windows computer of the owner's test instance, before the guide calls
  them verified.
* The coverage floors in `scripts/ci/check-coverage.sh` hold for the
  packages touched.

## To be confirmed
Not verified for this ADR, each checked before the slice that relies on
it ships:

* that the Event Log API refuses `contains()` (it is absent from
  Microsoft's list of functions);
* that Event Viewer's *Information* covers levels 0 and 4, and the form of
  its absolute time filter;
* the masks of the standard keywords (*Audit Success*, *Audit Failure*);
* the language messages come in for the SYSTEM account;
* the Security log's default access list, and that SYSTEM reads it;
* System log clears writing 104;
* what `EvtFormatMessage` returns when inserts cannot be resolved;
* forwarded events without `RenderingInfo`;
* classic providers' categories in their metadata, and
  `EvtOpenPublisherEnum`;
* 4103's field names and the *Windows PowerShell* log's layout;
* the error a query gets when the Event Log service is stopped;
* the presets' candidate IDs;
* Windows 10 and Windows Server 2016, 2019 and 2022, beyond CI's images;
* whether *do not overwrite* on a full Security log can halt a computer;
* `Win32_NTLogEvent`'s reach (only in *Not chosen*).

## Owner questions
1. **On-demand queries for Technicians** (the plan's question 15).
   Decided in review: Technicians and above query a computer's logs on
   demand with `eventlog.view`, without the Security log and sensitive
   fields, which need `log.view_sensitive` (Organization Administrators
   and above, organization-wide grants), so ADR-0060's `log.view` is not
   lowered. Is that the split you want, or should Site Administrators,
   who hold `log.view`, also read the Security log here without
   sensitive fields?
2. **Managing logs.** The requirement's bullets ask for reading; only its
   title says management. Are channel settings and clearing wanted? If
   so, decided in review: settings and clearing other logs at Site
   Administrators and above, clearing the Security log at Organization
   Administrators and above with a permission of its own, each with
   step-up. Should either sit elsewhere?
3. **Linux.** An on-demand view of a Linux computer's journal and syslog
   files is not in the requirement; ADR-0060 collects the journal. Is one
   wanted?

## References
* EvtQuery:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery
* EVT_QUERY_FLAGS:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_query_flags
* Consuming events (the XPath subset, structured queries):
  https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events
* EvtNext:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext
* EvtCancel:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcancel
* EVT_RENDER_FLAGS:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_render_flags
* EvtCreateRenderContext:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcreaterendercontext
* EvtFormatMessage:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtformatmessage
* EVT_FORMAT_MESSAGE_FLAGS:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_format_message_flags
* Formatting event messages:
  https://learn.microsoft.com/en-us/windows/win32/wes/formatting-event-messages
* EvtOpenPublisherMetadata:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtopenpublishermetadata
* EVT_PUBLISHER_METADATA_PROPERTY_ID:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_publisher_metadata_property_id
* SystemPropertiesType (the event's System fields):
  https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype
* StandardEventLevel:
  https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.standardeventlevel
* EvtOpenChannelEnum:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtopenchannelenum
* EVT_CHANNEL_CONFIG_PROPERTY_ID:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_channel_config_property_id
* EVT_CHANNEL_TYPE:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_channel_type
* ChannelType complex type:
  https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-channeltype-complextype
* ChannelLoggingType complex type:
  https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-channelloggingtype-complextype
* EvtGetLogInfo:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtgetloginfo
* EVT_LOG_PROPERTY_ID:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_log_property_id
* EvtSetChannelConfigProperty:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsetchannelconfigproperty
* EvtClearLog:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtclearlog
* EvtExportLog:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtexportlog
* EvtArchiveExportedLog:
  https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtarchiveexportedlog
* wevtutil:
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
* SystemTimeToTzSpecificLocalTimeEx:
  https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-systemtimetotzspecificlocaltimeex
* Event ID 41 and related restart events:
  https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart
* Event 1102, the audit log was cleared:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
* Command line process auditing:
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
* about_Logging_Windows (PowerShell 7.5):
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5
* Sysmon:
  https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
