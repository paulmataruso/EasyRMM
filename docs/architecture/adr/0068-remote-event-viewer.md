# ADR-0068: Remote Windows event viewer and event log management

* Status: Accepted (2026-11-21, after an independent review). Not
  implemented.
* Nothing here was decided by the owner. Everything marked as decided was
  decided in review, and the owner can overturn it; the
  [owner questions](#owner-questions) list what is the owner's.
* Revised after an independent review (2026-11-21): the Security log's
  settings take the permission that clears it and only *overwrite as
  needed*, since a full Security log can stop a computer; slice 5's
  check on the server is bounded and runs in the background; Technicians'
  on-demand view of sign-in and process events is stated as a change to
  ADR-0060's privacy terms; cancelling reaches the query inside the
  child; the cursor notices a cleared log; the server reads each event
  from its XML and drops a text match it had to redact; the sensitive
  list gains three fields; one size budget per encoded line; clear
  backups and exports are sized and capped. Each is in its section.
* Amends, each gaining an *Amended by ADR-0068* line when this is
  implemented:
  * [ADR-0017](0017-scripts-and-jobs.md): the job kinds
    `eventlog_query`, and in later slices `eventlog_manage` and
    `eventlog_export`.
  * [ADR-0060](0060-collecting-logs.md) (proposed): its classification of
    sensitive fields and `log.view_sensitive` are built here first, as
    the plan asks; the list gains PowerShell's module logging fields, the
    *Windows PowerShell* log and three fields of other providers
    ([Sensitive data](#sensitive-data)); `log.view_sensitive` also opens
    the Security log on demand, beside command lines and scripts; its
    [Privacy](0060-collecting-logs.md#privacy) section and
    [PRIVACY.md](../../../PRIVACY.md) say that Technicians see one
    computer's sign-in and process events outside the Security log on
    demand, without sensitive fields
    ([Permissions](#permissions)); its Logs tab gains *On the computer*;
    a log cleared through EasyRMM still opens its *Log cleared* alert
    ([Clearing a log](#clearing-a-log)).
  * [ADR-0063](0063-who-sees-job-output-and-arguments.md): its refusal
    bound counts `eventlog.refused`; a result read asks for
    `log.view_sensitive` as well when the query asked for sensitive
    data, as ADR-0063 foresaw ("The output endpoint would then ask for
    both").
  * [ADR-0067](0067-remote-registry-editor.md) (the registry editor,
    accepted): F2 gains a
    second permission a kind may require when its input says so, a
    definer function that builds a query's next page from its stored
    input and result, and in slice 5 a file a run may hand back.
  * [ADR-0054](0054-hardening-windows-computers-and-servers.md#the-job)
    (accepted 2026-11-22): "one change at a time on a device" covers
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
  for states),
  [ADR-0066](0066-customer-documentation-and-assets.md#attachments-and-diagrams)
  (files kept in PostgreSQL in chunks, downloads recorded first, a limit
  for the deployment), ADR-0067's F2 (kinds with an input and a result, the
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
  9. **The sensitive list grows**: PowerShell's module logging (4103),
     the *Windows PowerShell* log, Shell-Core's run-key commands, Sysmon
     13's registry data and BITS' URLs, which ADR-0060 does not collect
     by default and which on-demand queries reach.

## Context
Each repository claim was checked at `main` `b674a7f` (since `6e977bd`,
only ADR-0066 and the index changed).

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
| Input and result read by | the person who asked, holding `eventlog.view` and `job.view_sensitive` at the device's site, and `log.view_sensitive` in its organization when the query asked for sensitive data | holders of `eventlog.manage` (for the Security log, `eventlog.clear_security`) and `job.view_sensitive` at the device's site | the person who asked, holding `eventlog.view` and `job.view_sensitive` at the device's site, and `log.view_sensitive` for a `.evtx` file or JSON lines that asked for sensitive data |
| Each read recorded | no: only the asker reads it, and the query's record covers it | no: it holds settings, never events | the download, `eventlog.export` |
| Waits for an offline device | 2 minutes | 15 minutes | 15 minutes |
| Timeout and lane | 60 seconds, quick | `configure` and `undo` 60 seconds, quick; `clear` 10 minutes, the normal lane | 10 minutes, the normal lane |
| In the Jobs list | under its filter only | under its filter only | under its filter only |
| Change lock | no | yes | no |

* **One query open per person and device, two per device, one running.**
  A new filter, page or refresh from the same person cancels their run
  still open on that device (ADR-0054's runs the server cancels, which F2
  extends); a third open query on one device is refused: "two searches
  are already open on PC-12". The claim delivers an event log run to
  a device only while none is running there, so at most one of the quick
  lane's two slots holds an event log query, and registry reads are not
  starved by searches.
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
  a query handle belongs to the thread that made it.
* **Cancelling reaches the query, not only the process.** The agent
  starts the child with a pipe on its standard input and closes it to
  cancel (a person's new filter, a server cancel, the run's timeout).
  Inside the child a watchdog goroutine waits for that end of input or
  for its own 45-second limit, then calls `EvtCancel` on the handles the
  query thread is using, as Microsoft describes (the operation returns
  `ERROR_CANCELLED`); the query thread writes the lines it has and its
  last line, and the child exits. The agent waits 5 seconds after
  closing the pipe before the job object ends the child, so that the
  Event Log service is told to stop rather than left scanning for a
  client that is gone. Whether the service stops work for a killed
  client is measured ([Testing](#testing)).

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

With the list comes the computer's `CrashOnAuditFail` value, read from
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, shown on the Security log's
page and used by [Channel settings](#channel-settings): with 1, a
computer whose Security log fills and cannot overwrite stops with
`STOP 0xC0000244`, and the value becomes 2, after which "only
administrators may log on" (Microsoft's pages on the policy and on the
value, [References](#references)).

The console groups them: *Windows Logs* (Application, Security, Setup,
System, ForwardedEvents), then the others by provider, split at the `/`
of a name such as `Company-Product-Component/Operational` (the naming
convention Microsoft's channel schema describes); Analytic and Debug
channels behind *Show analytic and debug logs*. The Security log is
listed for everyone, marked *needs permission to see the Security log*
for those without `log.view_sensitive`. The list is kept by the console
for its session and refreshed on request; it costs about a second of the
run (to be measured).

**Channel names are compared ignoring case**, by the server and the
agent (Unicode simple case folding), and a query's channels are
deduplicated the same way before it is built, so that `SECURITY` or
`security` is the Security log for every rule and no channel is read
twice; whether Windows itself opens a channel by any case is to be
confirmed, and does not matter once both checks fold case.

### Queries

#### Filters into the query
The server builds the query from typed filters; nobody sends XPath
([Not chosen](#not-chosen)). Within a filter the values are alternatives
(or); between filters every one must hold (and).

| Filter | Into | Limits |
|---|---|---|
| Logs | one query per channel | 1 to 10 channels, names checked against Windows' rules, compared and deduplicated ignoring case; the Security log and its archives (`Archive-Security-*`) refused by the server before anything is sent, without `log.view_sensitive` |
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
  next page adds `EventRecordID < n` for that channel (`> n` for an
  Analytic or Debug channel, read oldest first). If record numbers only
  grow within a log (to be confirmed: Microsoft's pages describe the
  field, not its order), events written while the person reads appear at
  the next refresh, not in the middle of the pages, and none repeats.
* **A cleared or wrapped log is noticed.** With each channel's position
  the cursor keeps the log's creation time and its oldest record number
  (`EvtGetLogInfo`'s `EvtLogCreationTime` and
  `EvtLogOldestRecordNumber`), read when the first page ran. When the
  creation time has changed, the next page says *This log was cleared
  since the first page* and offers to start again; when the oldest
  record has passed the cursor, *Events after T were overwritten since
  the first page*. Analytic and Debug channels, for which Windows gives
  no oldest record, are checked by creation time where Windows gives it,
  and otherwise say they cannot tell.
* **The cursor is the server's.** The console names the previous page's
  run, never a cursor. A definer function, owned by `easyrmm_owner` with
  `search_path = pg_catalog, public, pg_temp` like ADR-0067's, checks
  that the caller asked for that run, on the same device, within the
  hour, and returns its stored filters and the cursor from its stored
  result; the server builds the next page's input from those. The
  filters are therefore the same by construction, and `easyrmm_app` gains
  no grant on the input or the result.
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
| Time | the builtin stops itself at 45 seconds of the run's 60 (30 for `channels`, `event` and `provider`), cancelling with `EvtCancel` | as above |
| Memory | F2's 512 MiB job-object limit; batches of 32 handles closed after each is written; at most 256 providers' metadata cached | the child is stopped by the job object, and the lines written so far are sent |
| One event | its line as encoded (below): 32 KiB in a page, 1.5 MiB from the `event` operation; at most 256 values | the event is cut and marked, and the cursor moves past it |

**One budget per event, on the encoded line.** The builtin writes each
line with Go's JSON encoder with `SetEscapeHTML(false)`, so that `<`,
`>` and `&` in the XML are not written as six-byte escapes, and measures
the line as encoded, the base64 of `raw` values ([Fields](#fields))
included, before writing it. An event keeps at most 256 values; those
after are dropped and counted. A line over its budget is cut in this
order until it fits: the message to 4,096 characters, then each value to
1,024, each cut made alike in the fields and in the XML and marked in
both, so that the server's comparison still holds; last, the event is
sent as its `System` element alone, with no data or message, marked *too
large for the list: open it*. The `event` operation does the same at
1.5 MiB, cutting the message at 256 KiB and values at 64 KiB, and ends
at *too large to show here*, offering the `.evtx` export to those who
may (slice 5). Every cut is marked, and an event however large takes one
line and moves the cursor: it never stops a page or holds it on the
same event.

**The Event Log service's own work is outside the job object.** Windows
filters events in the Event Log service, so a query over a large log costs
that service's processor time until the page fills, the log ends or the
builtin cancels; the job object does not count it. Bounded by the time
limit, the cancel that reaches the query, one query running per device
and two open; slice 1 measures it on a log filled to 256 MiB on the
runners ([Testing](#testing)).

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
* the names of fields withheld ([Sensitive data](#sensitive-data));
* **its XML** as Windows renders it (`EvtRenderEventXml`), with only the
  values the caller may not see replaced by a fixed marker. The fields
  above are the builtin's reading of that XML, and the server reads the
  XML again for itself ([Where it is enforced](#where-it-is-enforced)).

**NUL characters and lone surrogates** follow ADR-0067's rule: PostgreSQL's
`jsonb` refuses `\u0000` and lone surrogates, so a string holding either
is sent as `raw` (base64 of its UTF-16 bytes) with a `display` text in
which each such character is a visible escape, and a flag; it is shown
read-only, copied and exported as the display text, and the server's
decoder refuses a result with a `\u0000` or lone surrogate escape
anywhere.

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
* **Matched on leaf names**, at any depth: an `EventData/Data` element by
  its `Name`, and any element under `UserData` by its own name, since some
  events keep their values there (5861's `CONSUMER` is in `UserData`).
* **And what repeats them**: an event with a sensitive field is shown
  without its message, and its XML with those values and its
  `RenderingInfo` message replaced by the marker, since the message
  repeats the field, as ADR-0060 keeps such an event without its
  message.

Without the permission, each such field shows *hidden: needs permission to
see command lines and scripts*, the message *hidden* likewise; the
event's other fields, and its XML with the marker, are shown.

#### Fields added to the list
On demand reaches channels ADR-0060 does not collect by default, some
known to hold command lines, parameter values and addresses with tokens.
The list gains, for every user of it (ADR-0060 included); each field's
name, and what each event records, is to be confirmed on the runners or
ADR-0054's machines before the slice ships:

* **PowerShell module logging, 4103**, in the PowerShell Operational logs:
  its `Payload` and `ContextInfo` fields, which hold the cmdlets'
  parameters and the host's command line;
* **the *Windows PowerShell* log**, whose classic events (400, 403, 600,
  800) carry the host's command line in unnamed values: every value of
  every event in it;
* **Shell-Core 9707 and 9708** (the Shell-Core Operational log's run-key
  commands): `Command`;
* **Sysmon 13** (a registry value set): `Details`, the value's data;
* **the BITS client's** Operational log: `url`, which can carry a
  download's token.

The last three names are common words that other providers use for
harmless values, so they match only within their provider (Shell-Core,
Sysmon, the BITS client); ADR-0060's names match in every provider. The
list only ever grows by review, and a custom source can mark more fields,
never fewer (ADR-0060's rule).

**The classification is not a boundary.** It keeps known command lines,
scripts and URLs out of casual sight, in lists, exports and copies, and
out of bulk reading; it cannot find every secret an application writes,
and a Technician can read any log through the terminal
([What this does not fix](#what-this-does-not-fix)).

#### Where it is enforced
* **The input says** whether the person asked for sensitive data:
  `sensitive: true` only when they hold `log.view_sensitive` in the
  device's organization from an organization-wide grant and chose the
  Security log or *Show command lines and scripts*. It is off by
  default for those who may.
* **On the computer**, with `sensitive: false`, the builtin refuses the
  Security channel and its archives (`Archive-Security-*`), drops every
  event whose channel is Security (from ForwardedEvents, say), and writes
  sensitive values, and the message of their events, as withheld, in the
  fields and in the XML; the text match skips them. Sensitive values
  never reach the result file.
* **On the server**, with its own rules, reading each event from its XML:
  * **the XML is parsed** with `encoding/xml` by `internal/eventrules`;
    the channel, the IDs, the time and the data's names and values are
    taken from it, and the fields the builtin reported must equal them,
    or the run fails and is recorded as `eventlog.refused_on_device`. An
    event cut to its `System` element is checked on that element and
    carries no data;
  * **a Security event** in a result for an input without `sensitive`, or
    an event from a log, channel or time the input did not ask for,
    fails the run the same way;
  * **values the server's list classifies** and an older agent's list
    let through are replaced by the marker, in the fields and the XML,
    with the event's message, before the result is stored, and counted on
    the run;
  * **on a text query, an event the server had to redact is dropped**,
    since the text may have matched what was redacted, and its presence
    alone would say so; the page says how many were dropped.

  A result is stored only after this check.
* **What the server's check cannot catch.** It catches an agent with
  older rules or a bug. An agent that is compromised runs as SYSTEM on the
  computer, can read every log there itself, and can write XML that
  passes; the server's check is not a defence against it.
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
| The same, but the log's oldest event is after T1 | *Reported* | *No events match; this log begins at T_oldest*, so nothing before it can be known from the computer |
| A bound reached before the range's start | *Reported*, incomplete | *Searched N events back to T; more may match* and *Continue* |
| The log cleared, or overwritten past the cursor, since the first page | *Reported*, incomplete | *This log was cleared since the first page*, or *events after T were overwritten*, and *Start again* |
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
when the whole range was searched, and with the log's first event when
the log does not reach back to the range's start. An Analytic or Debug
channel, whose oldest event Windows does not report, says *the log's
start is unknown*.

### Permissions
*Decided in review.*

| Permission | What | Who | Slice |
|---|---|---|---|
| `eventlog.view` | the Logs tab, every channel but Security, without sensitive fields | Technicians and above, at their sites | 1 |
| `log.view_sensitive` | ADR-0060's: the Security log and sensitive fields, in this mode and in ADR-0060's | Organization Administrators and above, from organization-wide grants only | 1 |
| `eventlog.manage` | settings of every channel but Security, and clearing them | Site Administrators and above, at their sites | 4 |
| `eventlog.clear_security` | clearing the Security log, and any change to its settings (size, retention, archiving) | Organization Administrators and above, from organization-wide grants only | 4 (settings), 6 (clearing) |

* **Reading a result** needs `job.view_sensitive` as well, by F2's rule.
* **Organization-wide only**: `log.view_sensitive` and
  `eventlog.clear_security` join the permissions a site-scoped role never
  gets (`rbac.go:286`).
* **Why Technicians may query.** A Technician holds `device.terminal` at
  the same sites (`rbac.go:145-148`), a SYSTEM shell from which every log
  can be read; the viewer adds structure, bounds and a record of each
  query. On-demand queries get a permission of their own (plan).
* **What that gives Technicians that ADR-0060 keeps for `log.view`.**
  ADR-0060 puts sign-in and process events behind `log.view` (Site
  Administrators and above) in its store. Outside the Security log, such
  events are in other channels: remote desktop sign-ins in the Terminal
  Services logs, process starts in Sysmon's. On demand, a Technician sees
  them for one computer at a time, without sensitive fields, as they could
  through the terminal. That is a widening of who sees them through the
  console, not only through a shell, and it is stated as such: ADR-0060's
  [Privacy](0060-collecting-logs.md#privacy) section and
  [PRIVACY.md](../../../PRIVACY.md) gain it in slice 1 (*On demand,
  Technicians and above see one computer's events, sign-ins and process
  starts outside the Security log included, without command lines and
  scripts; each query is recorded*), and the owner is asked
  ([Owner questions](#owner-questions)). What stays at `log.view` is
  ADR-0060's: search across devices and sites, and history after a
  computer's own log has moved on or the computer is gone.
* **One tab, two answers** (slice 3): a Technician holding `eventlog.view`
  but not `log.view` sees an event under *On the computer* and not under
  *Collected*. The tab says so (*Collected events need permission to see
  sign-in and process events*) rather than showing an empty list; the
  owner question covers it.
* **Why the Security log needs more than `log.view`.** This mode shows the
  original message and XML that ADR-0060 drops, so it is stricter than
  `log.view` for the Security log (plan, Risks). A Site Administrator
  sees collected sign-ins under ADR-0060 and not the Security log here.
* **Why the Security log's settings take `eventlog.clear_security`.**
  Shrinking it or changing how it fills loses its history as surely as
  clearing it, and the wrong retention can stop the computer
  ([Channel settings](#channel-settings)).
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
| `eventlog.refused` | the server refuses a request (the Security log or its archives without the permission, a refused channel name, a previous page not the caller's) | what was asked and the rule, within ADR-0063's bound |
| `eventlog.refused_on_device` | a result breaks the rules (a Security event when none was allowed, the wrong channel or range) | the rule broken; the system as actor, the person who asked in the details |
| `eventlog.export` | an export is downloaded (slices 2 and 5) | format, event count, size, whether sensitive, the query's record |
| `eventlog.configure` | a channel setting is changed or undone (slice 4) | device, channel, setting, value before and after, `CrashOnAuditFail` as read, when the session stepped up, the warnings shown, the typed confirmation matched where one is asked |
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
  open run is cancelled: the agent closes the child's input, the child
  cancels its query with `EvtCancel` and exits, and after 5 seconds the
  job object ends it if it has not
  ([One set of rules, one reader](#one-set-of-rules-one-reader)).
* **Load on the computer.** The child is in the run's job object (memory,
  cancel); the Event Log service's own work is not
  ([Bounds](#bounds)). One query running per device, two open.

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
  Only those names in that folder: a query never names another path. An
  archive belongs to the channel its name gives, compared ignoring case,
  so `Archive-Security-*` is refused by the server before anything is
  sent, and by the builtin again, to a caller without
  `log.view_sensitive`.
* **Saved searches**: a person's own filters with a name, up to 50 each,
  in a table under row-level security by user; never results. Shared
  ones are the presets; others are not built until asked.
* **A saved search never keeps the text.** It keeps every other filter
  and that it had text, and the text is typed again each time it is
  run. The text is what a person hunts for: a user's name, an address,
  sometimes a password seen in a log. A saved search lives until it is
  deleted, while a query's text lives an hour with its result and is
  recorded only as a length; keeping it for an hour instead would make
  a saved search forget itself, which is no saving.

### Export
*Decided in review.*

* **Slice 2, CSV and JSON lines**, of the selected events or of a filter,
  built by the server from results it holds and checked:
  * **selected events**, from the person's own result, within its hour;
  * **a filter**, through an `export` operation that writes compact
    events, a page's lines with each held to 8 KiB as encoded (cut in
    the page's order, [Bounds](#bounds)), up to F2's 2 MiB: a few
    hundred to a few thousand events, and the file says where it stopped
    and offers the next part.
  CSV cells beginning with `=`, `+`, `-`, `@`, a tab or a carriage return
  get a leading `'`, as ADR-0060's exports do. Only what the person may
  see; recorded as `eventlog.export`.
* **Slice 5, files**: F2 gains a file a run hands back, for `.evtx`, for
  large exports and for a clear's backup.
  * **Sized before it is made.** The builtin reads the log's size
    (`EvtGetLogInfo`) and the free space where it will write, and stops
    with *the export would need N; narrow the time range* or *not enough
    free space on C:* before exporting anything; it measures the file
    again before uploading.
  * **The capability** `job.files`. The builtin writes the file in the
    run's private folder; the agent compresses it and uploads it after
    the run, in signed requests of 1 MiB to a new agent endpoint, each
    stored by one short transaction in a staging table, with the
    SHA-256 of the whole in the result.
  * **Stored in PostgreSQL**, in rows of 1 MiB under row-level security,
    as signed builds are kept as `bytea`
    (`server/migrations/00026_signed_agent_builds.sql:19`) and as
    [ADR-0066](0066-customer-documentation-and-assets.md#attachments-and-diagrams)
    keeps attachments: one place to back up and restore.
  * **At most 64 MiB compressed** per file. One export at a time per
    device, three per person. Kept 24 hours, then purged.
  * **A limit for the deployment**, as ADR-0066 has for attachments: the
    files kept and staged together at most 10 GiB by default, set by
    Super Administrators (`settings.manage`); a notice at 80% (ADR-0053),
    and at 100% new exports and backup uploads are refused
    (`409 storage_full`) with the reason shown. The backup guide counts
    them beside attachments.
  * **`.evtx`**: `EvtExportLog` with the query into a new file, then
    `EvtArchiveExportedLog` so that the messages travel with it, both
    packed by the agent in one `.zip`. If the Event Log service, not
    the builtin, writes the exported file (slice 6's test finds out for
    clears), it is exported into the backup folder below and moved. The
    server checks its size and SHA-256 and never unpacks it. A `.evtx`
    cannot be masked, so every `.evtx` needs `log.view_sensitive` and
    step-up.
  * **JSON lines of up to 100,000 events** (ADR-0060's export bound),
    gzip-compressed, which the server checks line by line with its rules
    as it checks a result before anyone may download it:
    * **bounded**: at most 100,000 lines and 100,000 × 8 KiB of
      decompressed bytes (about 781 MiB); past either, or at a line over
      8 KiB, the check stops, the file is refused, its staged chunks are
      deleted and the run says why;
    * **in the background**: a worker in the server reads the staged
      chunks and writes the checked, compressed output one chunk of
      1 MiB per short transaction, holding no transaction while it
      decompresses or checks; the file becomes downloadable in a last
      short transaction that writes its size and SHA-256. A server that
      stops midway starts the file's check again;
    * **records apart**: any audit record the check writes
      (`eventlog.refused_on_device`) is appended in its own short
      transaction, never inside a long one, as ADR-0066 appends a
      download's record before streaming.

    CSV is made from it on download.
  * **Downloads** as ADR-0066 serves attachments: as a download only, the
    `eventlog.export` record first in its own short transaction, then
    chunks each read in a short transaction of their own, with the
    SHA-256 checked as the file streams.

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
  file's path, isolation, Analytic and Debug publishing settings, and
  `CrashOnAuditFail` itself, which is a security policy and Group
  Policy's.
* **How**: `EvtOpenChannelConfig`, `EvtSetChannelConfigProperty`,
  `EvtSaveChannelConfig`; the result carries each value before and after,
  and *Undo* sets the old values back, under the same rules as the
  change.
* **A full Security log can stop the computer.** With the policy *Audit:
  Shut down system immediately if unable to log security audits*
  (`CrashOnAuditFail`) on, "if the security log is full and an existing
  entry can't be overwritten", Windows stops with `STOP: C0000244 {Audit
  Failed}`, and afterwards only administrators may sign in until the log
  is cleared and the value reset; Microsoft calls the combination with
  *Do not overwrite events* a denial of service an attacker can cause by
  generating events. So:
  * **the Security log is offered only *overwrite as needed***. *Do not
    overwrite* and *archive when full* are refused for it outright,
    whatever `CrashOnAuditFail` says: the policy can be turned on later
    by Group Policy, and archives grow without limit (Microsoft: "no
    limit to the number of backup files");
  * **any change to the Security log's settings** needs
    `eventlog.clear_security`, not `eventlog.manage`
    ([Permissions](#permissions));
  * **shrinking the Security log is treated as a clear**: the same
    permission, step-up, and the device's and the log's names typed,
    since a smaller log overwrites its oldest events sooner. Whether
    Windows applies a smaller maximum at once or at the next clear is to
    be confirmed on the runners, and the console says which;
  * **`CrashOnAuditFail` is shown** on the Security log's page as the
    agent read it ([Channels](#channels)): 1, *this computer stops if
    its Security log fills and cannot overwrite*; 2, *it has stopped for
    that reason: only administrators can sign in*, with the log's
    settings beside it. Where the Security log is set not to overwrite
    (by Group Policy, say) and the value is 1 or 2, the page says so in
    red and offers *overwrite as needed*;
  * **other channels: *do not overwrite* is refused while
    `CrashOnAuditFail` is 1 or 2**, decided in review although the policy
    concerns security audits, so that no setting made through EasyRMM
    adds a log that stops recording on such a computer.
* **Warnings shown before the change**, and recorded:
  * *do not overwrite* makes the log sequential (Microsoft's
    `retention`), so a full log records nothing more until it is cleared
    (to be confirmed on the runners, with the test log);
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

* **Sized first.** The builtin reads the log's size (`EvtGetLogInfo`) and
  the free space on the backup folder's volume, and refuses the clear
  unless the space exceeds the log's size by 1 GiB.
* **Always saved on the computer first**: `EvtClearLog` with a backup
  path, a new `.evtx` named `EasyRMM-cleared-<channel>-<UTC time>.evtx`,
  in `%windir%\System32\winevt\Logs\EasyRMM-backups`. That folder sits
  where Windows writes its own archives (Microsoft's `autoBackup`), so
  the Event Log service can write beside them; the agent creates it with
  an access list of its own, not inherited: SYSTEM and Administrators,
  and the Event Log service's SID (`NT SERVICE\EventLog`, the name to be
  confirmed) with full control, as Microsoft's Eventlog Key page asks
  for a file the service is given. Whether the backup is written by the
  service or by the calling process is to be confirmed by slice 6's
  test, which drops the service's entry if it is not needed.
* **No backup, no clear.** If `EvtClearLog` fails, the builtin reads the
  record count again and reports the log as not cleared; a clear that
  emptied the log without its backup (not expected, to be confirmed by
  the test that makes the folder unwritable) is reported as a failure,
  in red, with the record.
* **Kept on the computer for 30 days**, then deleted by the agent. A
  backup of at most 64 MiB compressed is also uploaded through slice 5's
  files, for download (`log.view_sensitive`, step-up); a larger one is
  not, and the console names the file left on the computer, to be
  fetched through the device's files (`device.files`) by someone who may.
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
* **A Technician still reaches every log another way**: the terminal
  (`device.terminal`), a script (`script.run`) and the device's files
  (`device.files`, the `.evtx` files themselves), all as SYSTEM, the
  Security log and command lines included. The viewer's split binds the
  viewer, as ADR-0060's binds its search. Hiding sensitive fields guards
  against casual exposure, on screens, in exports, copies and bulk
  reading; it is not a boundary against a Technician who means to read
  them.
* **The classification catches field names**, not every secret: an
  application that writes a password into its message is shown to
  Technicians.
* **The server's check catches older rules and bugs**, not a compromised
  agent ([Where it is enforced](#where-it-is-enforced)).
* **The Event Log service's work** during a query is outside the job
  object.
* **Results stay in database backups** made within their hour, as
  ADR-0063 says of output; slice 5's files, `.evtx` included, stay in
  backups made within their 24 hours, and a `.evtx` holds the Security
  log and command lines unmasked.
* **A clear's backup stays on the computer** for 30 days, readable by its
  administrators.
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
| Save frequently used searches | Saved searches (slice 2) | New: personal, keeping every filter but the text, which is typed again; presets shared |
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
| "Event Log Management" (the title) | Channel settings (4); Export (5); Clearing (6) | Later slices; settings and clearing are an owner question |

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
     the definer function that builds a next page; the refusal bound;
     `eventlog.query`, `eventlog.refused`, `eventlog.refused_on_device`;
     ADR-0060's Privacy section and PRIVACY.md amended;
   * **the builtin**: `agent/winevent` and `builtin eventlog` with
     `channels` (and `CrashOnAuditFail`), `query`, `event` and
     `provider`; cancelling through the child's input;
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
   `eventlog_manage`, `eventlog.manage`, and `eventlog.clear_security` for
   the Security log's settings; `eventlog.configure`, undo, the change
   lock, the rules for a full Security log. Built only if the owner wants
   it ([Owner questions](#owner-questions)).
5. **Files**: `job.files`, the agent's upload, staging, the background
   check, storage, the deployment's limit and purge; `eventlog_export`;
   `.evtx`; JSON lines up to 100,000 events.
6. **Clearing** (after 5): `clear`, its backup on the computer and its
   upload, `eventlog.clear`, ADR-0060's detection amended. Built only if
   the owner wants it.

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
  fields, the *Windows PowerShell* log, Shell-Core's `Command`, Sysmon
  13's `Details` and the BITS client's `url`.
* Technicians see one computer's sign-in and process events outside the
  Security log on demand, which ADR-0060 keeps for `log.view` in its
  store; ADR-0060's Privacy section and PRIVACY.md say so.
* A computer's Security log can be set only to overwrite through EasyRMM,
  so no setting made here can stop a computer that audits with
  `CrashOnAuditFail`.
* Permissions gain `eventlog.view` and `log.view_sensitive`, then
  `eventlog.manage` and `eventlog.clear_security`; the audit log gains the
  six actions above; the refusal bound counts `eventlog.refused`.
* The jobs' kinds gain `eventlog_query`, then `eventlog_manage` and
  `eventlog_export`; F2 gains a second permission per input and, in slice
  5, files a run hands back.
* A query's Event Log service work is not capped by the job object;
  measured, bounded by time, by a cancel that reaches the query and by
  one query running per device.
* No PowerShell runs for the viewer, so it writes nothing into the
  PowerShell logs it reads.

## Testing
* **Integration tests** in Go against real PostgreSQL through `testdb`
  (`make test-db`), without mocks:
  * **Permissions**: every role on every endpoint; `log.view_sensitive`
    from a site-scoped grant ignored; a query asking for the Security log
    without it refused (`403`, recorded within the bound, counted with
    ADR-0063's actions); the Security log's settings refused with
    `eventlog.manage` alone.
  * **Results**: an input and its result read by the person who asked and
    refused to another Technician of the site, through `/result` and
    `/arguments`; a sensitive result refused to its asker once the
    permission is taken away; the purge emptying them after the hour and
    not before.
  * **The server's check**: results as an agent sends them, built in the
    test: a Security event in a result for an input without `sensitive`
    failing the run and recorded; a `CommandLine` value and the message
    of its event replaced by the marker, in the fields and the XML,
    before storing, and counted; on a text query, that event dropped
    and counted; reported fields that differ from the event's XML (a
    channel, a name, a value) failing the run; an event from a channel
    not asked for, or outside the range, failing the run; `\u0000` and
    a lone surrogate escape refused; `SECURITY` and
    `Archive-Security-1` treated as the Security log.
  * **The next page**: built from the stored input and result through the
    definer function; a previous page of another person, another device
    or over an hour old refused; `easyrmm_app` holding no grant on
    `job_inputs` or `job_runs.result`.
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
    `x/sys/windows/svc/eventlog` (`InstallAsEventCreate`, which registers
    sources only under the Application log, `install.go:23` in `x/sys`)
    and removed after: information, warnings and errors with known IDs
    and a random marker; queries by ID, range, exclusion, level,
    provider, time and text; newest first; pages with the cursor while
    the test keeps writing, with no event twice and none missing; a task
    category written with `ReportEvent` and found by its number;
  * **a test log of its own**, for everything that changes or fills a
    log: a key `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<random>`
    with a source under it, as Microsoft's Eventlog Key page describes
    custom logs, its `MaxSize` set by the test, removed after. Whether
    the Event Log service opens it without a restart is to be confirmed;
    if not, the test uses `wevtutil im` with a test manifest instead.
    Application, System and Security are never cleared, filled or resized
    on a runner;
  * **cursors and clears**: the test log cleared between two pages,
    giving *cleared since the first page*; a log whose oldest event is
    after the range's start, giving *this log begins at T*; whether
    record numbers restart after a clear, recorded;
  * **cancelling**: a query over the filled test log cancelled through
    the child's input in the middle of `EvtNext`, the child gone within
    the 5 seconds and the Event Log service's processor time printed for
    the 10 seconds after; then the same with the child killed by the job
    object without cancelling, to measure whether the service goes on
    working for a client that has gone;
  * **sizes and strings**: an event with a 1 MiB value, cut and marked in
    a page, with the next event found by the cursor; an event with 300
    values; a value with NUL and a lone surrogate, sent as `raw` with
    its display text;
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
  * **bounds**: the test log filled to 256 MiB, searched for text that
    is not there: the page stopping at 45 seconds with the cursor and how
    far back it searched, the child's memory peak, and the Event Log
    service's processor time during the scan, printed; 100 events and
    the byte bound;
  * **channels**: every channel listed; an Analytic channel found on the
    image by its type, listed and its state shown;
  * **times**: fixed UTC instants in winter and summer converted for a
    zone with daylight saving set on the runner with `tzutil`;
  * **no PowerShell** and no `wevtutil` started by the builtin;
  * **slice 4** on the test log: sizes, retention modes, undo;
    Application, System and Security refused for enabling; for the
    Security log, *do not overwrite* and *archive when full* refused
    without sending anything, and a smaller size asking for the
    confirmation (the change itself not made on a runner);
    `CrashOnAuditFail` read and shown; with it set to 1 on the runner
    and set back after, *do not overwrite* refused for the test log;
  * **slices 5 and 6** on the test log: an export and an archived export
    read back; free space checked first; a clear with its backup written
    into the backup folder created with SYSTEM and Administrators only,
    then again without the Event Log service's entry, recording which
    writes the file; a clear with the folder made unwritable refused and
    the log still full; a backup over 64 MiB kept on the computer and
    named, not uploaded; 104 written (confirming it).
* **Integration tests of slice 5's files**: gzip files built in the test
  that decompress past 100,000 × 8 KiB, hold 100,001 lines or one line
  over 8 KiB, each refused and its staged chunks deleted; the check run
  in its worker while a test reads `pg_stat_activity` and finds no
  transaction of it open longer than one chunk's; the refusal record
  written in its own transaction; the deployment's limit giving
  `409 storage_full`; a server stopped midway restarting the check.
* **Machine tests**, with ADR-0054's Windows machines under KVM: a domain
  account's SID resolved, and one unresolved with the domain controller
  stopped; ForwardedEvents through a Windows Event Collector subscription
  between two machines, with and without `RenderingInfo`; Sysmon's events
  (1, 13, 19, 20); Shell-Core 9707 and BITS client events, recording the
  new sensitive fields' names; Group Policy setting a log's size; App
  Control on, the builtin still working.
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
* 4103's field names and the *Windows PowerShell* log's layout, and the
  names of Shell-Core 9707 and 9708's `Command`, Sysmon 13's `Details` and
  the BITS client's `url`;
* the error a query gets when the Event Log service is stopped;
* the presets' candidate IDs;
* Windows 10 and Windows Server 2016, 2019 and 2022, beyond CI's images;
* that record numbers only grow within a log, and whether they restart
  after a clear;
* that a clear changes the log's creation time (`EvtLogCreationTime`);
* whether Windows opens a channel by a name in any case;
* whether the Event Log service or the calling process writes the files
  of `EvtClearLog` and `EvtExportLog`, and the name of the service's SID;
* whether a smaller maximum size takes effect at once or at the next
  clear;
* that a full sequential log (*do not overwrite*) records no new events;
* that the Event Log service opens a custom log created under the
  `EventLog` key without a restart;
* whether the Event Log service stops working for a client that was
  killed in the middle of `EvtNext`;
* `Win32_NTLogEvent`'s reach (only in *Not chosen*).

## Owner questions
1. **On-demand queries for Technicians** (the plan's question 15).
   Decided in review: Technicians and above query a computer's logs on
   demand with `eventlog.view`, without the Security log and sensitive
   fields, which need `log.view_sensitive` (Organization Administrators
   and above, organization-wide grants). Two consequences to confirm:
   * **Technicians see sign-in and process events** outside the Security
     log (remote desktop sign-ins, Sysmon's process starts), one computer
     at a time and without command lines, which ADR-0060 keeps for
     `log.view` (Site Administrators and above) in its store. ADR-0060's
     Privacy section and PRIVACY.md would say so;
   * **the tab of slice 3 answers differently by role**: a Technician
     sees such an event under *On the computer* and not under
     *Collected*, told why.

   Is that the split you want? Or should on-demand queries need
   `log.view` (Site Administrators and above), keeping Technicians to the
   terminal; or should Site Administrators also read the Security log
   here without sensitive fields?
2. **Managing logs.** The requirement's bullets ask for reading; only its
   title says management. Are channel settings and clearing wanted? If
   so, decided in review: settings and clearing of other logs at Site
   Administrators and above; the Security log's settings, which are only
   ever *overwrite as needed* and a size, and its clearing at
   Organization Administrators and above with a permission of its own;
   each with step-up. Should either sit elsewhere?
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
* Audit: Shut down system immediately if unable to log security audits:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/audit-shut-down-system-immediately-if-unable-to-log-security-audits
* Can't access Web sites when security event log is full
  (`CrashOnAuditFail`'s values):
  https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/users-cannot-access-web-sites-when-log-full
* Eventlog Key (custom logs, `MaxSize`, `Retention`, `File`):
  https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key
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
