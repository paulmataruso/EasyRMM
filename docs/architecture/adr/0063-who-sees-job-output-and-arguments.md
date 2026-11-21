# ADR-0063: Who sees a job's output and arguments

* Status: Accepted (2026-11-21); implemented (PR #81). Revised the same
  day after an independent review.
* Amends: [ADR-0017](0017-scripts-and-jobs.md): who reads a run's output
  and a job's arguments, how long output is kept, and the guidance on
  secrets; it has an *Amended by ADR-0063* line. Also the line of
  [ADR-0060](0060-collecting-logs.md) that says `job.view` shows a run
  with its arguments, which has a note.
* Builds on: [ADR-0007](0007-hash-chained-audit-log.md) (the audit log),
  [ADR-0023](0023-audit-forwarding.md) (forwarding it),
  [ADR-0028](0028-software-deployment.md) and
  [ADR-0051](0051-hardening-linux-computers.md) (EasyRMM's own kinds of
  job), [ADR-0047](0047-tokens-shown-again.md) (a read and its audit
  record in one transaction), and four proposed ADRs:
  [ADR-0060](0060-collecting-logs.md) (`log.view` and
  `log.view_sensitive`; job arguments in collected logs),
  [ADR-0053](0053-one-notification-sender.md) (notifications),
  [ADR-0054](0054-hardening-windows-computers-and-servers.md) (retention
  per kind of job) and
  [ADR-0058](0058-signed-settings-that-reach-the-agent.md) (settings per
  organization).

## Context
A survey of `main` at `6f9fe99` for the security features found that job
output is read more widely than anything else that can hold a secret, and
that no one can tell who read it. Each claim below was checked again in
the code for this ADR.

**What is kept.**

* A run keeps the first and last 128 KiB of its standard output and of
  its standard error, as UTF-8 text (`agent/jobs/capture.go`;
  `job_runs.stdout` and `stderr` in
  `server/migrations/00004_scripts_jobs.sql`).
* A job keeps its arguments: at most 32, each at most 1 KiB (`jobs.args`).
  A job is written once; `easyrmm_app` cannot update it
  ([database.md](../database.md)).
* Both stay until the job is removed: `EASYRMM_JOB_RETENTION` after it was
  created, once every run has finished (`Purge`,
  `server/internal/jobs/service.go`). The default is 90 days. The setting
  is for the whole deployment, at least 24 hours
  (`server/internal/config/config.go`).
* Both are plain text in the database, so in every dump and backup.

**Who reads it.**

* `GetRun` returns a run's output and its job, arguments included, to
  anyone with `job.view` at the run's site. `GetJob` returns a job's
  arguments to anyone with `job.view` at the site of one of its runs.
  `ListJobs` returns the arguments of every job it lists
  (`server/internal/jobs/jobs.go`).
* `job.view` is a view permission. Every role holds it, **Read-Only
  included** (`viewPerms` in `server/internal/rbac/rbac.go`;
  [rbac.md](../../security/rbac.md)).
* Nothing records a read. Starting a run is audited as `device.script_run`
  with the number of arguments, never their values (ADR-0017). Reading
  output or arguments writes nothing.

**What that means.** A technician who runs `manage-bde -protectors -get`
to help a locked-out user leaves the BitLocker recovery password in that
run's output. For 90 days every Read-Only user of that site or its
organization can read it, and no one can find out who did. Read-Only is
a natural role for a customer's own staff: the RBAC guide suggests giving
customers Site Administrator or lower. The same holds for any script that
prints a password, a token or a key. It holds for arguments too: a script
that sets the local administrator's password and takes it as an argument
shows it on the job's page, and in every Jobs list response, to the same
users. The guide says never to pass passwords or keys as arguments, and
that arguments are "shown to everyone who can see" the job
([Scripts and jobs](../../operations/scripts-and-jobs.md#running-a-script)).
It says nothing about output.

**Every place output and arguments reach today**, checked for this ADR:

| Where | Output | Arguments | Who |
|---|---|---|---|
| `GET /api/v1/job-runs/{id}` (`GetRun`), and the run that canceling it returns | Both streams | The job's | `job.view` at the run's site |
| `GET /api/v1/jobs/{id}` (`GetJob`), and the job that creating or canceling one returns | No | Yes | `job.view` at the site of one of its runs |
| `GET /api/v1/jobs` (`ListJobs`) | No | Every listed job's | `job.view` anywhere; runs under row-level security |
| `GET /api/v1/job-runs` (`ListRuns`) | No | No | `job.view` at the run's site |
| `GET /api/v1/devices/{id}/hardening` | Findings parsed from the hardening script's last line, each checked | No | `device.view` |
| A run's `error` | No, except one case: a refused hardening result quotes up to 40 characters of a module name from the output (`parseHardeningResult`) | No | `job.view` |
| The server's log | The same quote, in a warning | No | The host |
| The audit log, and forwarding (ADR-0023) | No | The count (`device.script_run`); a software action's package and version; a hardening check's modules and options | `audit.view`; the collector |
| Reports and their CSV downloads | No: no report reads a job table (`server/internal/reports`) | No | |
| Mail | No: invitations and password resets only (`server/internal/mailer`) | No | |
| Notifications and webhooks | None are built; ADR-0053 (proposed) carries no job content | | |
| The agent's journal | The whole result, until the server has it | No | Root, or SYSTEM and Administrators |
| The computer's command lines and logs | No | Yes (ADR-0060's context) | The computer's administrators |
| Database dumps and backups | Yes | Yes | Whoever holds them |

The patching engine runs no technician scripts and never sees jobs.

**How the console reads runs.** This matters for auditing:

* A run's page asks for the run every 2 seconds while it is open
  (`web/src/pages/jobs/RunDetailPage.tsx`).
* A job's page prefetches a run, output included, when the pointer rests
  on its row or the row gets focus (`JobDetailPage.tsx`). The Jobs list
  prefetches a job, arguments included, the same way (`JobsPage.tsx`).
* Every query is asked again when the window regains focus
  (`refetchOnWindowFocus` in `web/src/main.tsx`).

So a request for a run does not mean that someone looked at its output.

**What else exists.**

* Five built-in roles, defined in code. There are no custom roles.
  Assignments name a role; permissions are not stored (`rbac.go`).
* EasyRMM's API has no API tokens: every route needs a signed-in session
  (`httpapi.RequireActive`). The patching engine's statements (ADR-0038)
  never reach the jobs API.
* Nothing marks an argument as secret. A script declares no parameters,
  only a body; a job's arguments are positional strings (`Script` and
  `JobInput` in `server/internal/jobs`).
* ADR-0060 (proposed) keeps job arguments on the command line and replaces
  their values in what it collects from the computer's logs. Its
  `log.view_sensitive` keeps the command lines and scripts it collects to
  Organization Administrators.
* ADR-0047 shows a token again by opening it and writing the audit record
  in one transaction, so a read is never returned without its record
  (`revealSecret` in `server/internal/agents/tokens.go`).
* ADR-0054 (proposed) keeps its daily hardening checks for 7 days, not for
  `EASYRMM_JOB_RETENTION`.
* A keystore for BitLocker and LUKS recovery keys is planned in the
  security feature work. It has no ADR yet, and nothing of it is built.

## Decision

### The permission
*Decided in review.*

* **`job.view_sensitive`** opens a run's output (standard output and
  error, their sizes and whether each was cut) and a job's argument
  values. It covers every kind of job: library scripts, software actions
  and hardening checks. `job.view` keeps showing the jobs and runs
  themselves. The pair follows ADR-0060's `log.view` and
  `log.view_sensitive`: one permission for the rows, one for the fields
  that can hold secrets.
* **Held by Technicians and above**: Technician, Site Administrator,
  Organization Administrator and Super Administrator. **Not Read-Only.**
  In `rbac.go` it joins the Technician's permissions, not `viewPerms`. The
  roles stay a chain of supersets (`TestRoleHierarchyIsMonotonic`), and
  Read-Only keeps view permissions only
  (`TestReadOnlyHasNoWritePermissions`).
* **Granted where the role is**: at an organization or a site, as
  `job.view` is. Output is checked at the run's organization and site.
  Arguments belong to the whole job: they are shown to a caller who holds
  the permission at the site of at least one of the job's runs that they
  can see.
* **A Technician sees other technicians' output in the same scope.** The
  reasons:
  * Troubleshooting and hand-over: a colleague's failed run, a job started
    by someone who is off shift.
  * Withholding it protects little. A Technician who holds this at a site
    also holds `script.run` and `device.terminal` there, and can print the
    same thing again while the computer is online.
  * Every read is audited (below), so reading someone else's output is
    seen by the site's administrators.
* **Why Technicians, when `log.view_sensitive` is for Organization
  Administrators.** Reading what one's script printed is the reason to
  run it, and runs are read one at a time, with no search or export
  across a fleet. Collected command lines are other people's activity,
  searched in bulk. If output ever becomes searchable or exportable in
  bulk, that needs a decision of its own.
* **Later kinds** that read sensitive data on purpose, such as the
  planned registry and event log viewers, may need a stricter permission
  for their output, for example `log.view_sensitive` for events. The
  output endpoint would then ask for both. Not built now: every kind needs
  `job.view_sensitive`.

### What Read-Only still sees
*Decided in review.*

A caller with `job.view` and without `job.view_sensitive` still sees:

* every job and run in their scope: the status, the exit code, the error
  text the agent or the server wrote, the device with its organization
  and site, when it was queued, delivered, started and finished, how long
  it took and how often it was delivered;
* each job's script name and shell, the script as run (its body, which
  `script.view` shows in the library too), the timeout, who started it and
  when, and how many arguments it had;
* for software and hardening jobs, the action, package, version and
  manager, or the modules and options (`software` and `hardening`), which
  the server checks against fixed patterns and lists;
* a device's hardening findings (`device.view`): EasyRMM's own checked
  result, not output.

That is enough for what Read-Only is for, to view "devices, alerts and
reports without making changes" (`rbac.go`): what ran where, who started
it, and whether it worked. What it loses is the detail of why a run
failed, which a Technician of the site can read.

The `error` text stays visible: the agent and the server write it, never
the script (`agent/jobs/exec.go`, `server/internal/jobs/delivery.go`).
The one exception is removed: a refused hardening result says "a module
the job did not ask for" instead of quoting the name from the output, in
the run's error and in the server's log.

### The API
*Decided in review.*

* **Output and argument values leave the run and job answers, for
  everyone**, and come only from endpoints of their own. Runs and jobs are
  fetched for reasons the reader does not see: polling, prefetching on
  hover, asking again on focus (Context). So fetching a run is not reading
  its output, and auditing those requests would record hovers.
* **Fields left out, not emptied.**
  * `stdout`, `stderr`, `stdoutTruncated`, `stderrTruncated` and `args`
    are gone from every run and job answer: the lists
    (`GET /api/v1/jobs`, `GET /api/v1/job-runs`), one job or one run, and
    the jobs and runs that creating, canceling and removing output return.
    The Go types no longer have them, so no answer built from them can
    carry them.
  * **New fields are on the answers for one run or one job only**, never
    in a list, where nothing would read them:
    * one run (`GET /api/v1/job-runs/{id}`, and the run that canceling it
      or removing its output returns): `canViewOutput` and
      `canRemoveOutput`, for everyone; and
      `stdoutBytes`, `stderrBytes` and `outputRemovedAt` only for a caller
      who holds `job.view_sensitive` at the run's site, so that the console
      says "Nothing was written" or when the output was removed without
      reading it;
    * one job (`GET /api/v1/jobs/{id}`, and the job that creating or
      canceling one returns): `argCount` and `canViewArguments`, for
      everyone, as `canCancel` is.
  * Whether a stream was cut comes with the output, from its endpoint.
* **`GET /api/v1/job-runs/{id}/output`** returns `stdout`, `stderr`,
  `stdoutTruncated` and `stderrTruncated`:
  * `404` when the caller cannot see the run, as before, with no record;
  * `403` when they can see it but do not hold `job.view_sensitive` at
    its site, recorded as denied within a bound (Auditing reads);
  * `409 run_open` while the run has not finished, and
    `409 output_removed` once its output was removed, with no record;
  * `200` otherwise, recorded (Auditing reads). A run that printed
    nothing answers empty and records nothing.
* **`GET /api/v1/jobs/{id}/arguments`** returns `args`, with the same
  answers: `404`; `403` recorded as denied; `200` recorded. A job without
  arguments answers an empty list and records nothing. Jobs of every kind
  answer; the console asks only for library scripts' jobs with arguments.
* **`DELETE /api/v1/job-runs/{id}/output`** empties a finished run's
  output at once (Retention) and answers the run: `404` when the caller
  cannot see the run; `403` unless they hold both `job.view_sensitive` and
  `job.manage` at its site; `409 run_open`, `409 output_removed`, or
  `409 no_output` for a run that printed nothing. A refused removal is not
  recorded: it shows nothing.
* **One transaction.** The output or the arguments are read, and the
  record written, in one transaction, as ADR-0047's reveal does (In the
  database). If the record cannot be written, nothing is returned.
  Answers are `Cache-Control: no-store`, as every JSON answer already is
  (`httpapi.WriteJSON`).
* **Downloads** are not built (the console has *Copy* only). When they
  are, they use the output endpoint with `?download=stdout` or
  `?download=stderr`, with the same checks and a record that says it was
  a download.

### In the database
*Decided in review.*

The server's own checks are not the only guard: PostgreSQL refuses the
server's role the columns themselves, so that a query added later, for an
export, a report or a notification, cannot read them by mistake.

* **Column privileges.** Migration 00028 revokes `SELECT` on `job_runs`
  and `jobs` from `easyrmm_app` and grants it back column by column: every
  column but `job_runs.stdout`, `job_runs.stderr` and `jobs.args`. A query
  that names them, selects `*`, uses the whole row or returns them is
  refused (`42501`). A column added to either table later needs its own
  grant; [database.md](../database.md) says so.
* **Writing is unchanged.** `INSERT` and `UPDATE` keep their table
  privileges: creating a job writes its arguments, a result writes the
  output, and the purge and *Remove output* empty it. None of them reads
  it back: their `WHERE` and `RETURNING` clauses name granted columns only.
  The sizes and the number of arguments (`stdout_bytes`, `stderr_bytes`,
  `arg_count`) are set by `BEFORE INSERT OR UPDATE` triggers from what is
  written, whatever a statement says, so the server reads them without
  reading the values. *Decided in review*: plain columns kept by triggers,
  not generated columns, which would rewrite both tables while the
  upgrade holds them locked (Upgrading).
* **Reads go through two `SECURITY DEFINER` functions**, owned by
  `easyrmm_owner` with `search_path = pg_catalog, public, pg_temp`:
  `easyrmm_job_run_output` and
  `easyrmm_job_arguments`. The server passes the run or the job, the
  caller's `job.view` and `job.view_sensitive` scopes as it resolved them
  from the caller's roles, and who asks. The function checks the scopes
  against the runs' organizations and sites, appends the audit record with
  `easyrmm_audit_append` and returns the values, in the request's
  transaction: if the record cannot be written, the transaction fails and
  nothing is returned. Row-level security applies inside, since
  `easyrmm_owner` is subject to it too, so a run outside the request's
  scope is not found. The output read checks the caller's scopes first and
  only then locks the run (`FOR SHARE`), so a removal cannot empty it
  between the checks and the read, and a caller who may not read takes no
  lock (*decided in review*).
* **`pg_temp` last.** *Decided in review.* A function that does not name
  `pg_temp` in its `search_path` has the session's temporary schema
  searched first for tables and types. A caller able to create temporary
  objects could then put its own type where a function that runs as its
  owner expects PostgreSQL's, and have its code run as `easyrmm_owner`.
  * Every function that runs as its owner names `pg_temp` last: the three
    above, created that way, and the three before them
    (`easyrmm_audit_append`, `easyrmm_audit_verify`,
    `easyrmm_purge_audit`), changed by migration 00029. They were found in
    the catalog and are named one by one; down gives them their earlier
    `search_path`.
  * A test reads every `SECURITY DEFINER` function from the catalog and
    fails the build when one does not end its `search_path` with
    `pg_temp`.
  * A second layer: `easyrmm_app` and `PUBLIC` lose `TEMPORARY` on the
    database, since the server never creates temporary tables. Only the
    database's owner can take it away. Every documented install makes
    `easyrmm_owner`, which runs migrations, the owner, so 00029 revokes
    it; under any other owner it stops with the statement to run. The
    install script and the end-to-end script no longer grant it.
* **The agent's poll** reads the arguments of the runs it delivers through
  a third function, `easyrmm_job_delivery_args(device, runs)`, which
  answers only at platform scope, and only for that device's runs being
  delivered (`sent`). It is not audited: the device is the one that runs
  them.
* **What it does not stop**: a compromised server process. It holds the
  owner's credentials, to run migrations, so it can read anything. The
  functions check the scopes and the caller that the server passes them.
  The privileges and the functions guard against mistakes in the server's
  own code, not against its compromise.

### The console
*Decided in review.*

* **A run's page.**
  * With `canViewOutput`, once the run has finished and its sizes say it
    has output, the page asks for the output once and shows it as before,
    with a line under it: "Opening a run's output is recorded in the
    audit log." The query has a key of its own (`["job-output", run]`),
    outside the `/job-runs` prefix that refreshing or canceling a run
    invalidates. It is never asked again when the window regains focus
    (`refetchOnWindowFocus: false`), never goes stale
    (`staleTime: Infinity`), and leaves the cache as soon as the page
    closes (`gcTime: 0`). Hovering or focusing a run's row on a job's page
    prefetches the run, which carries no output.
  * Without it, the Output card says **"Hidden: needs permission to see
    job output (`job.view_sensitive`)"**, never "Nothing was written", and
    the page asks for nothing.
  * With both sizes zero, it says "Nothing was written to standard output"
    (and error) without asking.
  * Removed output says when it was removed, "by retention or by someone
    who could read it"; the audit log says by whom, when a person removed
    it.
  * **Remove output**, offered with `canRemoveOutput`, asks to confirm:
    "The output is emptied for everyone, and the audit log records that
    you removed it. Backups made before keep it." The server sets
    `canRemoveOutput` for the run's site with the same check the removal
    makes, `job.view_sensitive` and `job.manage` there (*decided in
    review*). Every built-in role that holds the one at a site holds the
    other there too.
* **A job's page.**
  * With `canViewArguments`, a library script's job with arguments asks
    for them once, with the same options and a key of its own
    (`["job-arguments", job]`), and shows them as before. The details and
    *Run again* share the one request.
  * Without it, Arguments says "2 arguments. **Hidden: needs permission
    to see job arguments (`job.view_sensitive`)**".
  * **Run again** presets the arguments it fetched. Where they are hidden
    it is not offered for a job that has arguments, since running it
    without them would run something else. No built-in role holds
    `script.run` without `job.view_sensitive`, so this does not happen
    with today's roles.
* The console decides from `canViewOutput`, `canRemoveOutput` and
  `canViewArguments`, not from the user's permission list, because the
  permissions may hold in some sites only.
* **The run-script dialog** no longer says that arguments are shown to
  everyone who can see the job: "Arguments are kept with the job, and
  people who may see job arguments can read them, each read recorded.
  Never use them for passwords."
* **The audit log's pages** name the new records "Viewed job output",
  "Viewed job arguments" and "Removed job output", and gain the area
  *Job output* (`job_run`): the server matches action prefixes at the dot,
  so *Jobs* (`job`) does not include `job_run.*`.
* **A page that fails to render** shows "This page stopped working" with
  **Reload**, from a boundary around the whole console
  (`AppErrorBoundary` in `web/src/main.tsx`), instead of a blank window. A
  tab loaded before the upgrade does not have it (Upgrading).

### Exports, reports, notifications and forwarding
*Decided in review.*

Checked one by one. None carries output or argument values today, and the
rule for each is set here so that later work keeps it:

* **CSV exports and reports.** The six reports read no job table
  (`server/internal/reports`; the patch reports come from the engine). No
  export carries output or argument values. An export of jobs, if one is
  added, has the fields of the list answers, and cannot read more: the
  database refuses the columns to the server's role (In the database). Output in bulk is a decision of its own (The
  permission).
* **Mail.** EasyRMM sends account mail only (`server/internal/mailer`).
* **Notifications and webhooks.** None are built, and ADR-0053 (proposed)
  carries no job content. No notification, webhook, Slack or Teams message
  carries output or argument values. A later notice about a job names the
  job, the device, the status and a link, as ADR-0060's alerts carry no
  event content.
* **The audit log and forwarding.** Records of jobs carry the number of
  arguments (`device.script_run`), the action, package and version
  (`device.software_action`), or the mode, modules and options
  (`device.hardening`), never output or the values of a script's
  arguments. The new records carry identifiers and sizes only.
  Forwarding (ADR-0023) sends records as written, so nothing more leaves.
* **The server's log** has the method, path and status of each request,
  never bodies or query strings (`RequestContext` in
  `server/internal/httpapi/middleware.go`). The hardening quote is
  removed (above).

### Auditing reads
*Decided in review.*

* **Every read of output or argument values is audited**, whoever reads,
  super administrators included:
  * `job_run.output_view`, under the run's organization, site and device,
    with the run, the job, the script's name, the kind and the size of
    each stream;
  * `job.arguments_view`, once for each organization in which the caller
    holds the permission for some of the job's runs, under the site when
    those runs share one (as `report.export` is recorded), with the job,
    the script's name, the kind and the number of arguments;
  * `job_run.output_remove`, under the run's organization, site and
    device, with the sizes removed;
  * a refused read (`403`) is recorded with the outcome `denied`, as a
    refused remote session is, within a bound (below).

  Site Administrators and above see them (`audit.view`), and they are
  forwarded like every record. None holds output or argument values.
* **Lists are not audited, because they carry neither.** The noise to
  weigh lies in how the console reads, not in the endpoints. The output
  endpoint is asked once per run page opened, the arguments endpoint once
  per page of a script job with arguments. That is about as many records
  as `device.script_run` writes, one per device per job. A record per
  list, per poll or per hover would bury these and record no reading.
* **Reads are not merged.** Opening the same run twice writes two
  records: a second look is a look.
* **Refusals are bounded.** A caller without the permission could ask
  again and again, and each record takes the audit log's chain lock
  (ADR-0007), which every record in the deployment waits for. So a
  refusal is recorded at most once per caller, action, target and
  organization in 10 minutes, and at most 20 times per caller in 10
  minutes across both reads. Every refusal still answers `403`. After 20,
  nothing more is recorded for that caller until the 10 minutes pass, so
  a gap in the records does not prove there were no attempts; the guide
  and the CHANGELOG say so.
  * **No table of its own.** The audit log is the state:
    `easyrmm_job_refusal` looks for the caller's denied records of the
    last 10 minutes before it appends.
  * **More than one server process.** The look and the append run under
    a transaction advisory lock per caller
    (`pg_advisory_xact_lock(63, …)`), so two requests from one caller, on
    any server process, take turns. Under PostgreSQL's default
    `READ COMMITTED`, each statement sees what committed before it, so the
    second sees the first's record. A refusal that is skipped takes no
    chain lock.
  * **Written synchronously**, in the request's transaction, like every
    audit record: if it cannot be written, the request answers an error,
    not `403`.
  * **Where a refused `job.arguments_view` is recorded**: as a successful
    one would be, once for each organization of the job's runs the caller
    can see, under the site when those runs share one. A caller who sees
    none of the job's runs gets `404` and no record.

### Retention
*Decided in review. The 30-day default is pending owner question 1.*

* **Jobs and runs keep `EASYRMM_JOB_RETENTION`** (default 90 days). Their
  history, who ran what where and how it ended, is what Read-Only and the
  console's lists show.
* **Output is kept for less: `EASYRMM_JOB_OUTPUT_RETENTION`**, by default
  30 days, or `EASYRMM_JOB_RETENTION` when that is shorter. Set
  explicitly, it must be at least 24 hours and at most
  `EASYRMM_JOB_RETENTION`, or the server does not start, as for the other
  retention settings. 30 days is ADR-0060's default for logs. The default
  follows a shorter job retention so that no deployment fails to start
  after the upgrade.
  * **Counted from when the output arrived**, `job_runs.output_stored_at`,
    which is set exactly while a run has output
    (`job_runs_output_stored`). Output kept before the upgrade counts from
    when its run finished.
  * The hourly purge empties `stdout` and `stderr` of each run whose output
    arrived longer ago than that, clears `output_stored_at` and sets
    `output_removed_at`, using a partial index on `output_stored_at`. The
    run, its status and exit code stay until the job goes. The purge is
    not audited, since it is the deployment's rule and not a person's
    read; the server's log says how many runs it emptied.
  * **`output_removed_at` marks only runs that had output.** The purge
    touches only runs with output, and *Remove output* answers
    `409 no_output` for a run that printed nothing. The two times are never
    both set (`job_runs_output_removed`).
  * **Late results.** A run marked *No result* still accepts a result that
    arrives later, as before. It had no output, so nothing of it was
    removed; the output that arrives is kept for the output retention from
    then, and purged like any other. **A result never stores output on a
    run whose output was removed**: it records the status and exit code
    and leaves the output empty. Today that cannot arise, since output
    arrives only with the result that ends a run and an ended run takes no
    second result. The rule is kept in the result's SQL and in the table's
    constraints so that a later change cannot bring removed output back.
  * Emptying removes the output from the table. The old row versions go
    at PostgreSQL's next vacuum, and backups made before keep the output
    as long as the backups are kept.
* **A run's output can be removed at once**: `DELETE
  /api/v1/job-runs/{id}/output`, for a finished run, by a caller with
  `job.manage` and `job.view_sensitive` at its site (Technicians and
  above), audited. It serves the case this ADR starts from: a technician
  who retrieved a recovery key removes the output once the key is used.
  Arguments cannot be removed (Arguments).
* **Not per organization now.** That needs a setting per organization
  that stays on the server: ADR-0058's catalogue (proposed), with keys
  that are not sent to agents, which ADR-0060 needs for `logs.retention`
  too. When that is built, a `jobs.outputRetention` key at the platform
  and organization levels, set by super administrators, can shorten the
  deployment's value, never lengthen it.
* **Not per kind now.** ADR-0054's daily checks (7 days) and the planned
  registry and event log viewers (minutes or hours) need retention per
  kind. The purge already works per run, on when its output arrived; per
  kind, it gains the job's kind in its condition and a time per kind.
  That is built with the first kind that needs it, not before: a table
  holding one value for every kind would be code that nothing uses.

### Arguments
*Decided in review.*

* **The same treatment as output**: `job.view_sensitive`, an endpoint of
  their own, every read audited, never in a list or a job response.
* **Kept with the job**, for `EASYRMM_JOB_RETENTION`, not emptied with the
  output. A job is the record of what ran, written once, which
  `easyrmm_app` cannot update; and *Run again* needs the arguments. The
  guide already says never to pass passwords or keys as arguments.
  ADR-0060 adds why: they are on the computer's command line, in its
  process events and in its PowerShell logs.
* **No secret-argument flag.** Nothing like one exists: scripts declare no
  parameters, and arguments are positional strings. A flag that only hid
  the value in the console would leave it on the computer's command line
  and in its logs. A real one would need:
  * parameters declared on the script, some marked secret;
  * values sealed with the server's key, bound to the run, and deleted
    when the run ends;
  * delivery off the command line, on standard input or in the
    environment, which process events do not record: an agent and
    protocol change;
  * the value never shown again, not even to the person who typed it, and
    asked for again by *Run again*;
  * the agent replacing the value in the output before it reaches the
    journal.

  That is a feature of its own, for a later ADR if wanted (Owner
  questions).
* **Software and hardening jobs** pass their action, package, modules and
  options as arguments, checked against fixed patterns and lists
  (`server/internal/jobs/software.go`, `hardening.go`). Their `args`
  follow the same rule. The same values stay visible in `software` and
  `hardening` under `job.view`: they are choices from fixed lists or
  checked names, not text a person typed for a script.

### The agent's journal
*Decided in review: no change.*

* The agent keeps each run's result, output included, in
  `jobs/journal/<run>.json` under its state folder until the server
  acknowledges it, then deletes the file (`agent/jobs/journal.go`,
  `agent/jobs/worker.go`). The record holds the run's IDs, its state and
  its result, not the job's arguments.
* **Windows.** The state folder is `%ProgramData%\EasyRMM\Agent`. Its
  access list grants SYSTEM and Administrators only, inherits nothing from
  ProgramData, and is inherited by what the agent makes below it
  (`protectedDACL` in `agent/host/system_windows.go`).
  Since PR #61 the agent checks it at every start, before reading
  anything in it: a folder someone else made or could change is moved
  aside and made anew, and `jobs`, `jobs\journal` and each file in it must
  be owned by a trusted account and changeable by no one else
  (`host.CheckState`; `layout` in `agent/state/state.go`).
* **Linux.** The state folder is `/var/lib/easyrmm-agent`, mode 0700 for
  root (`host.Protect`); the journal's folder is 0700 and its files 0600.
* Whoever can read the journal can also read the device's private key
  beside it, and runs as SYSTEM or root, so encrypting the journal would
  protect nothing from them. What remains: a deleted file's blocks until
  they are overwritten, and copies of the folder in the computer's own
  snapshots and backups, such as Volume Shadow Copies, which belong to the
  customer.

### Upgrading
*Decided in review.*

* **Roles.** Roles and their permissions are code; assignments name a
  role. From the first request after the upgrade, every Technician and
  above holds the permission and no Read-Only user does. There are no
  custom roles to migrate.
* **API clients.** EasyRMM has no API tokens, and `/api/v1` has no written
  compatibility policy: the console, served by the same server, is its
  only client in this repository. A script that read `stdout`, `stderr`,
  `stdoutTruncated`, `stderrTruncated` or `args` from run and job answers
  moves to the new endpoints. In this repository that is
  `scripts/drill/backup-restore.sh`, which now reads its run's output from
  `/output`.
* **The database.** Migration 00028 adds the sizes, `output_stored_at`,
  `output_removed_at` and `arg_count`, the two triggers that keep the
  sizes and the count, the two constraints, the purge's index, the column
  privileges and seven functions: the five that check and read
  (`easyrmm_job_scope_covers`, `easyrmm_job_refusal`,
  `easyrmm_job_run_output`, `easyrmm_job_arguments`,
  `easyrmm_job_delivery_args`) and the two the triggers run. Output kept
  before counts from when its run finished, so the first purge after the
  upgrade empties output whose run finished more than 30 days before (or
  the value set). The CHANGELOG says so. Down gives the server's role its
  table privileges back and drops what up added.
  * **The backfill.** *Decided in review.* The new columns have constant
    defaults, which PostgreSQL adds without rewriting the table; one
    `UPDATE` then fills in the runs that have output, and another the jobs
    with arguments. The tables stay locked for the migration, as for any
    `ALTER TABLE`, but each run with output is written once, where
    generated columns rewrote every run and then wrote those with output
    again. The update keeps a second version of each run with output until
    `VACUUM`, so it needs free disk about the size of those rows; output
    stored out of line (TOAST) is not copied. Measured on a test
    database, against the generated columns: 50,000 runs with 1 KB of
    output each, 3 seconds instead of 15, and 69 MB of extra disk either
    way; 5,000 runs with 16 KB each, under a second instead of 5 to 6, and
    1 MB of extra disk instead of 11.
  * Migration 00029 names `pg_temp` last for the older functions and
    revokes `TEMPORARY` (In the database).
* **Secrets printed before.** Reads before the upgrade left no record. The
  CHANGELOG and the guide say: treat a secret that a job printed, or that
  was passed as an argument, within the job retention before the upgrade
  as seen by every Read-Only user of its site, and change it. For
  BitLocker: add a new recovery password, then remove the old one.
* **A console tab loaded before the upgrade** runs the old code: on a
  job's page it reads `args`, which is gone, and goes blank; on a run's
  page it says "Nothing was written". Reloading loads the new console, and
  the old one reloads by itself at its next page change once it has seen
  the server's new build (`web/src/lib/consoleBuild.ts`). The new console
  has the boundary with **Reload** (The console), so a later change of
  this kind shows that instead of a blank window.

### The documentation
*Decided in review.*

Written with the implementation, and saying only what is built:

* `docs/operations/scripts-and-jobs.md`:
  * a section *Who sees output and arguments*: `job.view_sensitive`, what
    Read-Only sees instead, every read audited, *Remove output*, and the
    retention settings;
  * **never print secrets** (passwords, tokens, keys, recovery
    passwords) in output: everyone who holds `job.view_sensitive` in the
    site can read them until the output is removed, backups keep them, and
    they pass through the agent's journal. If a script must print one,
    remove the run's output once it is used, and change the secret if
    others could have read it;
  * **BitLocker and LUKS recovery keys** will have a keystore of their
    own, with its own permission and every read audited. It is planned,
    not built. Until then, a recovery key retrieved by a script is in
    that run's output: remove it after use;
  * in *Running a script*: arguments are read by people with
    `job.view_sensitive`, every read audited; still never pass passwords
    or keys as arguments; *Run again* needs the arguments;
  * in *Retention*: both settings;
  * in *What happens on the device*: the journal on Windows as well as
    Linux, and who can read it.
* `docs/security/rbac.md`: the permission's row, and why Read-Only does
  not hold it.
* `docs/operations/software.md` ("reports each device's status, exit code
  and output") and `docs/operations/hardening.md` (the troubleshooting row
  that points at the run's output): output needs `job.view_sensitive`.
* `docs/deployment/docker.md` (the retention table) and
  `deploy/docker-compose.yml` (passing `EASYRMM_JOB_OUTPUT_RETENTION`).
* `docs/architecture/database.md`: the new columns, privileges and
  functions, and that a column added to `job_runs` or `jobs` needs its own
  grant.
* `docs/security/threat-model.md`, under *Known limits*: output and
  arguments are plain text in the database and its backups, and holders
  of `job.view_sensitive` can read them, with a record.
* `PRIVACY.md`: who sees script output, and for how long it is kept.
* `CHANGELOG.md`: who sees output now, the new setting and the first
  purge, the advice on secrets printed before, and tabs left open across
  the upgrade.
* ADR-0017's *Amended by ADR-0063* line, and a note at ADR-0060's line
  that `job.view` shows a run with its arguments.

### What this does not fix
*Decided in review.*

Said plainly here and in the guide:

* **Whoever can run scripts can read any secret on an online computer.**
  `script.run` or `device.terminal` at a site lets a Technician print a
  recovery key, a stored password or a private key whenever the computer
  is online. This ADR records who read output; it cannot stop the person
  who produced it, and the terminal leaves no record of what was shown.
* **Super administrators see everything**, everywhere, and the server's
  operator can read the database. Their reads through the console are
  audited like anyone's, but they can change what the server does.
* **The database and its backups** hold output for the output retention,
  and arguments for the job retention, in plain text, so a dump alone
  holds them. Sealing them would not have protected a leaked backup set
  either: the backup guide keeps `.env`, which opens every sealed value,
  next to the dump
  ([Back up](../../operations/backup-restore.md#back-up)).
* **The computer** holds output in the agent's journal until it is
  reported, arguments on its command lines and in its logs, and whatever
  the script itself left behind.
* **A TLS-inspecting proxy** that the computer trusts can read results on
  their way: the agent trusts the system's roots, and signing its requests
  keeps them from being changed, not from being read.
* **Script bodies** are readable by everyone with `script.view` or
  `job.view`, Read-Only included. A secret written into a script is
  exposed to all of them; the guide says never to write one there.
* **Once shown, output can be copied anywhere.** The record says who
  opened it, not what they did with it.
* **Site Administrators who are a customer's own staff** hold the
  permission with their role, and see what the MSP's technicians printed
  on their site. They can run scripts there too.

### Not chosen
*Decided in review.*

* **Output for the person who started the job only**, others through a
  reveal. It breaks hand-over and protects nothing from someone who can
  run the script again; every read is audited anyway.
* **A click to reveal each run's output.** Every read is already a
  request made on purpose and recorded. A click adds a step to every look
  at a failed run, and no information.
* **Step-up authentication** (ADR-0055, not built) to read output. Too
  heavy for routine troubleshooting. It belongs to the recovery-key
  keystore.
* **Sealing output at rest** with the server's key. The server must open
  it to show it, and the backup set holds the key, so it would protect
  only a dump taken without `.env`, at the cost of a column type change
  and resealing when keys rotate. A shorter retention does more for less.
* **Redacting BitLocker recovery passwords from output now** (pending
  owner question 2). The pattern
  is distinctive (eight groups of six digits, each a multiple of 11). But
  redacting it removes the only way in the console to read a key for a
  locked-out user before the keystore exists, and it covers neither LUKS
  passphrases nor passwords, which have no pattern. The keystore's ADR
  decides how keys are retrieved and can add redaction then (Owner
  questions).
* **Emptying arguments with the output.** It would make jobs, written
  once, updatable by the application, and leave *Run again* without them.
* **Keeping output in the run's response for holders**, unaudited. The
  run is fetched on hover and on focus, so either reads go unrecorded or
  hovers are recorded.

## Consequences
* Read-Only users no longer see output or argument values. Technicians
  and above see them at their sites, and each read is recorded where the
  site's administrators see it.
* The API changes shape: `stdout`, `stderr`, the truncation flags and
  `args` leave the run and job answers, the answers for one run and one
  job gain a few fields, and two read endpoints and one delete are added.
  The console is the only client; the backup-restore drill moves to the
  new endpoint.
* The server's database role can no longer select output or arguments;
  a column added to `job_runs` or `jobs` needs its own grant. It can no
  longer create temporary tables, every function that runs as the owner
  names `pg_temp` last, and `easyrmm_owner` must own the database.
* Output is kept 30 days by default, not 90, and the first purge after
  the upgrade empties older output. Job history keeps 90 days.
* The audit log gains a record for each run page a holder opens, and for
  each page of a script job with arguments; refusals add at most 20 a
  user in 10 minutes.
* The raw output of software and hardening runs needs the permission too.
  Their actions, modules and findings do not.
* The rule for later work: what a computer prints or a person types as an
  argument is read through one audited endpoint, and never rides along in
  a list, an export, a report, a notification or a forwarded record.
* A later kind can ask for a stricter permission and a shorter retention
  without changing this design.
* The agent does not change.

## Testing
* **Integration tests** in Go against real PostgreSQL through `testdb`
  (`make test-db`), without mocks.
  * **The jobs service**
    (`server/internal/jobs/output_integration_test.go`):
    * **Every kind of caller**: Super Administrator; Organization
      Administrator; Site Administrator; Technician at the organization,
      at the run's site, and at another site of it; Read-Only at the
      organization and at the site; a user who is Read-Only in one
      organization and Technician in another; another organization's
      administrator; a user with no role. One library script job with two
      arguments, across two organizations, its output and arguments
      carrying markers. For each caller: the run's and the job's answers,
      decoded as maps (`canViewOutput`, the size and removal keys exactly
      for holders, `argCount`, `canViewArguments`, no marker, no run of a
      job carrying output fields); the output read; the arguments read; and
      the records each writes, with their organizations and sites (a
      super administrator reading the two-organization job's arguments
      makes two). Empty output and an open run too.
    * **Refusals bounded**: ten concurrent refused reads by one user make
      one record; refusals stop being recorded at 20 per user in 10
      minutes; another user is counted apart; with the audit clock moved
      10 minutes on, a refusal is recorded again.
    * **Retention and removal**, with the stored times moved back as the
      owner: output emptied after the output retention counted from when
      it arrived, not from when the run finished, the run kept; a lost run, then the purge and *Remove output*
      (nothing to remove), then its late result, which is stored and later
      purged; a run whose output was removed takes no output from a result
      (the state set as the owner, since today's statuses cannot reach
      it); *Remove output*'s permissions and its `409`s, with one record;
      a second result ignored.
    * **Who may remove**: the run's `canRemoveOutput` for every caller
      above, equal to `canViewOutput` with the built-in roles.
    * **The database refuses the server's role**: `42501` for selecting
      `stdout`, `stderr`, `*`, `args`, a whole row, or `RETURNING stdout`,
      and for calling the helper functions directly; the only columns of
      the two tables it lacks are those three; the delivery function
      answers only at platform scope; with appends made to fail (a trigger
      the test adds as the owner), the reads answer an error and return
      nothing, refusals included.
  * **The migration**
    (`server/internal/database/job_output_migration_integration_test.go`):
    00028 down and up over runs kept before: the backfill, the sizes, the
    argument count, the triggers keeping them on insert and update
    whatever a statement sets, row-level security forced on `jobs` again,
    the constraints, and the privileges taken and given back.
  * **Functions that run as their owner**
    (`server/internal/database/definer_integration_test.go`):
    * every `SECURITY DEFINER` function in the catalog ends its
      `search_path` with `pg_temp`, and the six known ones are among them;
    * the runtime role cannot create a temporary table or type, and
      neither it nor `PUBLIC` holds `TEMPORARY`;
    * with types planted in a session's temporary schema (made as the
      superuser, which may, in a session that then acts as
      `easyrmm_app`), a function made the old way runs the planted code as
      `easyrmm_owner`, which shows the test can fail; each of the six
      functions, on its reading and its refusing path, answers as it
      should and never runs it;
    * 00029 down and up: the earlier `search_path` and `TEMPORARY` come
      back, up refuses when another role owns the database and leaves
      nothing changed, and then succeeds once `easyrmm_owner` owns it.
  * **The HTTP API**
    (`server/internal/app/job_output_api_integration_test.go`), with
    devices enrolled and reporting through the agent API: sites in two
    organizations; a Technician of one site, a Read-Only user of the
    organization, the site's administrator, another organization's
    administrator and a super administrator; output and an argument
    carrying random markers.
    * Each caller asks for the job list, the run lists, the run, the job,
      the output and the arguments; `401` without a session; `404`,
      `409 run_open`, `409 no_output` and `409 output_removed`; removal
      refused for Read-Only (`403`) and for the other organization
      (`404`); `canRemoveOutput` on the run for each caller.
    * The site's administrator sees the records through
      `GET /api/v1/audit`, the Read-Only user's denied one included; the
      other organization's administrator does not.
    * Every report and its CSV download answer for Read-Only and the
      Technician.
    * Audit forwarding over TCP to a loopback collector, driven by the
      test, delivers the three new actions.
    * No marker in any other answer, in the forwarded messages, in the
      server's log captured at debug level for the whole test, or in the
      audit records; no `stdout`, `stderr` or `args` key in any other
      answer.
  * The jobs, hardening, software and enrolled-agent tests that read
    output or arguments read them through the new functions and endpoints.
* **No guard test on SQL.** The draft planned a test failing when a
  package other than `server/internal/jobs` names the columns. The
  database now refuses them to the server's role, and the Go types for
  runs and jobs have no such fields, so it is not built. ADR-0053's
  sender, when it is built, adds the marker to its own tests.
* **Unit tests**: `rbac_test.go` (Technicians and above hold the
  permission, Read-Only does not, the roles stay a chain of supersets);
  the hardening refusal quotes nothing from the output; the
  configuration's default, the shorter default under a short job
  retention, and its refusals; the Compose file passes the setting.
* **Coverage.** `server/internal/httpapi/jobsapi` has no tests of its own:
  its handlers are covered by the API tests in `server/internal/app`,
  because the integration run measures with `-coverpkg=./...`
  (`make test-integration`; floors in `scripts/ci/check-coverage.sh`).
* **Page tests** (`web/src/pages/jobs/jobs.test.tsx`), recording the
  requests the test server receives:
  * Read-Only: the job's and the run's pages say "Hidden: needs
    permission …", hovering a run's row asks for the run only, and no
    request goes to `/output` or `/arguments`;
  * a Technician: one request to `/output` for a finished run, none while
    it is open or when it printed nothing, and none again when the window
    regains focus and the run is asked again; one request to `/arguments`,
    none again when the job refreshes, shared with *Run again*, which
    presets the fetched values and is not offered where they are hidden;
  * *Remove output* with its dialog, after which the page says the output
    was removed and holds no marker; not offered when the run says
    `canRemoveOutput` is false, though the session holds `job.manage`;
  * the audit log's names for the three records, and the *Job output*
    area;
  * the error boundary (`web/src/components/ErrorBoundary.test.tsx`).
* **The browser end-to-end test** (`make e2e`, `web/e2e/console.spec.ts`)
  against a real server, with the simulated agent in `web/e2e/agent.ts`.
  The administrator invites a Read-Only user and adds a script that prints
  its argument. The technician signs in again and runs it with a marker as
  its argument; the simulated agent receives the argument from its poll
  and reports output carrying it. The Read-Only user opens the job and the
  run: both say hidden, asking the two endpoints directly answers `403`,
  and no response their browser receives contains the marker. The
  technician sees the argument and the output, and removes the output,
  after which the page says it was removed. The audit log shows the
  technician's reads and removal and the Read-Only user's refusals.
* **The backup-restore drill** reads its run's output through the new
  endpoint. Changed and checked with shellcheck; not run for this change,
  since it needs a whole deployment.
* The agent does not change, so no agent test or test on a real computer
  is needed. The coverage floors hold for the packages touched.

## Owner questions
1. **30 days.** Output is kept 30 days by default; today it is kept 90,
   with the job. Is 30 right, or should the default stay 90 with the
   setting available to shorten it?
2. **Recovery passwords before the keystore.** Should BitLocker recovery
   passwords be redacted from output now, on the agent before the journal,
   accepting that the console then cannot show a key to help a locked-out
   user until the keystore exists?
3. **Secret arguments.** Should a later ADR plan arguments marked secret,
   as described under Arguments? Scripts that set passwords are common in
   an MSP's library.
