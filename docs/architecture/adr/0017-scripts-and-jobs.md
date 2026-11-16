# ADR-0017: Scripts and jobs

* Status: Accepted (2026-11-16). Phases ADR-0009's job delivery: signed
  HTTPS long polling now, the WebSocket channel later.

## Context
Phase 7 brings automation: technicians run scripts on devices and read what
they printed. ADR-0009 already fixes the principles: jobs are durable rows,
delivery is at least once with idempotent ids, results are accepted once,
and the server signs what it asks a device to run, so a TLS-intercepting
middlebox cannot inject work. RBAC has had `script.view`, `script.manage`,
`script.run`, `job.view` and `job.manage` since phase 2; Site
Administrators manage scripts "for a site or organization", Technicians run
them.

## Decision

### Script library
* A script has a name, a description, a shell, a body and a default timeout.
  Linux shells come first: `sh`, `bash` and `python3`. PowerShell and `cmd`
  arrive with the Windows agent.
* A script belongs to the **shared library** (every organization), an
  **organization** or a **site**. Writing it needs `script.manage` at that
  level: platform-wide for the shared library (super administrators), an
  organization-wide grant for an organization's script, a site grant for a
  site's. A site administrator therefore never edits code that runs on
  another site's devices.
* Reading it needs `script.view` at its level or below: anyone with
  `script.view` somewhere reads the shared library; an organization's
  scripts are read by people with `script.view` in it or in any of its
  sites.
* Bodies are at most 64 KiB of UTF-8 without NUL; line endings are stored
  as LF. Names are unique within a level, case-insensitively. Timeouts run
  from 1 second to 4 hours (default 5 minutes). Creating, changing and
  deleting a script is audited with the body's SHA-256.

### Jobs and runs
* A **job** runs one script on up to 500 devices. It stores a snapshot of
  the script (name, shell, body and its SHA-256), the arguments (at most 32,
  each at most 1 KiB, no NUL), the timeout, and how long to wait for an
  offline device (1 hour to 7 days, default 24 hours). Editing or deleting
  the script later does not change what the job ran.
* Only library scripts run; there are no ad hoc scripts in this phase, so
  `script.run` lets a technician run reviewed code without letting them
  write it. (Interactive terminals remain a separate permission.)
* Starting a job needs, for every device, `script.run` at the device's site,
  a device that is enrolled with the EasyRMM agent on a platform the shell
  supports, and a script whose level covers the device: the shared library
  covers every device, an organization's script its organization, a site's
  script its site. One device failing a check refuses the whole job.
* Each device gets a **run**: `queued` → `sent` (delivered) → `running` →
  `succeeded` (exit code 0), `failed` (other exit code, or the script could
  not start), `timed_out` or `canceled`. A run the device never picks up
  becomes `expired`; a run that starts but never reports within its
  deadline (start + timeout + 5 minutes) becomes `lost`; a late result
  still replaces `lost`.
* Every run is audited when the job is created, as `device.script_run`
  with the script's name and SHA-256, the job and run ids and the number of
  arguments. Argument values stay out of the audit log, which outlives jobs
  and may be exported; they are kept with the job.
* Canceling (`job.manage` at the device's site) cancels a queued or
  delivered run at once; a running run is asked to stop and reports
  `canceled` when the agent has killed it.
* Runs are tenant rows with the device's organization and site under
  row-level security; a job is visible through the runs the caller can see,
  and each caller sees only those runs. Jobs and their output are removed
  after `EASYRMM_JOB_RETENTION` (default 90 days) once every run has
  finished.

### Delivery
* The agent long-polls `POST /api/agent/v1/jobs/poll` with a signed request
  (ADR-0015). The server answers at once when it has work, otherwise holds
  the request for up to 25 seconds and answers when a run for the device is
  queued or canceled on this server instance. Several instances still
  deliver within one poll interval. At most 8 jobs go out per answer.
* Delivery is at least once: a run delivered but not started within two
  minutes is delivered again. The agent recognizes it by its run id.
* Before running, the agent calls `POST /api/agent/v1/jobs/{run}/start`;
  the server answers `proceed: false` when the run was canceled, expired or
  has finished, so a late redelivery never runs. Starting twice is allowed
  (the agent may have crashed between the call and its journal), so the
  agent records a run as started before it executes anything.
* Results go to `POST /api/agent/v1/jobs/{run}/result` (at most 4 MiB);
  the first result for a run wins and repeats are acknowledged and ignored.
* A sweeper on the server expires runs past their wait and marks lost runs
  every 30 seconds.

### Signing
* The server holds an Ed25519 **job-signing key**, generated on first start
  and stored sealed in the settings table like the internal certificate
  authority (ADR-0016). Its public key goes to the agent in the enrollment
  and heartbeat responses; the agent pins it on first sight in its
  configuration and refuses jobs signed by any other key.
* A job is a JSON payload (version, run, job and device ids, shell, script,
  arguments, timeout, issue and expiry times) signed over
  `EASYRMM-JOB-SIG-V1\n` + the payload. The agent checks the signature, the
  device id and the expiry before anything else. A job that fails the check
  is not run, and the agent reports it as failed with the reason.

### Execution on the agent
* The agent runs at most four scripts at once. Each run gets a private
  temporary directory with the script file; the interpreter runs there as
  the agent's user (root on Linux) in its own process group, with standard
  input closed and a minimal environment (`PATH`, `HOME`, `LANG`,
  `EASYRMM_JOB_ID`, `EASYRMM_RUN_ID`).
* At the timeout or on cancellation the process group gets SIGTERM, then
  SIGKILL ten seconds later.
* Standard output and error keep their first and last 128 KiB each; what
  is cut is marked and the run says it was truncated. Output is stored as
  UTF-8 text without NUL.
* A journal (`jobs.json` in the state directory) records each run as
  received, started and finished, so a restarted agent reports finished
  runs it had not reported, reports interrupted ones as failed ("the agent
  restarted while the script ran") and never runs a job twice.

## Consequences
* Running a script needs the agent's job loop, which works through any
  proxy that allows the agent's HTTPS requests; there is no inbound
  connection to the device.
* Jobs cannot be injected by a middlebox or a database row alone: without
  the sealing key, nothing the agent trusts can be signed. An attacker
  present during enrollment could substitute the key the agent pins, as
  they could the server's certificate.
* Rotating the job-signing key needs a signed hand-over that agents accept;
  until that exists, a server restored without its secret key must
  re-enroll its agents.
* Output is held in PostgreSQL. With 500 devices and full output a job is
  about 256 MiB; retention and the per-stream cap bound the total.
