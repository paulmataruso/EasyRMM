# log0: ADR-0060 slice 0 (Windows jobs inside their job object)

Branch ws/log0. Only `agent/jobs/exec_windows.go` changed in behaviour.

## What it does
`startLimited` (also used by builtins) now makes the job object and attaches a
completion port (refusing the run if either fails), starts the process with
`CREATE_SUSPENDED` added, assigns it (terminating and reaping it and refusing
on failure), then resumes its thread found by Toolhelp32. Still `os/exec`, so
inherited handles, pipes and command lines are unchanged. A goroutine drains
the port and records process ids (cap 4096) for slice 3.

## Decided in review
* Builtins take the same steps and are refused the same way.
* A resume failure terminates the job and refuses the run.
* The port is drained from the start, not left to fill; ids only, no creation
  times yet (slice 3).
* Slice 1 not taken: its verification needs real computers, and it merges after
  F1 and F2.

## Tests
`agent/jobs/exec_job_windows_test.go`: child and its child in the job and on
the port, a short-lived child reported, assignment before the process runs,
refusal on make/attach/assign failure with the process gone, no thread,
Execute refusing, exit codes and arguments unchanged. Failures are injected
through package variables (`createJobObject`, `associatePort`, `assignToJob`).

## Changelog
* Windows jobs now start inside their job object from their first instruction,
  and a run is refused, with the reason, if the job object cannot be made or
  assigned (ADR-0060 slice 0).

## Implementation status
* ADR-0060 slice 0: built; Windows CI run recorded in the report.
* ADR-0060 slices 1 to 10: not started.

## Privacy
None: no new data is stored or sent.
