# Feature 11 slice 2: maintenance windows and pacing

Licensed under FSL-1.1-ALv2; licensor DHI Technical Services LLC.

## What it does

* **One set of windows (feature plan F4).** ADR-0053's `site_maintenance_windows`
  table gains a `purpose` column: `notifications` (what every window did until
  now, and the default), `tasks`, or `both`. No second table. The notification
  planner (`notify/due.go`) holds notifications only for windows whose purpose
  includes them. The API (`purpose` on create and update) and the Notifications
  tab's window list and dialog carry it.
* **Window on a task.** `automations.window_id` (nullable, `ON DELETE SET NULL`).
  Saving checks that the window is in the task's organization (and site, if the
  task has one), allows tasks, and is at least as long as the stagger. At each
  run the scheduler checks the window again: switched off, or no longer allowing
  tasks, or closed now, the run is recorded as skipped with the reason (audit
  `automation.run_skipped`). A task with a window and no site reaches only the
  window's site. Deleting a window that active or paused tasks use is refused
  (`window_in_use`).
* **Stagger.** `automations.stagger_minutes` (0 to 1440). The devices of each
  site are spread evenly over the span in whole minutes (`schedule.Spread`,
  `schedule.Plan`); the first device of every site starts at once and the rest
  become rows of `automation_run_batches`, run by the scheduler tick when due.
  The span is cut to what is left of the window (less a minute). Each batch
  re-checks the window, the owner's permissions, the script hash and which
  devices are still there and online. The run stays `running` until its last
  batch is made, then closes as succeeded or failed (any failed batch) with a
  summary. Batches left running by a crash fail after ten minutes.
* **Only if online.** `automations.only_if_online`: devices without a live
  agent connection (`agent_online_until`) get no job, at the start and again at
  each batch; the run's detail says how many were left out.
* **API.** Existing routes carry `purpose`. New:
  `GET /api/v1/organizations/{id}/maintenance-windows?siteId=&purpose=tasks`.
  Scheduled-task create and patch take `windowId`, `clearWindow`,
  `staggerMinutes`, `onlyIfOnline`.
* **Web.** Notifications tab: purpose in the window dialog and list. Scheduled
  task form: window picker (windows that allow tasks), stagger, only-if-online.
* `devscope.Allowed(org)` still guards every automatic start, including each
  batch.

## For the integrator

* Migration `90610_maintenance_windows_pacing.sql` needs renumbering.
* The brief listed purposes `maintenance, patching, restart, general`; the
  feature plan (F4) and ADR-0053's amendment define the purpose as what the
  window does (hold notifications, allow tasks, or both), so the plan's meaning
  is used. A finer category could be added later as a second column.
* Windows are per site (ADR-0053's table). There is no organization-wide window.
* The ADR-0053 text and `docs/architecture/database.md` list the table without
  `purpose`; update them with the renumbered migration. CHANGELOG, ROADMAP and
  IMPLEMENTATION_STATUS were not touched.
* Not covered: a window that is open for part of a stagger and closes (batches
  are skipped, tested), restarts across a daylight-saving change inside a
  window (the window logic is ADR-0053's `wallInstant`, unchanged).
