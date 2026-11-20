# ADR-0048: The engine keeps what is reached

* Status: Accepted (2026-11-20).
* Amends: [ADR-0046](0046-what-one-product-retires.md), whose rule it
  applies to the engine's own routes and to the EasyPatch agent.

## Context
After phase R, two callers reach the patching engine, and nothing else
can:

* **EasyRMM's server**, through `server/internal/easypatch`, with a signed
  statement on every request
  ([ADR-0038](0038-statements-to-the-patching-engine.md)).
* **EasyPatch agents**, through EasyRMM's edge, which forwards
  `/api/v1/agents/`, `/downloads/agent/` and `/downloads/winget/` and no
  other engine path ([ADR-0039](0039-agents-on-easyrmms-name.md)). EasyRMM
  enrolls each agent with a single-use enrollment token made for that
  install ([ADR-0031](0031-easypatch-agent-install.md)).

The engine still served what EasyPatch's own console had used: deployment
codes and the enrollment requests they created, with install scripts and
approval; a dashboard; the compliance report and CSV exports; actions on
one device where EasyRMM sends the bulk routes; and deletes where EasyRMM
archives or cancels. The agent still carried a second way to enroll. None
of it can be reached, yet all of it was built, tested, scanned and
documented, and EasyRMM kept fallbacks, and a capability check, for
engines older than the one it ships with.

## Decision
**The engine serves what EasyRMM or its agents reach, and nothing else.**
As ADR-0046 rules, each test of living behaviour moved first, to the bulk,
trend, cancel and token paths EasyRMM uses; then each route below went with
everything only it used (services, DTOs, script builders, the CSV writer,
the `Dashboard` OpenAPI tag, audit actions, alert rule and settings).

1. **Deployment codes and enrollment requests.** `/api/v1/deployment-codes`
   (list, create, revoke, install script), `/api/v1/enrollment-requests`
   (list, approve, reject, bulk approve), the install scripts under
   `/downloads/install/`, the request credentials (`r_…`) and the policy
   they had, the `EnrollmentPending` alert rule, request expiry and the
   `enrollmentRequestExpiryDays` setting. EasyRMM enrolls with tokens
   only, and its edge never forwarded the install scripts.
2. **The agent's second way in.** `--deployment-code` on Windows, Linux and
   macOS, the MSI's `DEPLOYMENTCODE`, the `DeploymentCode` bootstrap
   setting, polling `enrollment/status`, and the waiting state with its
   tray, command-line and event-log (1001) texts. Token enrollment is
   unchanged.
3. **Routes EasyRMM does not call.**
   * `GET /api/v1/agent-versions` and `/api/v1/dashboard/summary` and
     `/activity`: EasyRMM reads agent versions from the endpoint list and
     has its own dashboard.
   * `GET /api/v1/reports/compliance`, `compliance.csv` and
     `installations.csv`: EasyRMM reads the compliance trend, the endpoint
     list and the installations as JSON, and makes its own exports.
   * `GET /api/v1/organizations/{id}/endpoints`: EasyRMM lists
     `/api/v1/endpoints`.
   * `DELETE /api/v1/endpoints/{id}` and `GET /api/v1/endpoints/{id}/events`:
     EasyRMM revokes an endpoint or uninstalls its agent, and shows jobs and
     history.
   * `POST /api/v1/endpoints/{id}/scan`, `inventory-refresh`, `restart`,
     `notify` and `agent-update`: EasyRMM sends the bulk routes, which
     answer per endpoint, and agents report their inventory on their own.
     The agent's handling of `InventoryRefresh` jobs, which only
     `inventory-refresh` queued, goes too; the job type stays so earlier
     jobs still read, and an agent reports one as unsupported.
   * `DELETE` of jobs, organizations and sites: EasyRMM cancels jobs and
     archives organizations and sites.
   * `POST /api/v1/organizations/{id}/restart-pending`: EasyRMM reads the
     list and restarts through `bulk/restart`.
   * `POST /api/v1/endpoints/tags/bulk`: EasyRMM sets each endpoint's tags
     with `PUT …/tags`.
4. **EasyRMM's fallbacks for older engines.** The restart plan for engines
   before 1.10.0, which had no `restart-pending` list (every device treated
   as a server, `serversKnown`); reading the settings before saving them
   to keep those EasyRMM did not show; and the check for the
   `scheduled-installs` capability before offering to install later
   (`canSchedule`, and Settings' *Install later*), with `capabilities` in
   the engine's `/api/v1/server-info`, which only that check read. EasyRMM
   ships with its engine, so it always offers to install later, and now
   shows every engine setting, which the contract test checks both ways.

**What stays, because something reaches it:**

* `deploymentCode` stays in the enroll request's contract. An agent up to
  1.11.1 sends `"deploymentCode": null`, or nothing, with its token and
  enrolls as before. A request that carries a code is refused with
  `400 deployment_codes_retired`, and its token, if any, is not used.
* `POST /api/v1/agents/enrollment/status` stays as an anonymous route that
  always answers `401 unknown_credential`. An older agent waiting for
  approval polls it; told that its request is unknown, it enrolls again
  with its code, is refused with `deployment_codes_retired`, clears the code
  and waits for a new one without calling the engine, instead of failing
  every minute.
* `GET /api/v1/alert-rules/types`, which the contract test holds EasyRMM's
  rule types to; `GET /api/v1/organizations/{id}/restart-pending`, which
  EasyRMM's restart plan reads; the `PUT …/tags` routes; enrollment tokens
  and agent packages, which EasyRMM's agent install uses.

A migration, `DeploymentCodesRetired`, drops `deployment_codes`,
`enrollment_requests` and `endpoints.enrollment_request_id`, and deletes
`EnrollmentPending` alert rules and their alerts. The tables of EasyPatch's
accounts stay, as ADR-0046 decided.

## Consequences
* **Imports.** `prepare-import` brings an imported database to the engine's
  schema, so the migration drops the old server's deployment codes and
  requests. Its audit log keeps their history, and EasyRMM's view of the
  engine's audit log still names them. Agents it enrolled with a code are
  endpoints like any other and keep working; one still waiting for
  approval stops and is installed again from EasyRMM.
* **Older agents.** An agent up to 1.11.1 installed with a token enrolls
  and works as before. One installed with a deployment code that has not
  enrolled is refused and stops calling the engine, as is one waiting for
  approval at its next poll; each logs the engine's message. An older agent's state saved
  while waiting no longer reads in a newer agent, which keeps it aside and
  starts fresh, as with any unreadable state.
* **Dropped tables.** The migration's `Down` recreates the tables empty; the
  codes and requests themselves come back only from a backup.
* **Fewer ways in.** No anonymous install scripts, one agent credential
  kind (`c_…`), and one way to enroll, which EasyRMM controls.
