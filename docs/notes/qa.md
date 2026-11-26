# Notes for the integrator: Quick Assist (ADR-0080), builder `qa`

Branch `ws/qa`, migrations 90301 to 90303.

## CHANGELOG lines

* Quick Assist (ADR-0080, first slices): one-time links a technician gives a
  user (until code signing exists, test links only, one setting
  `quickassist.link_mode` lifts that), a public link page and download whose
  program carries a signed one-hour ticket, a runner (`easyrmm-agent
  quick-assist`, Linux first) that asks first, shows a six-digit code, and
  removes its folder and reports it at the end, acceptance in the console by
  typing that code, a Quick Assist navigation section with requests, active
  sessions, links and ended sessions, and the audit rows `quickassist.*`.
* New permissions: `quickassist.view`, `.link.create`, `.link.permanent`,
  `.session`, `.session.takeover`, `.install` (the last three and the
  permanent link start at Organization Administrator).

## IMPLEMENTATION_STATUS rows

| Area | State |
| --- | --- |
| Quick Assist links, ticket, limits (QA1) | Built; tested against real PostgreSQL |
| Quick Assist sessions and acceptance (QA2) | Built; tested with the real runner on Linux |
| Quick Assist console (QA4) | Built; vitest and a browser e2e spec |
| Quick Assist Linux runner (QA7, no MeshAgent) | Built |
| Quick Assist Windows runner, MeshAgent, install permanently, EasyPatch ad hoc (QA3, QA5, QA6) | Not built; never run on Windows |

## Privacy

* A session stores the user's computer name, operating system, platform, the
  source address of the request and whether it was elevated, until 30 days
  after it ends. The six-digit code is stored only as a salted hash and is
  never in the audit log; tokens are stored as hashes and are never in it.
* The consent text names the server and what is shared; the runner contacts
  the server only after the user types YES.

## For the integrator

* `docs/security/rbac.md` has the new permissions (edited here, one row).
* `scripts/ci/check-coverage.sh` has floors for the new packages.
* Migrations 90301 to 90303 need renumbering; down migrations work.
* `app.go`, `agentapi.go` and `devices.go` have small additive edits.
* Sites got `kind`; `ListSites`, the device list and the device tree filter
  Quick Assist ones out. Other readers of `devices` (reports, alerts,
  monitoring, patching) do not yet skip `devices.quick_assist`; that
  filter is still to do (ADR-0080 Consequences).
