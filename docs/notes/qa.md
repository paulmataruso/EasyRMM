# Notes for the integrator: Quick Assist (ADR-0080), builder `qa`

Branch `ws/qa`, migrations 00063 to 00065.

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
| Quick Assist console (QA4) | Built; tab navigation, vitest and a browser e2e spec |
| Quick Assist Linux runner (QA7, no MeshAgent) | Built |
| Quick Assist install permanently (QA5) | Built; tested with the real runner flow on Linux |
| Quick Assist Windows runner and ad-hoc MeshAgent (QA3) | Built, compiles for Windows; never run on Windows or MeshCentral |
| EasyPatch ad-hoc mode (QA6) | Agent flag built and compiles; runner side, token and device removal not built |

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
* Migrations 00063 to 00065 need renumbering; down migrations work.
* `app.go`, `agentapi.go` and `devices.go` have small additive edits.
* Sites got `kind`; `ListSites`, the device list and the device tree filter
  Quick Assist ones out. All other readers of `devices` (reports, alerts,
  monitoring, patching, compliance, slow devices) now skip
  `devices.quick_assist` (done).
