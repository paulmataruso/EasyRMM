# Quick Assist limits (ws/qa-limits)

Branch `ws/qa-limits`, based on `integration/2026-11` (233ef6d2), because main has no Quick Assist code yet.

## Changelog lines

- Quick Assist ends a session after 30 minutes without activity (5 to 240, a setting). The runner is told by its next poll.
- A technician can extend a running session once, by the session length, from the Active sessions list.
- Permanent links nobody has used for 90 days are marked stale; after 180 days they are revoked and audited.
- Quick Assist limits (idle limit, session length, retention, download burst and refill, waiting cap, permanent link cap) are settings, in Settings > General.

## Implementation status

| Item | State |
| --- | --- |
| Idle limit: `last_activity_at`, sweep, `Status` poll answer, `TouchSession` | Built, integration-tested |
| Activity touches: remote session start and jobs (via `GuardTx`), accept, takeover, install request, extend | Built |
| Extension: `ExtendSession`, `POST /api/v1/quickassist/sessions/{id}/extend`, Extend button within 15 minutes of the end | Built, tested (Go and Vitest) |
| Stale links: `SweepLinks` (hourly from `Run`), stale badge, use clears the mark | Built, tested |
| Settings: `Settings`, `LoadSettings`, `UpdateSettings`; GET and PUT `/api/v1/quickassist/settings`; Settings > General form | Built, tested |
| Migration `90631_qa_limits.sql` | Written |

Details:

- Settings keys: `quickassist.idle_minutes`, `max_session_hours`, `retention_days`, `bucket_burst`, `bucket_refill_minutes`, `waiting_cap`, `permanent_link_cap`. A missing, non-numeric or out-of-range stored value is the default. PUT checks every bound before writing anything and needs `settings.manage` (platform-wide).
- The old exported constants (`MaxSessionLife`, `WaitingCap`, `Retention`, `MaxPermanentLinks`) stay as the defaults; existing tests use them. The unexported bucket constants are the defaults too.
- `PUT /quickassist/settings` took only `{mode}` and asks for step-up. It now takes `mode` (step-up only when set) and any of the limit fields. An empty body is a no-op. `PUT .../settings/default-life` is unchanged.
- The session JSON gained `expiresAt`, `extended`, `lastActivityAt`; the link JSON gained `stale`.
- Extension adds the configured session length to the current `expires_at`, once (`extended` flag), for the holder or anyone with `quickassist.session.takeover`. It also counts as activity.
- A stale link still works; using it clears the mark. A link never used counts from its creation date. Only permanent, active links in dev-scope-allowed orgs are swept.

## Integrator notes

- Migration number: `90631` as asked; renumber to the next free number on merge. It only adds columns and backfills `last_activity_at` from `accepted_at` or `requested_at`.
- Audit actions: new `quickassist.session.extend` and `quickassist.link.revoked` (reason `stale`, actor system). The task named `quickassist.link.revoked` rather than the existing `quickassist.link.revoke`; they are two names on purpose, so a reader can tell a person's revoke from the sweep's. Idle end uses the existing `quickassist.session.end` with reason `idle`.
- `quickassist.Guard` now opens a read-write transaction (it records activity). `GuardTx` writes in the caller's transaction, so callers must not pass a read-only one; the only caller (`jobs.create`) uses `InTx`.
- Idle is measured from `last_activity_at`, not from `last_seen_at`; the runner's own poll does not count as activity, or no session would ever go idle. The lost sweep (runner silent 10 minutes) is unchanged and still runs after the idle sweep.
- `Status` now reads settings on every runner poll (one small query).
- Test DB used: a throwaway Postgres on a private port (`make test-db TEST_DB_CONTAINER=... TEST_DB_PORT=...`).
- `web/node_modules` in this worktree is a symlink I made to run tests; it is not committed.
