# Notes for the integrator: reading recovery keys (ADR-0081 slice 2, branch ws/ks2)

## Changelog lines

* Reading a BitLocker recovery key from the console: a person with the new Recovery Key Reader add-on role gives a
  reason (at least 10 characters), confirms with their second factor, and sees the key once. The key is shown for 60
  seconds, is never cached or put in any list, export or log, and the organization's administrators get a notice (in
  the console and by email) saying who read which device's key and why.
* The keystore counts and limits reads itself (10 an hour and 50 a day per organization, 30 an hour in all) and keeps
  its own hash-chained log. Every hour the server checks that log against its audit records; a key that left without
  an audit record, or a log that does not verify, raises a critical alert.
* Optional two-person approval per organization (off by default): a second person with the Recovery Key Approver
  add-on approves the read, once, within 10 minutes.

## Implementation status rows

| Item | State |
| --- | --- |
| ADR-0081 read permission (add-on roles `key_reader`, `key_approver`; no built-in role implies them) | built, tested |
| ADR-0081 read: step-up, reason, server limits, audit-then-release, notices (console and mail) | built, tested (real PostgreSQL, real keystore socket); mail tested against a recording sender |
| ADR-0081 keystore limits, append-only hash-chained log, hourly reconciliation and its critical alerts | built, tested (real keystore code on a real socket) |
| ADR-0081 two-person approval (off by default), minimum for key reads | built, tested |
| ADR-0081 console: reveal once, no copy, cleared on close, after 60 s, on hide and leave | built, vitest and an e2e spec against the real server with the read answered by the test |
| ADR-0081 alerts for sealed more than 15 minutes, unreachable, file mode, TPM policy, recovery, KEK overdue, rotation | not built (later slices) |
| ADR-0081 console control to resolve a keystore alert | not built |
| ADR-0081 rotation after a read, LUKS, restore, offboarding export | not built (slices 3 to 5) |

## Privacy notes

* New personal data: the email label of the person who reads, and of the approver, in audit rows, notices and
  requests; the free-text reason they type (kept in the audit log, as the ADR asks; a key-shaped reason is refused).
  No key, ciphertext or fingerprint is stored anywhere new.
* Audit actions added: `recovery_key.read` (success, denied, failure), `recovery_key.read_requested`,
  `.read_approved`, `.read_denied`, `keystore.two_person`, `keystore.alert`.
* The keystore's log holds organization and record IDs and request IDs, never a key.

## For the integrator

* Migration `server/migrations/90351_keystore_reads.sql` (renumber): `role_assignments` checks (two roles),
  `keystore_org_settings`, `recovery_key_requests`, `keystore_log_cursor`, `keystore_alerts`, `keystore_notices`, all with
  forced RLS on `organization_id` (the cursor holds none). Down drops them and the two roles' assignments.
* Hotspot edits (small, additive): `rbac.go` (two permissions, two roles, `AddOnPermissions`; they are not in
  `AllPermissions`, so the super administrator does not hold them), `app.go` (`SetStepUp`, `SetNotifier`), web
  `types.ts` and `StatusBadges.tsx` (roles), `DeviceRecoveryKeys.tsx`.
* New routes (all `RequireActive`): `POST /devices/{id}/escrow/read`, `GET /keystore/requests`,
  `POST /keystore/requests/{id}/approve|deny`, `GET /keystore/notices`, `GET /keystore/alerts`,
  `GET|PUT /organizations/{id}/keystore-settings`. The notice, alert and settings routes have no console page yet;
  the device page shows the reveal and the approvals.
* Deviations are in ADR-0081's Amendments (role add-ons, approvals, own alert table, limits counted from the audit).
* Organization scope: reads are a person's explicit act and refuse an organization outside the dev scope; notices
  mail and the reconciliation's alerts check `devscope.Allowed`.
* Not run: a real BitLocker device, a real TPM keystore container; Go's HTTP buffers may keep a copy of a key.
