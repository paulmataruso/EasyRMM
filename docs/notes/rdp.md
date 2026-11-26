# Notes for the integrator: saved RDP credentials (ADR-0079, branch ws/rdp)

## Changelog lines

* Saved RDP credentials: a person can save an RDP login for a device, sealed with the server key, and connect
  with it. The password is never shown again and never reaches the browser or MeshCentral's database; the
  gateway writes it into the RDP connection request. Saving and using one need a fresh second factor, and every
  use is audited.
* The remote desktop page asks how to sign in when a credential is saved for the device.
* New permission `device.rdp_credentials.save` (technicians and above).
* MeshCentral's own "remember credentials" is forced off in every RDP connection request.

## Implementation status rows

| Item | State |
| --- | --- |
| ADR-0079 gateway frame rewrite, savepass forced off | built, tested (unit, fuzz, real MeshCentral) |
| ADR-0079 storage, API, audit, cascades (personal level) | built, tested (real PostgreSQL) |
| ADR-0079 console: chooser, save, replace, delete | built, tested (vitest, e2e with a stubbed device) |
| ADR-0079 shared (organization) level, re-seal job, keystore move | not built |
| ADR-0079 real RDP session against Windows | not run |

## Privacy notes

* New personal data: the user name and domain of a saved account, in clear (they are in the audit rows too);
  the password sealed. Deleted with the person, the device or the organization; purged with an audit row when a
  device moves organization.
* Audit actions added: `rdp_credential.created`, `.replaced`, `.deleted`, `.used`, `.use_denied`, `.purged`.

## For the integrator

* Migration `server/migrations/90171_rdp_credentials.sql` (renumber).
* `docs/security/rbac.md` and `web/src/api/types.ts` list the new permission.
* The shared level and re-sealing need `rdpcreds` to join the key-rotation job (ADR-0057) when that lands.
* Coverage floors for `server/internal/rdpcreds` and `server/internal/httpapi/rdpcredsapi` are added in
  `scripts/ci/check-coverage.sh`.
* Organization scope: saving, listing and use check `devscope.Allowed(orgID)`.
