# Notes for the integrator: actions and rotation (ADR-0081 slice 4, branch ws/ks4)

## Changelog lines

* BitLocker can be turned on from the console (Disk recovery keys card, a volume shown as "Not encrypted"): it asks for the
  computer's name typed out and your second factor, then the agent makes a recovery password, seals and sends it, the
  keystore checks it, and only then does the agent add the TPM protector and start encryption. It never encrypts on a
  key that was not verified, and refuses a domain controller. Needs the new permission `device.bitlocker.manage`
  (organization administrators and the super administrator).
* A recovery key that was read is replaced: ten minutes after the read the agent adds a new BitLocker recovery password
  (or LUKS key slot), escrows and verifies it, and only then removes the old one; the volume is never without a verified
  key. A rotation that cannot verify, or is not done within a day, raises an alert.
* Rotating the keystore's key re-wraps every organization's escrow key under the new version, in batches that resume;
  rotating an organization's escrow key (Organization > Recovery keys > Escrow key) moves its records to the new key
  inside the keystore. Old keys are kept until nothing needs them.

## Implementation status rows

| Item | State |
| --- | --- |
| ADR-0081 native executor (`native` shell, `job.native`, handlers in the agent) | built, tested (unit, real PostgreSQL with the real agent worker) |
| ADR-0081 BitLocker `enable`: permission, typed name, step-up, dev scope, server gate, agent order, DC refusal | built, tested against a stand-in for WMI; not run on a real computer |
| ADR-0081 Windows manager (WMI: add and delete protector, TPM protector, Encrypt, preconditions) | built, compiled and linted for Windows; protector add/read/delete tested on a virtual disk in CI where the edition has BitLocker; TPM protector and encryption not run |
| ADR-0081 rotation after a read, BitLocker and LUKS (new, verify, then remove; Remove with Successor; Watch) | built, tested (real PostgreSQL and keystore; agent unit; real LUKS2 volumes on loop devices, Alpine) |
| ADR-0081 alert for a rotation that could not verify, overdue rotation | built, tested |
| ADR-0081 KEK rotation: re-wrap job, resumable, reconciliation, per-version usage | built, tested (real keystore with a second KEK version); `destroy-version` and a console request not built (slice 5) |
| ADR-0081 organization-key rotation: new key, re-seal inside the keystore, drained marker | built, tested; destruction of a retired key not built (slice 5) |
| ADR-0081 console: enable dialog, rotation badge, escrow key card, keys per KEK version | built, vitest and an e2e spec (enable confirmations) |

## Privacy notes

* No personal data is added. New data: when a key was read and is due for rotation (`recovery_key_escrows.rotation_due_at`),
  when a retired escrow key was drained (`keystore_org_keys.drained_at`). A rotation alert names the volume and the
  computer's name, never a key.
* Audit actions added: `recovery_key.rotated`, `recovery_key.resealed`, `recovery_key.rotation_failed`,
  `keystore.org_key_rewrapped`, `keystore.org_key_rotated`, `keystore.org_key_drained`, and the job audit
  `winmod.bitlocker.enable` (with `winmod.bitlocker.enable.result`). None carries a key.

## For the integrator

* Migration `server/migrations/00079_keystore_rotation.sql` (renumber; it needs 00066, 00068 and 00070 before it):
  `recovery_key_escrows.rotation_due_at` (+ an index), `keystore_org_keys.drained_at`, and `jobs_shell_check` gains `native`.
  Down removes them (and deletes native jobs).
* Hotspot edits (small, additive): `app.go` (the bitlocker catalog, `SetEscrowGate`), `rbac.go` (one permission, in
  `AllPermissions` and the organization administrator's set), `agentproto` (`jobs.go`: `ShellNative`, `CapJobNative`; `escrow.go`:
  `EscrowNeed` fields, `Watch`; new `native.go`), `modules.go` (`BitLocker`, `Known`; not in `Catalog`), agent `main.go` (the native
  handler map and the manager), `DeviceHardware.tsx` (one prop), `types.ts`, `DeviceRecoveryKeys.tsx`, `RecoveryKeysTab.tsx`,
  `KeystoreTab.tsx`, `backend-tests.yml` (one Windows step in the LocalSystem job).
* New routes: `POST /organizations/{id}/keystore/rotate-key`. `GET /keystore` gains `kekUsage`, `GET .../keystore-settings` gains `key`,
  `GET /devices/{id}/escrow` gains `canEnable` and, per protector, `rotationDue`. The enable action is the existing
  `POST /devices/{id}/winmod/bitlocker.enable`.
* New keystore operations on the service socket: `rewrap_org_key`, `reseal_escrow` (a server built before them cannot call them, and a
  keystore built before them answers "unknown operation": upgrade together, as the one image does).
* Coverage floors: no new package needs one; `server/internal/winmod/bitlocker` is a catalog. Measure `agent/escrow`, `agent/jobs`,
  `internal/agentproto`, `server/internal/keystore`, `keystored`, `jobs`, `keystoreapi` before pushing.
* Organization scope: the re-wrap, the re-seal, the rotation's instructions and its alerts, and the enable gate check
  `devscope.Allowed(orgID)`; rotating an organization's key and enabling BitLocker are a person's acts and are refused (not
  found) outside the scope.
* Not run: a real Windows computer with BitLocker or a TPM (the integrator's test VM), a TPM2-token LUKS volume, a distribution
  other than Alpine for the real-LUKS test, the Windows CI step (it runs on GitHub's runner).
