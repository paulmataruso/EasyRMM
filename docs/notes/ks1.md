# Notes for the integrator: the keystore and BitLocker escrow (ADR-0081 slice 1, branch ws/ks1)

## Changelog lines

* A keystore for BitLocker recovery keys: a separate container with no network holds the key that protects
  them, sealed to the host's TPM (or a passphrase typed at the host; a file only if chosen on purpose). The server
  and its backups never hold it. `./scripts/easyrmm-keystore init` shows a recovery code once and will not wrap
  anything until a restore from the recovery bundle has been proved.
* Windows agents read their BitLocker recovery passwords themselves (through WMI, never a script), seal them to
  the organization's key and send them; the keystore checks each and the device page shows, per volume, whether
  the key is missing, pending, verified, stale or in conflict. Nothing can read a key back yet.
* The backup guide keeps `.env` and the secrets directory apart from the database dumps.

## Implementation status rows

| Item | State |
| --- | --- |
| ADR-0081 keystore process: init, KEK versions, recovery bundles, verify-recovery, wrap refused until verified | built, tested (unit) |
| ADR-0081 TPM mode (go-tpm, /dev/tpmrm0, PCR 7 policy) | built, tested against a software TPM (cgo test); not run on a real TPM |
| ADR-0081 passphrase mode (Argon2id, unseal at the host only) and file mode (opt-in) | built, tested |
| ADR-0081 organization escrow keys (HPKE, crypto/hpke), wrapped under the KEK | built, tested |
| ADR-0081 signed escrow-key instruction, device-signed escrow routes, verification inside the keystore, per-volume states in the console | built, tested (real PostgreSQL, real keystore socket, real agent client) |
| ADR-0081 agent BitLocker WMI reader | built, compiled and linted for Windows; not run (no BitLocker volume yet) |
| ADR-0081 compose service, setup.sh, backup guide, updater mount rule | built; compose validated (`docker compose config`); no container started |
| ADR-0073 native executor | catalog accepts it; the server refuses to run one until slice 4 |
| ADR-0081 reads, LUKS, rotation, restore, keystore log, reconciliation, alerts | not built (slices 2 to 5) |

## Privacy notes

* No personal data is added. New data: per-volume identifiers (volume device ID, drive letter, protector GUIDs) and
  sealed recovery-key records (HPKE ciphertext, 16-byte fingerprint), in organization-scoped tables with forced RLS.
* Audit actions added: `keystore.org_key_created`, `recovery_key.escrowed`, `.verified`, `.stale`, `.conflict`.
  None carries a key.

## For the integrator

* Migration `server/migrations/90311_keystore.sql` (renumber): `keystore_kek_versions`, `keystore_org_keys`,
  `device_encrypted_volumes`, `recovery_key_escrows`. Down drops all four.
* Hotspot edits (small, additive): `app.go` (Deps.Keystore, wiring, route, background loop), `agentproto`
  (`HeartbeatRequest.Caps`, `HeartbeatResponse.Escrow`, `internal/agentproto/escrow.go`), agent `runner.go`
  (`Escrow` field, caps, answer), agentapi (routes, heartbeat instruction), `DeviceHardware.tsx` (one card).
* New dependencies: `go-tpm` (direct now), `go-tpm-tools` (test only, cgo), `go-ole` (Windows agent). All permissive.
* Deviations from the ADR, recorded in its Amendments: the keystore is the server image's second binary (no
  image of its own, so release manifests and the updater's pull and verification are unchanged); the socket
  folder is `run/` inside the state directory, so no tmpfiles entry is needed; the TPM device is mapped through
  `EASYRMM_TPM_DEVICE` (not a second compose file, which the updater refuses).
* The updater (ADR-0052): `checkMounts` accepts the keystore's mounts and refuses them anywhere a backup copies;
  nothing else changed, since `compose up --wait` already waits on the keystore's health check, which passes sealed
  or unsealed.
* `scripts/drill/backup-restore.sh` now writes `.env` to a folder apart from the dumps; it was not run.
* Coverage floors added for `internal/escrowcrypto`, `server/internal/keystored`, `server/internal/keystore`,
  `server/internal/httpapi/keystoreapi` and `agent/escrow`.
* Organization scope: the escrow-key instruction, key creation, pending checks and the volume report check
  `devscope.Allowed(orgID)`. The dev-scope guard had landed in this base.
* Real BitLocker, a real TPM and a started keystore container were not tested.
