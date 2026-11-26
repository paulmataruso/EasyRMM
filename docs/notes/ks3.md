# Notes for the integrator: keystore alerts, console pages and LUKS escrow (ADR-0081 slice 3, branch ws/ks3)

## Changelog lines

* The keystore raises its own alerts from the server's checks: unreachable (after three failed checks), sealed for more
  than 15 minutes, the TPM policy changed, protection by a file, a recovery that has not been verified, a KEK version
  overdue for verification, and an escrow that conflicts with the verified one. They close by themselves when the
  condition ends, are mailed to the administrators once, and a person can resolve one from the console.
* Settings > Keystore (state, key versions, every open alert) and an organization's Recovery keys tab (the two-person
  switch, off by default and recommended; every read of a recovery key with who and why; the organization's alerts).
* Linux: where the agent can unlock a LUKS2 volume by itself (a key file in /etc/crypttab, or a TPM2 token), it adds a
  key slot of its own with a 200-bit passphrase, tests it, seals it to the organization's key and escrows it. A
  volume only a passphrase unlocks is shown as *cannot escrow*; Clevis-managed volumes are left alone. A slot that
  disappears or changes makes the escrow stale and the agent makes a new one, removing the stale slot only after the
  new key is verified and never the last slot of the volume. The key is read through the same audited path as a
  BitLocker key.

## Implementation status rows

| Item | State |
| --- | --- |
| ADR-0081 condition alerts (unreachable, sealed, TPM policy, file mode, recovery not verified, KEK overdue, escrow conflict) | built, tested (unit for the rules, real PostgreSQL and a real keystore socket for the monitor); *sealed* and *TPM policy* only through the rule, not on a sealed keystore |
| ADR-0081 console control to resolve an alert | built, tested (integration, app, vitest, e2e) |
| ADR-0081 console pages: Settings > Keystore, organization Recovery keys tab | built, vitest and an e2e spec |
| ADR-0081 LUKS escrow (agent: key file unlock, add slot with token, test, seal, upload, wipe; replace; rules) | built, tested on real LUKS2 volumes on loop devices (Alpine, cryptsetup 2.7.5; Debian 12, 2.6.1) |
| ADR-0081 LUKS per-volume states (escrowable, cannot escrow, managed elsewhere, stale on a changed or missing slot) | built, tested (real PostgreSQL, the real server with a stub for cryptsetup) |
| ADR-0081 LUKS unlock through a TPM2 token | built; not run (no TPM2 token on a test volume) |
| ADR-0081 rotation after a read, LUKS rotation on request, KEK and organization-key rotation, restore, offboarding export | not built (slices 4 and 5) |
| ADR-0081 alert for a rotation that could not verify | not built (slice 4 has the event) |

## Privacy notes

* New data: the LUKS UUID of a volume, the UUID of EasyRMM's token and the hash of its key slot's header metadata
  (`device_encrypted_volumes`, `recovery_key_escrows`), a short reason in words for a volume that cannot be
  escrowed, and who resolved an alert (`keystore_alerts.resolved_by`, `resolved_by_label`, an email label). No key,
  passphrase or fingerprint is added anywhere new beyond slice 1's sealed records.
* Audit actions added: `keystore.alert_resolved`; `recovery_key.stale` now also carries `why` (slot_gone,
  slot_changed) and `kind`.

## For the integrator

* Migration `server/migrations/00070_keystore_alerts_luks.sql` (renumber; it needs 00068 before it): `keystore_alerts`
  gains `resolved_by`, `resolved_by_label`; `device_encrypted_volumes` gains `escrow_state`, `reason` and a mount
  length of 64; `recovery_key_escrows` gains `slot_hash`. Down reverses all (it deletes volume rows whose mount is
  longer than 16 so the old check can return).
* New routes: `POST /keystore/alerts/{id}/resolve`. The agent's `PathEscrowVolumes` and `PathEscrow` carry a LUKS kind
  and fields (`kind`, `state`, `reason`, protector `hash`, `slotHash`, need `replace`); an older agent is unaffected.
* Hotspot edits (small, additive): `DeviceHardware.tsx` (one card for non-Windows devices, hidden unless a LUKS
  volume was reported), `levelTabs.tsx` (one tab), `SectionNav.tsx` (one Settings part and an icon), `SettingsPage.tsx`
  (one part), `fakeApi.ts` (a default `GET /devices/:id/escrow` route, so a non-Windows device page does not trip the
  unmatched-request check), `agent/cmd/easyrmm-agent/main.go` (`LUKS: cryptsetup.System()`).
* New package `agent/escrow/cryptsetup` (Linux backend; no coverage floor, since its tests need root and loop
  devices and run only through `scripts/ci/luks-test.sh`). Run it before releases:
  `scripts/ci/luks-test.sh [image]` (a privileged throwaway container with host networking). Floors in
  `check-coverage.sh` are unchanged.
* Deviations from the ADR are in its Amendments (a LUKS fingerprint exists; LUKS1 is cannot escrow; how the slot is
  marked; the monitor's thresholds).
* A Linux agent now gets the escrow-key instruction (an organization's key is made on its first heartbeat) even if
  the computer has no LUKS volume; the dev-scope guard applies as for Windows.
* Organization scope: the instruction, report, upload and alert mail check `devscope.Allowed(orgID)`; the monitor's
  alerts are keystore-wide, not for an organization. Resolving an alert is a person's act.
* Not run: a real TPM2 token, a Windows or BitLocker device, a real TPM keystore container, a distribution other
  than Alpine and Debian 12 for cryptsetup, systemd-cryptenroll volumes. `hardening.test.tsx` "10 of 14 modules"
  fails on this base without these changes.

* LUKS escrow is opt-in per organization (`keystore_org_settings.luks_escrow`, off by default, `org.manage` + step-up, audited as `keystore.luks_escrow`, on the Recovery keys tab). Off: volumes are reported and shown as *escrow off*, the server asks for nothing and refuses LUKS uploads; the agent only ever adds a slot for a volume the server's need list names.
