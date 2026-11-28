# Notes for the integrator: slices P2 and P3 (ADR-0082, posture state controls), partly built

## Changelog lines

- Security posture (ADR-0082, slices P2 and P3): two state controls join the score, each weighing 3, read from data the server already
  holds. **Disk encryption state** says whether the system volume is encrypted (Linux: a LUKS volume at `/`; Windows: BitLocker on `C:`;
  a computer that has not reported its volumes yet is "cannot tell"). **Defender health** (Windows, when the Defender module has read
  the computer) says whether real-time protection and antivirus are on, signatures are under 7 days old and a scan ran in the last 14
  days; Defender in passive mode leaves the score. They show in the Security column, the Security report and the computer's card
  with no screen change.

## Implementation-status rows

| Item | State |
|---|---|
| ADR-0082 P2: Linux disk encryption state (LUKS root) | built, tested against PostgreSQL |
| ADR-0082 P3: Windows BitLocker system volume state | built, tested against PostgreSQL |
| ADR-0082 P3: Windows Defender health (real-time, signatures, scan) | built, tested against PostgreSQL |
| ADR-0082 P2: UID-0 accounts, sudo/wheel members, insecure account settings, TPM and Secure Boot | not built: the agent does not collect them |
| ADR-0082 P3: local administrators, inactive accounts, insecure account settings | not built: the agent does not collect them |
| Disk encryption and Defender health on a real computer | not run; tests write the rows the agent and the Defender module write |

## For the integrator

- Migration `90701_posture_volume_reports.sql` (the reserved 90701 to 90709 range): `device_volume_reports` (device, kind, time of the
  newest volume report). It follows its device in the move test (added to `move_api_integration_test.go`). The keystore's
  `ReportVolumes` writes it inside its existing transaction, after the devscope check.
- Posture reads three tables it did not read before: `device_volume_reports`, `device_encrypted_volumes`, `windows_module_snapshots`
  (action `defender.status`). All reads are of the computers `devscope.Allowed` let through.
- A Linux or Windows computer whose agent has not yet reported volumes now reads "cannot tell" until it does (the agent reports about
  hourly while the keystore key is pinned). The Linux test fixture seeds a report, as slice P5's did for logs, so other tests keep
  their meaning; their expected percentages moved because the new control weighs 3.
- The control ids `disk-encryption` and `defender-health` are not the hardening modules `luks`, `bitlocker` and `defender`, which check
  settings, so one gap is not counted twice under one name.
- Coverage floor of `server/internal/posture` raised from 77 to 80 (measured 81.3).
- `TestMoveDispositionOfEveryTable` (and the other Move tests in `server/internal/app`) fail on integration at b04c1c1d with
  `winmod: action "ntp.set_ntp_server": a script does not match its pinned SHA-256`, before and after this change; not touched here.

## Known limits

- The Windows system volume is taken to be `C:`, the Linux root the volume whose first mount point the agent reports is `/`. A system on
  another drive letter reads "not in place". A LUKS root below LVM is found only when the agent's first mount point under the volume is `/`.
- A Windows computer with no `defender.status` snapshot (Defender module off) has no Defender health control, as an unlinked computer has
  no patching control.
- No privacy impact: volume ids and mount points were already stored; Defender's snapshot is read for four numbers and switches.
