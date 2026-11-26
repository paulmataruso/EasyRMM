# wtest: the Windows module scripts run on a real Windows Server 2025 domain controller

## Changelog lines

- Windows servers with the Print Server role are now reported as print servers when a printer is installed, not only when one is shared; Defender is reported as a role on every Windows server and desktop that has it (it was never reported).
- Fixed on a real server, in the Windows management modules: every read without parameters (DHCP, DNS, file sharing, print, backup) failed; Defender's list reads and its exclusion and Controlled Folder Access changes failed or said "not supported" for an empty list; Controlled Folder Access and Attack Surface Reduction could not be turned on without the EasyPatch agent installed; the Active Directory replication health check never ran; DHCP reservation and lease changes failed; the CA certificate, the CA findings (every default template was flagged), request templates and reinstated certificates were wrong; backup file specs, targets and disk targets were wrong.

## Implementation-status rows

- Windows module scripts (Defender, Backup, Active Directory, DNS, DHCP, certificate authority, file sharing, print): **run for real** in Windows PowerShell 5.1 as SYSTEM on a Windows Server 2025 domain controller of its own forest (AD DS, DNS, DHCP, AD CS, file and print server, Windows Server Backup); the real outputs are `testdata/real` fixtures of each module, read by the catalogue's own decoders (`realoutput_test.go`).
- Not run for real: DHCP leases (needs an active scope); Defender quick and full scans; more than one domain controller; bare-metal backup; Tamper Protection on.
- Role detection: all eight roles of the agent's Facts verified on that server.

## Privacy notes

- None. The fixtures use made-up names (`contoso.test`, `HQ-DC1`) and addresses; no real name or address is in the repository.

## For the integrator

- No migrations. The scripts' pins were rewritten (`pins.go` of each module and `StatusSHA256`; Active Directory by `gen.sh` from `src/`).
- Changes in the agent: `agent/roles` (`Inputs.PrintQueue`, `serviceState` with query-only access).
- `server/internal/winmod/realtest` is a new test helper.
- The ADRs 0073 to 0077 carry the amendments (decided in review).
- The open questions of `roles2.md` and `ad.md` are answered in ADR-0076 and ADR-0075: the `certutil -view` column names and the `-dump` date labels are as guessed; `Get-CATemplate` and the SYSTEM write gate work as SYSTEM.
