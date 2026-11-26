# roles2: the certificate authority, file sharing and print modules (ADR-0076, slices C1 to C6 less ESC5, F1 to F3 and F6 in part, P1 to P6 in part)

## Changelog lines

- Windows servers with Active Directory Certificate Services show a "Certificate authority" view in the Roles tab: the CA's state, its certificate and revocation list, the requests waiting, issued, revoked and failed, and the templates it publishes. Administrators can approve or deny a pending request, revoke a certificate with a reason (certificate hold can be reinstated), publish the revocation list, and publish or unpublish a template. Approving, revoking and publishing a template that lets the requester name the subject ask for the computer's name and a second factor. The CA's keys are never shown or touched, and templates are never edited.
- A weekly read-only check looks for the ESC1 to ESC8 certificate misconfigurations (ESC5 not yet) and lists what it found.
- File servers show a "File shares" view: shares and their permissions, open sessions and files. Administrators can create, change and remove a share, grant, revoke, block and unblock share access, and close a session or an open file. SYSVOL, NETLOGON, print$ and every share ending in $ are shown and never changed; opening a share to Everyone, Anonymous Logon or Authenticated Users for writing is refused.
- Print servers show a "Print" view: printers, queues and jobs, ports and drivers (read only), and the Point and Print security state. Technicians can pause and resume printers and pause, resume, restart and cancel jobs; Site Administrators can also see document names and owners, clear a queue, remove a printer, add or remove a driver already in the driver store, and restart the Print Spooler. A button can only strengthen Point and Print.
- New permissions `print.view_sensitive` and `print.destroy` (Site Administrator and above).
- New alerts: CA certificate expiring (90 days warning, 14 days critical), CA revocation list about to lapse, Certificate Services stopped, print queue stuck, Point and Print weakened (all on); CA misconfiguration findings, file server service stopped, print service stopped (off).

## Implementation-status rows

- Certificate authority module: reads, templates, requests, approve, deny, revoke, unrevoke, CRL publish, `ca_findings`, activity, four alert kinds: built; unit tests (catalog, params, `certutil` verb allowlist, no key operation, restriction helpers, alerts), the findings logic run in PowerShell 7.5 (Docker), integration tests (permission matrix, confirmation, step-up, alerts on real PostgreSQL), vitest. **Scripts not run against a real CA.** The `certutil -view` column names, the `-dump` date labels, `Get-CATemplate` as SYSTEM and the registry paths are all to confirm on the test CA (slice C1). Not built: ESC5, CDP fetch, the revocation-outside-the-console alert.
- File sharing: F1 to F3 and the service-stopped alert: built and tested as above. **Not run on a real file server.** Not built: NTFS edits and the bound (F4), FSRM quotas (F5), `share_changed` and `fsrm_quota_high`.
- Print: all reads, jobs, printer pause and resume, printer set, add, port add and remove, spooler restart, `point_and_print_restrict`, queue clear, printer and driver remove and add, three alerts: built and tested as above. **Not run on a real print server.** Not built: print configuration defaults, rename, the PrintService event alerts.
- The 62 + 19 + 24 scripts pass the AST check and PSScriptAnalyzer in PowerShell 7.5 (Docker) and say `module_missing` (or a typed refusal) where the role is absent. **Not run in Windows PowerShell 5.1.** The Windows runner steps `TestScriptsOnWindows` in the three packages run the role-absent path.
- `monitoring.ModuleKind.LowestWins` added (a lower threshold is the more urgent).
- e2e: not written for these three views (vitest covers them).

## Privacy notes

- Requesters, subjects and serial numbers of certificate requests, the audit events of the CA, SMB sessions and open files, and job documents, owners and client computers are `Sensitive`: opened by `ca.view`, `shares.view` and `print.view_sensitive`, kept 15 minutes, audited as a count. Alerts name the CA and a count, never a subject.
- `certificate_revoke` takes an optional note for the audit only; the script never reads it.
- Share names, folder paths and printer names are organization data and are in the audit as parameters of a change.

## For the integrator

- Uses roles1's `rolekit`, `roles` (three lines each in `Actions()` and `AlertKinds()`) and the Roles tab registry; no change to app.go.
- Migrations: none (90261 to 90269 are unused).
- Framework: `monitoring/modulekinds.go` (`LowestWins`), `rbac.go` (two print permissions and their unions), `scripts/ci/check-coverage.sh` (three floors).
- Editing a script means updating `pins.go` (`go test -run TestPins -update`; a test fails otherwise).
