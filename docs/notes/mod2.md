# mod2: modules read by themselves, shares, DHCP range

## Changelog lines
- Windows module tabs no longer have a "Read now" button: a tab shows its last result with its age, reads again by itself when it is older than about two minutes, and keeps it fresh while open; a skeleton of the page shows until the first result.
- A run in flight is followed every 0.7 s (was 1 to 1.5 s).
- File shares: the Permissions button opens a dialog that reads and edits the share's permissions.
- DHCP: a scope's address range can be changed (tier 3: typed scope, step-up); the network and mask cannot, which the form says.

## Implementation-status rows
- ADR-0073 section 5 amendment (automatic reads, `POST /devices/{id}/winmod-read/{action}`): built, tested (vitest, Go integration, e2e Directory and DNS tabs).
- ADR-0076 `dhcp.scope_range_set`: built; script not run on a real DHCP server.

## Privacy notes
- Automatic reads are audited like manual ones, with `automatic: true`; no new data is stored beyond the existing snapshots (sensitive snapshots keep their 15-minute retention).
