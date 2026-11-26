# pkg1: ADR-0056 slice 1, the enrollment file and an agent that waits

Branch `ws/pkg1`. No migration (90501 to 90509 unused): slice 1 changes the agent only. Slice 2 (the installer recorded, new devices on the server's build) needs a migration, the heartbeat field and the console, and so is not small or independent; it is not taken.

## Changelog lines

- Added: `easyrmm-agent install --package deb|rpm|msi`, the command a package's script runs. It installs the agent and enrolls it from `install.conf` (`/etc/easyrmm-agent/install.conf`, or `%ProgramFiles%\EasyRMM\Package\Enrollment\install.conf`; on Linux also `EASYRMM_SERVER`, `EASYRMM_TOKEN` and `EASYRMM_CA_FILE`); with no input it installs and waits for the file every 30 seconds. Where an agent is installed it records the package and changes nothing else.
- Added: the enrollment file is read only when an administrator made it and only administrators can read it (checked on the open file); anything else is left unread and `status` says why, and to revoke the token for a readable file. It is deleted once used.
- Added: `easyrmm-agent capabilities`, and a package's copy of the agent hands over to the installed agent that lists `package`.
- Added: `uninstall --package KIND [--rollback]`; `uninstall` by hand names the package manager's command while the package manager lists the package.
- Changed: the agent's unit waits for `time-sync.target`.
- Changed: a link at the agent's place that points at the package's copy is replaced with the agent's own file at install.

## Implementation-status rows

- ADR-0056 slice 1 (enrollment file, waiting, `install --package`, hand-over, `capabilities`, `uninstall --package`): built; unit tests on Linux (as root and as an unprivileged user) pass; Windows code (`host.OpenPrivate`, MSI product query, hand-over by child process) compiles, vets and lints for Windows, and its tests are in the new CI step "Enrollment file checks" of the Windows job: **not run**.
- Slices 2 to 7: not built. The bundle test's waiting scenario: not added.

## Privacy notes

None. The enrollment file and the package record hold a server address, a token (the file only, until used) and package names; nothing new is sent to the server.

## Decided in review

See the ADR's "Amended 2026-11-26" section. The MSI's upgrade code is `{DA28A5EF-C528-4A43-9375-59DF190A02E2}`.

## Organization scope

Nothing here is an automatic server-side behaviour; `devscope.Allowed` does not apply to the agent's own install. Packages do not exist yet.

## Checks the brief names that do not apply

Slice 1 downloads and verifies no package, so there is no signature, hash, size, downgrade or replay check yet; those arrive with the packages (slices 3 to 7). The refusals of this slice are tested: a file others could read (modes 0644, 0640), another owner, a symbolic link, a second hard link, a folder others may write, `/etc` others may write, a link for a folder, a directory, a file too large, an unknown or duplicated setting, a file not yet settled, and a refused token not asked again until the file changes.
