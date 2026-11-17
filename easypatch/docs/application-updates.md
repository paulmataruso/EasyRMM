# Application updates (winget)

EasyPatch can keep approved third-party applications on Windows endpoints up to date with
[winget](https://learn.microsoft.com/windows/package-manager/winget/), the Windows Package
Manager. It is **off by default**. When it is on, EasyPatch:

* checks only the applications on an **approved list** of winget package IDs, such as
  `Mozilla.Firefox`;
* upgrades an application only where it is **already installed**. It never installs an
  application that is not there;
* uses only the **winget community repository** (source `winget`), never the Microsoft Store;
* counts an upgrade as installed only when winget **lists the new version** afterwards.

Application updates appear in the console next to Windows updates, in the **Application**
category, and are installed by the same jobs: *Install all missing updates*, scheduled installs
in the maintenance window, or selected updates.

## Requirements

* **Agent 1.4.0 or newer** on Windows. Older agents ignore the setting. The endpoint page shows
  *Agent too old* when the policy is on but the agent cannot check applications. Linux endpoints
  are not affected.
* **App Installer (winget) 1.6 or newer**. It comes with Windows 11 and with Windows 10 1809 and
  later through the Microsoft Store. **Windows 10 LTSC and Windows Server 2019 and 2022 do not
  include it.** Agents 1.7.0 and later install it for all users when it is missing or too old
  (see [agent-installation.md](agent-installation.md#winget)); older agents fail the check with
  `winget_not_found` unless App Installer was installed separately. winget needs Windows 10 1809
  or Windows Server 2019 or later, so Windows Server 2016 cannot use application updates.
* The computer must be able to reach the winget community repository and the vendors' download
  sites. Windows Update settings and WSUS have no effect on application updates.

The agent runs as LocalSystem, which has no `winget` command. It uses the newest App Installer
package in `%ProgramFiles%\WindowsApps` for the computer's architecture (x64 or ARM64).

## Turning it on

1. Open a policy: global (**Settings → Global policy**), an organization, a site, a tag or an
   endpoint.
2. Under **Application updates (winget)**, set the status to **On for the approved
   applications**.
3. Approve applications by their winget package ID. To find an ID, run `winget search <name>` on
   any Windows computer and use the value in the *Id* column. The console suggests some common
   applications. You can approve at most 100.
4. Save.

The setting is inherited or overridden **as a whole**: a site or tag that sets its own list
replaces the organization's list (the lists are not merged), and setting *Off* at a lower level
switches it off there. A tag policy is a convenient way to try application updates on a pilot
group first.

Package IDs must look like `Publisher.Application` (letters, digits, `.`, `-`, `_`, `+`).
Microsoft Store IDs such as `9NBLGGH4NNS1` are not accepted.

## What the agent does

**Checking.** After each successful Windows Update scan, the agent runs this for each approved
ID:

```
winget list --id <ID> --exact --source winget --accept-source-agreements --disable-interactivity
```

* If the application is not installed, nothing is reported.
* If it is installed, its version is reported as installed. If winget shows a newer version, an
  application update titled *&lt;name&gt; &lt;version&gt;* is reported as missing.
* If winget cannot tell the installed version (it shows `Unknown` or a range such as `< 6.2`),
  the application is skipped.
* The result of the check is shown on the endpoint's **Overview** tab: winget version, last check
  and the last error, and why the agent could not install winget if it could not. A failed check raises an *ApplicationScanFailed* event, and the application
  updates already known keep their state until a check succeeds.

**Installing.** An application update is installed with:

```
winget upgrade --id <ID> --exact --version <version> --silent --accept-package-agreements
       --source winget --accept-source-agreements --disable-interactivity
```

The version is the one the agent's own check found, not a value from the server. Afterwards the
agent runs `winget list` again. The update is reported as installed only if the new version is
listed. Otherwise it fails: `not_verified` when winget exited successfully but the version did
not change, or `winget_0x8A15…` with winget's reason. Each upgrade may take up to 60 minutes.

**Approving an application accepts its package agreements** (`--accept-package-agreements`).
The policy's *Accept license agreements* setting applies to Windows updates only.

## Compliance

Updates of approved applications are **required** updates, so a missing application update
counts toward compliance like a missing Windows update. The *Other updates* rollout delay applies
to them. They have no CVE or known-exploited data. See
[compliance.md](compliance.md#required-updates).

When an application is removed from the approved list, or application updates are switched off,
the agent stops checking it and its updates are marked *not applicable* at the next scan. Until
then they are not required, and install jobs skip them with *Application not approved by
policy*.

## Restarts and running applications

* EasyPatch never restarts a computer because of an application update. When winget reports that
  a restart is needed (`0x8A150109` or `0x8A15010A`), the update is reported as failed with that
  reason (the new version is not installed yet) and the next check after a restart confirms it.
* winget's silent mode normally suppresses restarts, but **a third-party installer can still
  restart the computer by itself**. winget reports this as `0x8A15010B`. EasyPatch cannot prevent
  it; approve only applications whose installers behave well.
* Installers may close a running application, or fail with `0x8A150101` (*the application is
  running*) and succeed at a later attempt.

## Limitations

* **Per-user installations are not visible.** Applications installed only for one user (for
  example in `AppData`, as many browsers and Visual Studio Code do by default) are not seen by the
  agent, which runs as LocalSystem.
* winget recognizes applications installed by other means only when it can match them to a
  package. Applications it cannot match are treated as not installed.
* The check runs one `winget list` per approved application, so a long list makes scans slower.
* Only upgrades are offered. EasyPatch never downgrades, uninstalls or installs new applications.

## Trust model

Packages come from the winget community repository: manifests reviewed by Microsoft that point to
the vendors' installers, whose SHA-256 hash winget checks before running them. Approving an
application means trusting that repository and the vendor for that application.

* The agent passes a fixed command line with only the validated package ID and version as
  arguments, never through a shell. It never uses `--force`, `--ignore-security-hash`, custom
  installer arguments or another source. EasyPatch has no way to run other winget commands or
  arbitrary programs.
* The approved list is enforced three times: the agent checks only approved IDs, the server marks
  only approved application updates as required, and install jobs carry the approved list so the
  agent installs nothing else.
* The server rejects application updates whose ID or version is malformed or whose update GUID
  does not match the ID and version.

See also [security.md](security.md#application-updates-winget).
