# wm-s89: UI frame and CI for the Windows modules (ADR-0073 slices 8 and 9)

## Changelog lines

- Windows devices show a "Security" tab when Defender is found and its module is on for the site; the tab reads Defender's state (`defender.status`) on request. A module that is off for the site keeps its URL and says so, with a link to the Windows modules settings for someone who may change it.
- The "Windows modules" tab on organization and site pages now sits between Patching and Install (ADR-0072 amended).
- Parameters sent to Windows scripts are plain ASCII JSON (non-ASCII characters as `\uXXXX`), so Windows PowerShell 5.1 reads names with accents or other scripts correctly.
- CI: a PowerShell syntax-tree check of every Windows module script, and a hostile-value test (quotes, `$()`, backticks, newlines, Unicode) on the Windows runner.

## Implementation-status rows

- Device `ModuleTab` frame, tab rule, "module off" page, Security tab (`defender.status`, read-only): built; vitest and e2e. Not run against a real Windows device.
- Organization and site cards for modules: not built (need slices 6 and 7).
- AST check, fixtures and pinned-helper exemption: built and run with PowerShell 7.5 and 7.4 in Docker on Linux; **not run on the Windows runner or Windows PowerShell 5.1** yet.
- `TestHostileValuesOnWindows`: run with PowerShell 7 in Docker; **not run with Windows PowerShell 5.1** (the case the ASCII encoding is for).

## Privacy notes

None: nothing new is stored or logged.

## For the integrator and later slices

- Needs the PowerShell-script files to be CRLF per `.gitattributes`; the AST check normalises line endings in the pinned hash.
- A module adds one line to `DEVICE_MODULE_TABS` and its scripts under `server/internal/winmod/<module>/`. ADR-0077's slice adds `scripts/ci/winmod-helper-pins.json` entry for `New-EasyRmmCredential`.
- `baseRoutes` in `web/src/test/fakeApi.ts` now answers `GET /devices/:id/roles` (the device page asks for it on Windows devices).
- `scripts/ci/check-powershell.ps1` now scans `server/internal/winmod` (PSScriptAnalyzer passes with PSUseDeclaredVarsMoreThanAssignments excluded there, because a script that takes no parameters still reads `$p`).
- The Windows agent puts a UTF-8 prologue (`agentproto.ParamsPrologue`) before PowerShell scripts with params, so input and output are UTF-8 (ADR-0073 amended); scripts do not escape output. Changelog: names with accents or CJK now survive in module results.
- Not verified on Windows PowerShell 5.1: `TestParamsScriptIsUTF8InAndOutOnWindows` and the hostile test run on the Windows runner; they were only run here with PowerShell 7 in Docker (hostile) and compiled for Windows (agent test).
