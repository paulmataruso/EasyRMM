# TODO

Open work after release **1.10.0** (tag `v1.10.0`, 2026-11-17). See [CHANGELOG.md](CHANGELOG.md) for what each
release contains.

## Next up

- [ ] **Endpoint list: sorting by agent version is alphabetical.** With the first two-digit minor version,
  1.10.0 sorts before 1.9.0. The `"agentversion"` case of the sort in `EndpointEndpoints.ListAsync`
  (`backend/API/Endpoints/EndpointEndpoints.cs`) orders by the `AgentVersion` string. Sort numerically,
  for example on the integer parts in SQL or on a stored sort key. Agent update decisions and the
  *outdated agent* filter already compare `System.Version` and are correct.
- [ ] **Agent API: a `null` list answers 500.** A signed agent request that sends `null` for a list, for
  example `"activeJobIds": null` on check-in, fails with `500 internal_error` (an `ArgumentNullException` in
  `JobService.LeaseForCheckInAsync`) instead of `400 validation_failed`. EasyPatch's agents always send lists, so
  only a broken or hostile agent hits it, and only for its own endpoint. Found by EasyRMM's contract tests
  (`server/internal/easypatch/contract_test.go`). Reject null lists in the agent request DTOs
  (`shared/EasyPatch.Contracts/Agent/AgentDtos.cs`) for every agent endpoint, with tests.

## Test on a real instance

These need an EasyRMM instance with real endpoints.

- [ ] **Restart all that need it** on an organization and on a site whose endpoints report a pending
  restart. Schedule it outside working hours when servers are included.

## macOS agent: before removing "experimental"

The macOS agent (since 1.9.0) is **experimental, in development and not for production use**.

- [ ] **Enroll a real Mac to a server** and run scans, installs, restarts and an agent self-update end to
  end. The `macos-smoke` CI job (GitHub's Intel and Apple silicon Macs) only installs, scans, inventories,
  reinstalls and uninstalls; it never enrolls.
- [ ] **Sign and notarize the `.pkg`** with an Apple Developer ID (needs an Apple Developer account).
  Unsigned, macOS blocks it when opened by double-click; the install script is not affected.
- [ ] **Warn signed-in users on screen before a restart.** Windows has the tray for this; the Mac agent
  shows nothing.
- [ ] **Apple silicon:** macOS updates can be installed only by a volume owner or an MDM, so the agent fails
  them with `macos_owner_required`. This probably stays a documented limitation.

## Notes for working on the project

- **Build:** .NET 10 SDK; `TreatWarningsAsErrors` is on.
  - Backend tests: `dotnet test backend/Tests/EasyPatch.Tests.csproj` (needs Docker for Testcontainers).
  - Agent tests: `dotnet test agent/EasyPatch.Agent.Tests`.
- **Release:**
  1. Bump the version in `Directory.Build.props`, `scripts/build-*.sh` and `build-agent.ps1`, the issue
     template (`.github/ISSUE_TEMPLATE/easypatch-bug_report.yml` in the repository root), the README, and the
     download and build commands in `docs/linux-agent.md` and `docs/macos-agent.md`.
  2. Add a `## [x.y.z] - date` section to the CHANGELOG. `easypatch-release.yml` (in the repository root's
     `.github/workflows/`) checks that the tag, `Directory.Build.props` and the CHANGELOG agree.
  3. Push `main`, then the tag `easypatch-vX.Y.Z`. `easypatch-release.yml` builds and tests everything,
     publishes the server image to GHCR, and creates the GitHub Release with the `.msi`, `.deb`, `.rpm` and `.pkg`
     packages, their `.sig` files and `SHA256SUMS`.
- **Release signing key:** the private key is the `EASYPATCH_RELEASE_KEY` secret of the GitHub
  `easypatch-release` environment. Signed local builds read it from `~/.easypatch/easypatch-release-key.pem`.
  Copy it between machines only over a secure channel, and never commit it.
- **Constraints:** the security and design rules are in `docs/security.md` and `docs/architecture.md`.
  Documentation must match what is implemented.
