# TODO

Open work after release **1.10.0** (tag `v1.10.0`, 2026-11-17). See [CHANGELOG.md](CHANGELOG.md) for what each
release contains.

## Next up

- [ ] **Endpoint list: sorting by agent version is alphabetical.** With the first two-digit minor version,
  1.10.0 sorts before 1.9.0. The `"agentversion"` case of the sort in `EndpointEndpoints.ListAsync`
  (`backend/API/Endpoints/EndpointEndpoints.cs`) orders by the `AgentVersion` string. Sort numerically,
  for example on the integer parts in SQL or on a stored sort key. Agent update decisions and the
  *outdated agent* filter already compare `System.Version` and are correct.
- [ ] **SSO: organization access for accounts created on first sign-in.** An account that single sign-on
  creates has no organization restriction, because an empty list means *all organizations*. For MSPs, add a
  per-provider setting for the organizations such accounts get (all, or chosen ones), applied when the
  account is created. Show it in *Settings → Single sign-on* and add tests. Update
  `docs/single-sign-on.md` and `docs/security.md`.

## Test on a real instance

These need the console at a DNS name with a certificate browsers trust. Passkeys do not work at an IP
address or behind a certificate warning, and Google refuses an IP address as a redirect URI. The DNS
records are in [docs/installation.md](docs/installation.md#dns-records).

- [ ] **Passkeys and security keys:**
  - Add one under *My account → Passkeys and security keys*.
  - Sign out, then use *Sign in with a passkey*.
  - Use a security key as the second step after the password.
  - Check the offer to create a passkey after sign-in, and *Not now* (remembered for 30 days).
- [ ] **Single sign-on:**
  - Add a provider (Entra ID, Google or Keycloak) under *Settings → Single sign-on*.
  - Register `https://<EASYPATCH_DOMAIN>/api/v1/auth/sso/callback` at the provider.
  - Sign in and check linking by verified email. Entra ID needs *Trust the provider's email claim*, which
    is safe only for a single-tenant app.
  - Check that EasyPatch MFA still applies unless *The provider enforces MFA* is set.
- [ ] **Restart all that need it** on an organization and on a site whose endpoints report a pending
  restart. Schedule it outside working hours when servers are included.

## Optional features (not built)

- [ ] SSO-only mode: no password sign-in for users who use single sign-on.
- [ ] Map identity provider groups to EasyPatch roles and organizations.
- [ ] Sign out at the provider (RP-initiated logout).
- [ ] `private_key_jwt` client authentication, and multi-tenant Entra ID issuers.

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
  - Console, from `frontend/`:
    `docker run --rm --network none -v "$PWD:/app" -w /app node:24.22.2-alpine3.24 sh -c "npx --no-install tsc -b --noEmit && npx --no-install vitest run"`.
    On a new machine, install the dependencies in the same image first (`npm ci`, with network). The
    lockfile pins them, and the native bindings must be the musl ones.
- **Release:**
  1. Bump the version in `Directory.Build.props`, the image defaults in `docker-compose.yml`, `.env.example`,
     `scripts/build-*.sh` and `build-agent.ps1`, the issue template, the README, and the download and build
     commands in `docs/installation.md`, `docs/linux-agent.md` and `docs/macos-agent.md`.
  2. Add a `## [x.y.z] - date` section to the CHANGELOG. `release.yml` checks that the tag,
     `Directory.Build.props` and the CHANGELOG agree.
  3. Push `main`, then the tag `vX.Y.Z`. `release.yml` builds and tests everything, publishes the images to
     GHCR, and creates the GitHub Release with the `.msi`, `.deb`, `.rpm` and `.pkg` packages, their `.sig`
     files and `SHA256SUMS`.
- **Release signing key:** the private key is the `EASYPATCH_RELEASE_KEY` secret of the GitHub `release`
  environment. Signed local builds read it from `~/.easypatch/easypatch-release-key.pem`. Copy it between
  machines only over a secure channel, and never commit it.
- **Constraints:** the security and design rules are in `docs/security.md` and `docs/architecture.md`.
  Documentation must match what is implemented.
