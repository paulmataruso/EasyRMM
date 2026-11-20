# The patching engine

This directory holds EasyRMM's patching engine (EasyPatch's server) and the
EasyPatch agent that it patches computers with. Both are built, tested and
released with EasyRMM from this repository; the engine runs only inside an
EasyRMM deployment, on loopback, behind EasyRMM's console and roles.

* How the engine works: [docs/architecture/patching-engine.md](../docs/architecture/patching-engine.md)
* The EasyPatch agent on Windows and Linux: [docs/deployment/patching-agent.md](../docs/deployment/patching-agent.md)
* Patching from the console: [docs/operations/patching.md](../docs/operations/patching.md)
* Building, testing and CI: [docs/development/README.md](../docs/development/README.md)

## Layout

| Path | Contents |
|---|---|
| `backend/API` | The engine's HTTP API: EasyRMM's statements and the agents' signed requests |
| `backend/Worker` | Background work: schedules, maintenance windows, vulnerability feeds, reports, alerts and notifications |
| `backend/Core`, `backend/Infrastructure` | The domain (policies, jobs, compliance) and its data access and services |
| `backend/Tests` | The engine's tests, with PostgreSQL in Testcontainers |
| `agent/` | The EasyPatch agent: the Windows service and tray (Windows Update, winget), Linux (apt, dnf), the MSI and Linux packages in `Installer/`, and an experimental macOS build that is not released |
| `shared/EasyPatch.Contracts` | Types the API and the agent share |
| `deployment/server` | The engine's container image, which carries the signed agent packages |
| `scripts/` | Building and signing the agent packages |
| `tools/EasyPatch.ReleaseSigner` | Signs agent packages with the release key, and checks signatures |
| `keys/` | The release key's public half, which the agent carries |
| `branding/logo.svg` | The source of the agent's icon (`scripts/build-icons.sh`) |

## Building and testing

With the .NET SDK pinned in `global.json`, from this directory:

```bash
dotnet build EasyPatch.slnx -c Release
dotnet test backend/Tests/EasyPatch.Tests.csproj
dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj
```

## Versions

The engine and the EasyPatch agent keep their own version
(`Directory.Build.props`), raised with every EasyRMM release, since a
version is published only once; [CHANGELOG.md](CHANGELOG.md) is their history, including the releases
up to 1.10.0 made before EasyPatch became part of EasyRMM. Releasing is in
[docs/development/releasing.md](../docs/development/releasing.md).

## Licence

The same as the rest of the repository: [FSL-1.1-ALv2](../LICENSE.md), with
the details in [LICENSING.md](../LICENSING.md). Report vulnerabilities as
[SECURITY.md](../SECURITY.md) describes.
