# Contributing to EasyPatch

Thank you for your interest in EasyPatch. Bug reports, ideas and pull requests are welcome.

EasyPatch is EasyRMM's patch management and part of EasyRMM. It lives in `easypatch/` of the
[EasyRMM repository](https://github.com/paulmataruso/EasyRMM), where its issues and pull
requests go.

## License and contributor terms

EasyRMM's [CONTRIBUTING.md](../CONTRIBUTING.md) applies to `easypatch/` too: the licence
(FSL-1.1-ALv2, [LICENSE.md](../LICENSE.md), DHI Technical Services LLC) and the contributor
terms. This file adds the rules for EasyPatch's code.

## Reporting bugs and asking for features

* **Security problems:** do not open an issue. Follow [SECURITY.md](SECURITY.md).
* **Bugs:** use the *EasyPatch bug report* issue template. Include the server and agent versions,
  the operating system of the endpoint and the relevant log lines (remove host names, tokens and
  anything else you do not want to publish).
* **Features:** use the *EasyPatch feature request* template and describe the problem first.

## Development setup

Requirements: the .NET SDK pinned in `global.json` and Docker (the integration tests start
PostgreSQL with Testcontainers). Run these from `easypatch/`:

```bash
dotnet build EasyPatch.slnx -c Release
dotnet test backend/Tests/EasyPatch.Tests.csproj
dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj
```

A local server for trying changes is an EasyRMM install from a clone: its Compose file builds
the engine from `easypatch/` (see [Patching engine](../docs/deployment/docker.md#patching-engine)).

## Pull requests

* Keep a pull request to one change, and explain why it is needed.
* Builds must pass with warnings as errors, and the tests must pass. Add tests for new behavior.
* The repository's CI (`ci.yml`) runs EasyPatch's server and agent checks when a change touches
  them, and the *EasyPatch contract* check, which runs EasyRMM's connector against EasyPatch's
  server, when the server changes. See
  [Continuous integration](../docs/development/monorepo.md#continuous-integration).
* Update the documentation in the repository's `docs/` in the same pull request. Documentation must describe what
  the code actually does.
* Pin new dependencies to exact versions, and prefer MIT, BSD or Apache-2.0 licensed ones.
  Dependencies under copyleft licenses (GPL, AGPL, LGPL) cannot be accepted.

### Rules for agent and job changes

EasyPatch manages other people's computers. Changes must keep these properties:

* No remote shell and no arbitrary command execution through jobs, policies or any other
  server-controlled input.
* No restart without an explicit administrator action.
* No change to Group Policy, WSUS or Windows Update settings unless an administrator configured
  it, and original values restored when it is removed.
* An update counts as installed only when a scan confirms it. Never report success that was not
  verified.
* No shared secrets in the agent, no plaintext reusable credentials, and no tokens or credentials
  in logs.
* Jobs must survive disconnects and restarts.
* Agent packages are installed only after their release signature has been verified.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
