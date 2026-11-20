## What and why

<!-- What does this change do, and why is it needed? Link issues. -->

## How it was tested

<!-- Unit, integration, e2e, manual steps. Paste relevant output. -->

## Checklist

- [ ] Tests added or updated for the change (backend, frontend and permissions as applicable)
- [ ] Authorization is enforced server-side for every new endpoint, with a test for denied access
- [ ] Tenant isolation considered (row-level security covers any new tenant table)
- [ ] Security-relevant actions are written to the audit log
- [ ] No secrets, tokens, certificates or personal data committed
- [ ] UI changes reviewed with the Impeccable workflow; detector passes
- [ ] Docs, `IMPLEMENTATION_STATUS.md` and `CHANGELOG.md` updated
- [ ] I agree to the [contributor terms](https://github.com/paulmataruso/EasyRMM/blob/main/CONTRIBUTING.md#licence-and-contributor-terms), including the licence grant to DHI Technical Services LLC

## Changes under `easypatch/`

<!-- Only for pull requests that change files under easypatch/; delete this section otherwise. -->

- [ ] Builds pass with warnings as errors, and the tests pass.
- [ ] No remote command execution, no unrequested restarts, no unverified "installed" results, no secrets in logs (see [CONTRIBUTING.md](https://github.com/paulmataruso/EasyRMM/blob/main/easypatch/CONTRIBUTING.md#rules-for-agent-and-job-changes)).

