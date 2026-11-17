# Security policy

EasyPatch installs software on the computers it manages, so security reports are taken seriously
and handled before anything else.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub:

1. Open the [Security tab](https://github.com/paulmataruso/EasyPatch/security) of this repository.
2. Choose **Report a vulnerability** and describe the problem, the affected version and, if you
   can, the steps to reproduce it.

You will get an acknowledgement within 7 days. Please give us a reasonable time to release a fix
before disclosing the issue publicly; we will agree on a date with you and credit you in the
advisory unless you prefer otherwise.

## Supported versions

Security fixes are released for the newest minor version only. Upgrade the server and the agents
to the newest release (agents update themselves when the *Agent updates* policy is *Automatic*).

| Version | Supported |
|---|---|
| 1.4.x | Yes |
| older | No |

## Scope

In scope: the server (API, worker, web console), the Windows and Linux agents and their
installers, the install scripts, the release signing and the Docker deployment in this repository.

Examples of what we especially want to hear about:

* a way for the server, or anyone who controls it, to make an agent run a command or install
  anything other than updates, a signed agent package or an approved application;
* bypasses of authentication, MFA, CSRF protection, organization access restrictions or roles;
* ways to read or forge agent credentials or enrollment tokens;
* secrets written to logs, images or the database in plain text.

The security design, threat model and known limitations are documented in
[docs/security.md](docs/security.md). Problems already listed under *Known limitations* there
are not new vulnerabilities, but reports that show they are worse than described are welcome.

## Verifying releases

Each release lists the SHA-256 of every file in `SHA256SUMS`. Agent packages carry a `.sig`
release signature made with the key in
[`keys/easypatch-release-key.pub.pem`](keys/easypatch-release-key.pub.pem); agents verify it
themselves before installing an update. See
[docs/security.md](docs/security.md#agent-release-signing).
