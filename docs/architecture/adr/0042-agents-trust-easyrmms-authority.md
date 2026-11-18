# ADR-0042: EasyPatch agents trust EasyRMM's own authority

* Status: Accepted (2026-11-18)
* Plan: [one product](../one-product-plan.md), phase B7.
* Refines: [ADR-0031](0031-easypatch-agent-install.md) (EasyRMM installs the
  EasyPatch agent) and [ADR-0039](0039-agents-on-easyrmms-name.md)
  (EasyPatch agents reach the engine on EasyRMM's address).

## Context
In bundled mode the EasyPatch agents reach the patching engine on EasyRMM's
own address. An install addressed by IP (`EASYRMM_TLS_MODE=internal`) serves
that address with a certificate from EasyRMM's own authority, which no
device trusts by default. EasyRMM's agent trusts it because it was given the
authority at enrollment; the EasyPatch agent was not.

Install instructions already carry a certificate authority (`CACert`) for a
connected EasyPatch server with a private certificate. The Windows MSI takes
it as `SERVERCACERT` and trusts it for that server only. The Linux agent had
no such option and trusted only the system's certificate store, which
EasyRMM does not change. In bundled mode the instruction carried no
authority at all, so neither agent could enroll on an IP-addressed install.

## Decision
* **In bundled mode with `EASYRMM_TLS_MODE=internal`, install instructions
  carry EasyRMM's own authority** (`pki.Authority.CAPEM`). Other TLS modes
  use a publicly trusted certificate, or one the proxy owns, and carry none.
* **The Linux EasyPatch agent gains `enroll --server-ca <file>`.** It reads a
  PEM or DER certificate, refuses one that is not a certificate authority,
  stores it in `agent.conf` as `ServerCaCertificate`, and trusts it for the
  connection to that server only, through the same validation as the
  Windows MSI's `SERVERCACERT`. The system store is unchanged.
* **EasyRMM's agent passes the authority as a file.** It writes it to a
  private temporary directory, passes `--server-ca`, and removes it after
  enrollment. The token still arrives on standard input.
* **Older EasyPatch agents still enroll.** An agent from before
  `--server-ca` refuses the option as a usage error (exit code 2) before it
  reads the token, so EasyRMM enrolls it again without the option. If that
  agent then cannot reach EasyPatch, the error tells the administrator to
  add the authority to the device's store or offer a newer agent package.
* **Settings shows the authority** the agents are given, as for a connected
  server.

## Consequences
* An install addressed by IP patches Windows and Linux devices without
  touching their certificate stores.
* The agent keeps the authority it was enrolled with. EasyRMM's authority
  lasts ten years and is not rotated; if it is ever replaced, agents must be
  enrolled again.
* The option is checked against the real engine: a Linux agent enrolled
  over a private authority with `--server-ca`, could not reach the engine
  without it (exit code 6), and refused a certificate that is not an
  authority (exit code 2).
