# ADR-0049: Operators sign the Windows agent with their own certificate

* Status: Accepted (2026-11-20). Implemented (2026-11-21).
* Refines: [ADR-0027](0027-agent-updates.md) (which build the server hands
  out and updates agents to).

## Context
`easyrmm-agent-windows-amd64.exe` and `-arm64.exe` carry no Authenticode
signature ([CODE_SIGNING.md](../../../CODE_SIGNING.md)). Windows names no
publisher for them, and endpoint protection products treat unsigned programs running as LocalSystem with suspicion;
many MSPs allow only signed programs on the computers they manage. A
public certificate for EasyRMM itself is on hold. Many MSPs already hold
a code signing certificate of their own, for their own tools, and would
rather the agent on their customers' computers name them anyway.

Four facts shape the design:

* **Code signing keys live in hardware.** Since June 2023, public
  certificate authorities issue code signing certificates only for keys
  in a hardware token or an HSM: a USB token, or a cloud service such as
  Azure Key Vault or DigiCert KeyLocker. Signing happens
  where the key is, with that vendor's tool (`signtool`, `jsign`,
  `osslsigncode` with PKCS#11). A server that signs needs every one of
  those integrations, and a copy of the key's credentials. That makes it
  a signing service for anyone who controls it.
* **An Authenticode signature does not change the program.** It sits in
  the PE file's certificate table. The Authenticode digest, which the
  signature covers, is the hash of the file without its checksum field,
  the certificate table's directory entry and the table itself, so it is
  the same before and after signing. The server can therefore tell that
  an uploaded file is exactly its own build with a signature added.
* **The server identifies a build by its SHA-256** (ADR-0027). Signing
  changes the file's SHA-256, so a signed build is another build. Agents
  move to it through the coordinated updates that already exist, a few at
  a time.
* **The EasyPatch agent's MSIs carry a release signature** over their
  SHA-256 (ADR-0041). An MSI signed by an operator no longer matches it,
  and EasyPatch agents refuse to update to it.

## Decision
* **The operator signs; EasyRMM checks and hands out.** The operator
  takes the server's Windows agent builds (from **Settings → Agent
  updates**, or from the release, whose files are attested), signs them
  with their own certificate and tools, and uploads the signed files on
  the same page (`settings.manage`). EasyRMM never holds the operator's
  key or its credentials.
* **An upload is accepted only if it is the server's build, signed.** The
  server checks that:
  * the file is a PE file for Windows with one Authenticode signature;
  * its Authenticode digest, computed by the server, equals that of the
    server's own build for one of the Windows architectures; nothing but
    the signature differs;
  * the digest that the signature covers is that digest, and the
    signature verifies with the signer's certificate;
  * the signer's certificate allows code signing.

  It does not check the certificate's chain: a certificate from an
  internal certificate authority is valid where the operator's group
  policy trusts it, and Windows decides that on each computer. The page
  shows the signer's subject, issuer, thumbprint and validity, and
  whether the signature has a timestamp. Without a timestamp the
  signature stops being valid when the certificate expires, so the page
  warns.
* **A signed build is the server's build for its architecture.** The
  install command downloads it, and coordinated updates move agents to
  it. An unsigned agent of the same version is then on another build, so
  it updates to the signed one within the rollout setting's limits. The
  agent changes nothing: it trusts the server's signed update instruction
  and the SHA-256 in it, as before. Authenticode is for Windows and the
  operator's security tools.
* **After an upgrade, the new build needs a new signature.** The release's
  build has another digest, so the old signed file no longer matches it.
  A setting chooses what the server hands out meanwhile:
  * *The release's build* (default): the new unsigned build, until a
    signed one is uploaded. Agents update twice, first to the release's
    build and then to the signed one.
  * *Only signed builds*: the newest signed build, even of an older
    version, until a signed build of the new version is uploaded. Agents
    wait on it, and so do new installs. The page and the device list say
    that Windows agents are waiting for a signed build. Older agents keep
    working with a newer server, as they must for devices that were off
    during an upgrade.
* **Stored in the database**, so that backups keep them: for each
  architecture, the signed build of the server's version and the newest
  older one. Removing a signed build hands out the release's build again.
  Uploads and removals are audited with the signer and thumbprint.

## Consequences
* An MSP can make every Windows agent it runs name the MSP as its
  publisher with the certificate and tools it already has, including
  hardware tokens and cloud HSMs, and a compromised server cannot sign
  anything with it.
* Each release needs the operator to sign two files and upload them. With
  *Only signed builds*, Windows agents stay on the older version until
  they do; with the default, unsigned agents run in between.
* The server needs a PE and PKCS #7 reader for the checks, written for
  this and tested against files signed by `osslsigncode` and `signtool`.
* **Not covered:**
  * The EasyPatch agent's MSIs. Signing them needs the release signature
    to cover the MSI without its Authenticode signature, and EasyPatch
    agents that check it that way: a later ADR.
  * MeshCentral's agent, which MeshCentral builds, signs and updates.
  * Signing by the server with a key file or a signing service.
    Rejected: it puts the key, or a way to use it, on the server.

## Implementation notes
* The checks are in `server/internal/agents/authenticode`: a PE reader
  and a PKCS #7 (SignedData) verifier for RSA and ECDSA signatures with
  SHA-256, SHA-384 or SHA-512. A signature may carry further signatures
  nested in it (`signtool /as`); only the outer one is checked and shown.
  Timestamps are noted, both RFC 3161 (`signtool /tr`) and Authenticode
  countersignatures (`signtool /t`), not checked. Tested against the
  checked-in programs signed by `osslsigncode` (with and without either
  timestamp), and on CI's Windows runner against `tiny.exe` and the
  Windows agent built there, signed by `signtool`.
* Uploads are at most 64 MiB. A new upload for the same architecture and
  version replaces the one before. The table is
  `signed_agent_builds` (migration 00026).
* *Only signed builds* cannot be turned on before a signed build is
  uploaded (`no_signed_builds`), and the last signed build cannot be
  removed while it is on (`last_signed_build`). For an architecture with
  no signed build at all, it hands out no Windows build: the install
  command for it fails until one is uploaded, and the page says so.
* With *Only signed builds*, an agent on an unsigned build updates to the
  signed build handed out even when that is of an older version. Agents
  identify builds by SHA-256 only (ADR-0027); the guide says so.
* Removing the signed build handed out hands out the release's build
  again, or, with *Only signed builds*, the newest older signed build.
* Devices waiting show the status *Waiting for a signed build* (`waiting`)
  with the release's version; the settings page counts them.
