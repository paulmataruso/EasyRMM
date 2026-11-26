# The keystore

The keystore keeps the key that protects BitLocker and LUKS recovery keys. It
is a separate container with no network at all, reached only through a Unix
socket, so the EasyRMM server, its database and its backups never hold the
key. The design and its limits are in
[ADR-0081](../architecture/adr/0081-the-keystore.md).

This is the first slice. The keystore and BitLocker escrow are built; reading
a recovery key back is not (a read needs its own permission, step-up and a
reason, and comes with the next slice), nor is LUKS, rotation or restore
tooling. **Nothing here has run against a real BitLocker volume yet.**

## What it does today

* Windows agents with BitLocker read their recovery passwords themselves,
  seal each to your organization's escrow public key and upload the sealed
  record. The server stores it and has the keystore open it to check it
  matches; the server never sees the password.
* The device page shows, for each volume, whether its recovery key is
  *missing*, *pending*, *verified*, *stale* or in *conflict*.
* Escrow is off for an organization until the keystore is initialised and its
  recovery verified, and off for organizations outside the
  [dev scope](dev-scope.md) while it is set.

## Setting it up

`setup.sh` creates the keystore's state directory (`EASYRMM_KEYSTORE_DIR`,
`/var/lib/easyrmm-keystore` by default), kept apart from the data root and the
deployment directory on purpose, and finds a host TPM if there is one. After
`docker compose up -d`:

```bash
./scripts/easyrmm-keystore init
```

* **With a TPM 2.0** (`/dev/tpmrm0`), the key is sealed to it under a policy
  on Secure Boot's state (PCR 7). The keystore opens by itself at every start.
  A firmware update or a Secure Boot key change makes the TPM refuse; the
  console then says *TPM policy changed* and the recovery bundle is the way
  back. A virtual machine's TPM belongs to whoever controls the hypervisor.
* **Without one**, `init` asks for a passphrase of at least 16 characters.
  After every start (including every upgrade) the keystore is **sealed**
  until someone runs `./scripts/easyrmm-keystore unseal` at the host. The
  console cannot unseal it: that command is reachable only inside the keystore
  container. While it is sealed everything else works, and agents still
  upload (the records wait as *pending*).
* **`EASYRMM_KEYSTORE_MODE=file`** keeps the key in a file in the state
  directory, for a host with neither a TPM nor anyone at restarts. It is off
  unless you set it, and the console shows a standing warning: a copy of the
  host's disk opens it.

`init` shows a **recovery code** once, writes the recovery bundle
`recovery/kek-v1.bundle` in the state directory and asks you to type the code
again; only then does the keystore wrap anything. `./scripts/easyrmm-keystore
status` says how it is, and `verify-recovery --bundle FILE` repeats the proof.

## The three things to keep apart

Keep these in three different places:

1. **The database dump** (and the rest of the [backup](backup-restore.md)):
   it holds wrapped keys and sealed records, and opens nothing by itself.
2. **The recovery bundle** (`recovery/kek-v*.bundle`): copy it to offline
   storage when it is made. It opens nothing without the code.
3. **The recovery code**: a password manager or a safe, never with the bundle.

Together, bundle and code open everything. If the host and its TPM are lost
and the bundle or the code is also lost, the escrowed keys are gone. The
state directory is not in the updater's backup or the backup guide's commands
on purpose. A restore command for a new host is not built yet; until it is, a
keystore cannot be moved to another machine.

## What it does not protect against

Root on the keystore's host can ask the TPM to unseal, or read the keystore's
memory. The design keeps the recovery keys of **offline, stolen or dead
devices** safe from database dumps, backups and lower roles. Anyone who may
run scripts or open a terminal on an *online* device can reach its BitLocker
recovery key through the device itself; the keystore's permission does not
change that.
