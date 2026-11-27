
### Amended 2026-11-27 (decided in review), the job key ring and its tripwires

ADR-0057 slice 1 adds tables (migrations `90531` and `90532`, renumbered by the
integrator). The disposition test lists the four that hold a device's id:

* `device_unknown_keys` (a key a device reports that the server never held),
  `device_instruction_log` (the sequence of the device's instruction log the
  server recorded) and `device_instruction_flags` (an entry that matched
  nothing the server issued) are what the computer's agent trusts and did, so a
  move leaves the rows alone: they **follow the device**, like
  `device_tls_trust`. None holds an organization or a site.
* `issued_instructions` holds what the server signed for a device: its kind, its
  ID, the device's id and the key's generation, and no foreign key, so that
  removing or deleting a device keeps the rows for their 90 days. It holds no
  organization or site, so a move changes nothing in it: it **follows the
  device** too. The audit records of the instructions it names stay with the
  organization that issued them, as the rest of the audit log does.

`job_keys` (the ring of job keys), `server_instances` (the servers sharing the
database) and `server_restores` (the restores the server knows of) belong to the
deployment. They hold no device, organization or site id (`server_restores`
lists device ids in an array, only to name the devices whose claims raised a
possible restore), so the disposition test does not list them, and a move leaves
them alone. The new columns on `devices` (the last report of the keys the device
trusts, the cut-over sent, the authorities in its `ca.pem`) move with the
device's row; those on `retired_devices` stay, as that table does.
