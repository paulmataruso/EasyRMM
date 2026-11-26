# le1: ADR-0055 slice 5a (CertMagic, status and alerts)

## Changelog lines
- Certificates for the names in `.env` are now obtained and renewed by CertMagic with ACME Renewal Information, stored in the database (sealed) instead of `<data dir>/acme`. An upgrade imports autocert's account and valid certificates and serves the same ones; it orders nothing.
- `EASYRMM_ACME_EMAIL` is optional; `setup.sh` no longer asks for it or copies the administrator's address. New `EASYRMM_ACME_CA_FILE` and `EASYRMM_LISTEN_MESH_CERT`.
- Settings -> Certificates: state, renewal window, Check, Retry now, Order anyway; a banner and a platform notice when a certificate is missing or failing. `easyrmm-server tls check`.
- MeshCentral reads its certificate from a loopback listener of its own; a new certificate is applied three minutes after its last read (fifteen at most). The loopback rule on the main listeners is gone. MeshCentral restarts once at the upgrade (certUrl changed).

## IMPLEMENTATION_STATUS rows
- 5a: built; tested against Pebble (issuance, renewal with ARI, failure alert, Retry now, autocert upgrade). Unverified: real Let's Encrypt staging, a real MeshCentral reading the listener, the bundle test with real agents, BIND/DNS-01 (5b4).

## Privacy
Nothing is sent to Let's Encrypt but what issuance needs; no contact address unless the operator sets one. Account and certificate keys are sealed in `tls_storage` and never logged or sent to the console.

## Not done in 5a (stated)
- devscope.Allowed: the notices are platform-wide (no organization), so the guard does not apply; dev-scope guard had not landed on this branch.
- Notification sender platform rules (ADR-0053) are not built; only the console notice and banner.
- Windows/bundle jobs from the ADR's Testing section (BIND, parallel bundle job).
