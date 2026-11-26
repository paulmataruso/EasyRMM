# le2: ADR-0055 slice 5b1 (agent trust)

## Changelog lines
- Agents can now verify, on the computer itself, the certificate chains the server serves, when the server asks with a signed trust instruction (job key, context `EASYRMM-TRUST-SIG-V1`, valid 10 minutes). An agent that pinned no job key, or sees an unsigned, forged, stale, replayed or mis-addressed instruction, refuses it and logs it.
- Agents widen their trust (system roots plus their CA file) only when a move's target chain verifies on the computer; nothing asks for that yet, so no agent's trust changes with this release. New agents report the capability `tls.trust.v1`; older agents and servers below protocol level 2 are unaffected.
- A device's page shows what its agent verified ("Certificate trust") and, for a device cut off by a certificate it cannot verify, **Reinstall through a remote session**.

## IMPLEMENTATION_STATUS rows
- 5b1 agent trust: built; Go unit tests (agentproto, agent, client, runner), PostgreSQL integration (service, migration down/up, end to end through the real server with the real agent code), vitest and an e2e spec. Unverified: Windows platform verifier (tests are in `agent/trust/verify_windows_test.go`, run by the Windows CI job, not yet run), a real agent binary against Pebble, a real Linux EasyPatch (.NET) bundle check, the e2e spec against `make e2e` (see report).

## Privacy
Chains are public certificates; nothing secret is stored or sent. The server stores, per device, what its agent said it trusts ("system", "ca-file", "system+ca-file"), its build hash and the origin it connects to.

## Decided in review
- Chain purposes are `served`, `fallback` and `target`; only target chains of the agent's own origin widen trust, and only when all pass.
- A request's ID is derived from what it asks; the agent answers a known ID from memory and carries it out once.
- An agent's origin must be a DNS name; IP origins are never asked (5b3).
- Added certificates must be authorities' (at most 4).
- The widened client verifies against the host it was made for: the connection's server name is empty for an IP address (found by a test).
- In 5b1 the edge supplies only the served chain, so no device shows as unprotected until 5b2 adds fallbacks. In `offload` mode nothing is asked.
- Reinstall is offered when a failed result and an unconnected device go together, or a move's question stands unanswered for an hour on an unconnected device ("not seen within 30 days" needs no separate rule: such a device is not connected).
- The reinstall token is one use, one day, made through the existing token route; the card reads state and sends nothing to the device.
- Migration 90491 (renumbered by the integrator): `device_tls_trust`, `device_tls_state`.
- Coverage floors added: `agent/trust` 90, `server/internal/tlstrust` 85, `server/internal/httpapi/tlstrustapi` 75.
- `devscope.Allowed(org)` gates every instruction and every stored question.

## Not done in 5b1
- The expiry alert listing unprotected devices, an ask-again button, the .NET bundle check, the Pebble end-to-end run with a real agent binary.
