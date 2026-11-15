# ADR-0009: Agent protocol — device keys, WebSocket with HTTPS polling fallback

* Status: Accepted (2026-11-15)

## Decision
* At enrolment the agent generates an **Ed25519** key pair; the private key
  never leaves the device (Windows: DPAPI LocalMachine + SYSTEM-only ACL;
  Linux: root-only 0600). The deployment token is exchanged once for a device
  identity bound to the public key.
* Primary channel: WebSocket (`/api/agent/v1/connect`) authenticated by a
  signed challenge. Fallback: HTTPS polling where each request is signed over
  method, path, timestamp, nonce and body hash (replay window ±5 min, nonces
  single-use).
* Jobs are durable rows; delivery is at-least-once with idempotent job ids;
  results are accepted once.
* Server-to-agent job payloads are signed with the server's job-signing key;
  agent releases are signed with an offline release key embedded in the agent.
* Exponential backoff with full jitter, retry caps, and automatic recovery.
* Credential rotation and revocation are server-driven.

## Consequences
A compromised endpoint can only impersonate itself. A TLS-intercepting
middlebox cannot inject jobs.
