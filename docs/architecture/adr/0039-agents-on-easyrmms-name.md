# ADR-0039: EasyPatch agents on EasyRMM's name

* Status: Accepted (2026-11-18)
* Plan: [one product](../one-product-plan.md), phase B4.
* Refines: [ADR-0035](0035-cohosting-easypatch.md) (EasyPatch on the same
  server) and [ADR-0038](0038-statements-to-the-patching-engine.md) for the
  engine inside EasyRMM's deployment.

## Context
With `EASYRMM_PATCHING=bundled`, the patching engine listens on loopback
only. Its agents still need to reach it from every managed device, and the
deployment has one public name, EasyRMM's: there is no second name or
certificate for EasyPatch, as co-hosting had.

What the engine's agents do, read from its code:
* they **sign each request** (ECDSA P-256) over the method, the exact request
  target, a timestamp, a nonce and the body's hash; no client certificate is
  involved;
* they fetch agent packages and winget files from paths relative to the
  server address they were installed with;
* the engine reads the client address from `X-Forwarded-For` when the peer is
  on loopback, using the last entry only, for per-address rate limits and for
  the source networks a deployment code may be used from;
* its largest request is 16 MiB; nothing is long-lived (no WebSocket, server-
  sent events or long polling).

Everything forwarded is answered on EasyRMM's own origin, where EasyRMM's
session cookie lives.

## Decision
EasyRMM's edge forwards **exactly three path prefixes** to the engine, at
`EASYRMM_PATCHING_URL`, in bundled mode only:

| Prefix | What |
|---|---|
| `/api/v1/agents/` | the agents' API |
| `/downloads/agent/` | agent packages |
| `/downloads/winget/` | winget files the agents install from |

* **First.** They are dispatched before the session, CSRF and console
  layers, which an agent carries nothing for, and after the address and
  request-id layers. EasyRMM's own routes have nothing under them.
* **As sent.** The method, the path and query, and the body pass through
  byte for byte; answers are not decompressed. A path that could mean another
  one to the engine (a dot or empty segment, a backslash, or an encoded
  slash, backslash, dot or NUL) is refused with 400 and never sent, so the
  prefixes cannot reach the rest of the engine's API.
* **Who asked.** `X-Forwarded-For` is replaced by the one address EasyRMM
  resolved: the peer, or behind EasyRMM's trusted TLS proxy, what that proxy
  reported. `X-Forwarded-Proto` and `X-Forwarded-Host` come from the origin
  EasyRMM matched, `Forwarded` is removed.
* **Nothing of EasyRMM's goes in.** `X-EasyRMM-Assertion` is removed, so
  only the connector, on loopback, makes statements; cookies are removed.
* **Nothing of the engine's acts on EasyRMM's origin.** `Set-Cookie` and
  `Clear-Site-Data` are dropped, and every answer is sent with
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none';
  sandbox` and `nosniff`, so no answer can run script beside the console.
* **20 MB** at most per request, declared or streamed (413); the engine's own
  limit is lower.
* **The engine down** is a 502 with `Retry-After: 30`; agents retry.

**Not forwarded:** `/downloads/install/`, the engine's install scripts for
deployment codes, and everything else of the engine (its console API, its
health). EasyRMM installs the EasyPatch agent itself (ADR-0031), with an
enrollment token, the engine's public address (EasyRMM's) and packages from
`/downloads/agent/`.

## Consequences
* An EasyPatch agent enrolls, checks in and downloads through EasyRMM's
  name, with the certificate EasyRMM serves. On an install whose name has a
  publicly trusted certificate that is all it needs; with EasyRMM's own
  authority, the agent needs that authority (phase B7).
* EasyPatch's own install one-liners and deployment codes do not work on
  EasyRMM's name. EasyRMM's console does not offer them.
* The edge carries the agents' traffic: a polling agent sends a request a
  minute (every 15 seconds during a job), and packages stream through it.
* A test in the contract suite sends a simulated agent, signing as
  EasyPatch's agents do, through the forwarder to a real engine: it enrolls,
  checks in, and the engine records the address EasyRMM resolved.
