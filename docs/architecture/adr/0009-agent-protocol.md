# ADR-0009: Agent protocol — device keys, WebSocket with HTTPS polling fallback

* Status: Accepted (2026-11-15); amended 2026-11-21 ("Evolving the protocol")
* Refined by [ADR-0058](0058-signed-settings-that-reach-the-agent.md) (slice 2): for
  settings documents the envelope and the set of keys stay as strict as any signed
  instruction, and what is inside a key's value is judged per key.

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
  agent releases are signed with an offline release key embedded in the agent
  (refined by ADR-0027: update instructions are signed with the job key and
  name the build's SHA-256; a release key is deferred).
* Exponential backoff with full jitter, retry caps, and automatic recovery.
* Credential rotation and revocation are server-driven.

## Evolving the protocol (amended 2026-11-21)

An agent can be newer than its server: the host updater (ADR-0052) rolls a
server back while agents that already updated keep their build. Until this
amendment the server refused any request field it did not know, so the first
field a later release added would have cut those agents off. From protocol
level 2 these rules hold for every feature that changes the protocol:

* **The server ignores request fields it does not know.** Each body is
  decoded into a fixed type and, but for enrollment, signed by an enrolled
  device, so refusing extra fields protected nothing. Malformed JSON, a value
  of the wrong type and more than one JSON value are still refused.
* **The server states its level** in every heartbeat answer (`protocol`,
  `agentproto.Protocol`). A server whose answer has none is level 1: version
  1.0.0-rc.4 and every build before this amendment. They refuse unknown
  fields with 400 `bad_request`.
* **An agent sends a request field added after level 2 only while its last
  heartbeat answer came from a server of level 2 or higher.** Until its first
  heartbeat answer in a process it sends only level-1 fields. One rule covers
  every later field: no feature needs its own fallback, and no 400 is ever
  read as "this field is not supported", which would also match a refusal for
  another reason.
* **A new field is safe to ignore.** The agent never relies on a server
  having acted on it. Where the agent must behave differently because the
  server has a feature (a WebSocket server that no longer holds long polls,
  for example), the server lists the feature in its answer and the agent
  changes only when it is listed.
* **The enrollment request gains no fields.** The agent cannot know the
  server's level before its first heartbeat; anything new goes in that
  heartbeat.
* **An endpoint newer than the server** answers 404 `not_found`; the agent
  treats it as "not supported here" and goes on.
* **Signed instructions stay strict on the agent** (jobs, updates, EasyPatch
  installs, uninstalls): their payloads are refused with unknown fields. The
  server sends a new instruction, or a new field in one, only to a build that
  reported understanding it.
* **Answers stay lenient on the agent**: an older agent ignores answer fields
  it does not know, as it always has.

## Consequences
A compromised endpoint can only impersonate itself. A TLS-intercepting
middlebox cannot inject jobs. A server rolled back to a release with level 2
or higher keeps every updated agent working; one rolled back to level 1
(1.0.0-rc.4 or earlier) does too, because agents send nothing newer to it.
