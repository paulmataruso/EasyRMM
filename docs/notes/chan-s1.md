# chan-s1: ADR-0059 slices C0 and S1

## Changelog lines
* Added the server end of the agent's WebSocket channel (ADR-0059): a signed upgrade at `/api/agent/v1/channel`, per-device and server-wide limits, keepalives, and pushes only to connections a signed heartbeat has confirmed. It is off unless `EASYRMM_AGENT_CHANNEL=on`; no agent uses it yet.
* New settings: `EASYRMM_AGENT_CHANNEL` (default `off`) and `EASYRMM_AGENT_CONNECTIONS_MAX` (default 10000).

## Implementation status rows
* Agent channel, server endpoint and hub (C0, S1): built, integration-tested on Linux; off by default. Not built: the agent client (A1), the message kinds (M1 to M5), H1 (database registry, clone guard, stored capability check), H2, H3. Windows: unverified.

## Privacy
Nothing new is stored. The hub keeps connection state in memory only; no personal data.
