# chan-a1: ADR-0059 slice A1 (the agent's channel client)

## Changelog lines
* The agent can now hold the WebSocket channel to the server (ADR-0059): it connects after a heartbeat answer lists `channel`, verifies every frame, and checks in at once on a wake. Heartbeats continue unchanged when the channel is off or down. `EASYRMM_AGENT_CHANNEL=off` in the agent's environment turns it off. The server's own switch is still off by default.

## Implementation status rows
* Agent channel, agent client (A1): built; unit and end-to-end tested on Linux against the real server hub (forged and replayed frames refused, wake leads to an immediate heartbeat, heartbeats continue with the channel down). Windows: builds and vets, not run. Not built: message kinds M1 to M5 (the agent only acts on `wake`), reporting `replayed` in the heartbeat.

## Privacy
Nothing new is stored or sent beyond the capability list and the connection id the contract already defines.

## For the integrator
* Dev scope: the agent side adds no automatic behaviour of its own; the server decides whether `features` lists `channel` (`devscope.Allowed` is in S1).
* `agent/runner/runner.go` gained a `Channel` interface, `Every` and `MinWake` fields, and three small blocks (capability/report in the request, `Answered` after the answer, a wake case in `Run`).
