# inst-fix notes

## Changelog lines

* Fixed: running `install.sh` again over an enrolled Linux machine now
  restarts the agent service when the installed program changed, and prints the
  version that runs; the same build restarts nothing.
* Added: the device's Logs tab shows MeshAgent's side (source `meshagent`):
  service state changes, restarts and errors seen by the agent, MeshAgent's
  build from `meshagent -info`, and MeshCentral's view of its connection
  (connected, disconnected).

## Implementation status rows

* Linux reinstall restarts the service on a new build: implemented; tested
  with stub system tools (`install_sh_restart_test.go`); not run on a real
  machine. Cause: the installer wrote the file to its final place, so the
  agent's own "changed" check (source equals destination) never fired.
  Windows runs the downloaded program from a temporary folder, so it did.
  systemd only (the installer refuses other init systems); no macOS agent.
* MeshAgent records in Logs: implemented; unit tests plus an integration test
  of the connection records; not seen on a real device.

## Notes

* MeshAgent has no usable log of its connection or restarts (its
  `meshagent.log` is its diagnostics log, still tailed as before), so the
  agent collects what it can observe: state, process exit, errors and `-info`.
  MeshAgent's version comes from `-info` output (kept as text, not parsed).
* The agent-side observation is passive and local. The server-written
  connection records check `devscope.Allowed(org)`. The observation itself is
  not gated by the dev scope (no server-driven behaviour); say if it should be.

## Privacy

* `meshagent -info` output and error text go through the existing redaction
  before leaving the device and again on the server. Nothing else leaves.
