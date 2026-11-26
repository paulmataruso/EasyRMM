# meshiso notes (ADR-0071)

Changelog:
* Removing EasyRMM's MeshAgent on Windows also deletes the
  `Uninstall\EasyRMMMeshAgent` registry key MeshAgent creates; no other
  MeshAgent's keys are touched.
* ADR-0071: EasyRMM's MeshAgent beside a client's own (audit, rules, tests).

Implementation status rows:
* MeshAgent isolation (ADR-0071): audit done; Windows registry cleanup and tests
  built, Windows-only tests not run on Windows; real-Windows checks with a stock
  agent beside ours pending; Diagnostic Agent residual awaits a decision.

Privacy: none (nothing is collected).

Added: migration 90011 (retired_devices.platform, mesh_may_remain); MeshCentral's
uninstallagent is no longer sent to Windows devices; docs/operations/removing-our-meshagent.md.
Console display of mesh_may_remain and the script: not built.
Changelog: "Removing a Windows device never asks MeshCentral to uninstall its MeshAgent, so
another MeshAgent's Diagnostic Agent is never removed."
