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
