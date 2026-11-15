# ADR-0007: Append-only, hash-chained audit log

* Status: Accepted (2026-11-15)

## Decision
* Audit records are written only through `easyrmm_audit_append`, a
  `SECURITY DEFINER` function that serializes writers with an advisory lock
  and stores `entry_hash = SHA-256(prev_hash ‖ canonical(record))`.
* The runtime role has `SELECT` on the table and `EXECUTE` on the functions,
  nothing else. An `UPDATE` trigger rejects edits even by the owner.
* Records are written in the same transaction as the change they describe.
* `easyrmm_audit_verify` recomputes the chain; retention deletes only records
  older than the configured period (minimum 30 days).
* Tenant users see their organizations' records through row-level security.

## Consequences
Writers serialize on one lock; audit volume is per user action, not per
telemetry sample, so this is acceptable. Anchoring the chain head externally
(e.g. periodic signed checkpoints) is a planned hardening step.
