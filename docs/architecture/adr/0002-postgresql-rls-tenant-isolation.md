# ADR-0002: PostgreSQL with row-level security and split database roles

* Status: Accepted (2026-11-15)

## Context
The platform serves many unrelated MSP customers. A missed `WHERE
organization_id = …` is the most common way multi-tenant products leak data
(IDOR, broken access control).

## Decision
* PostgreSQL 18 is the only data store for EasyRMM (MeshCentral uses its own
  database on the same server).
* Every tenant-scoped table carries `organization_id` (and `site_id` where
  relevant), with composite foreign keys so the pair is always consistent.
* **Row-level security** with `FORCE ROW LEVEL SECURITY` on tenant tables.
  Policies read transaction-local settings written by
  `database.DB.InTx/ReadTx(scope)`; empty settings mean no rows.
* Two roles: `easyrmm_owner` owns the schema and runs migrations;
  `easyrmm_app` is the runtime login with DML only. It cannot alter tables,
  disable RLS, or write the audit log except through a definer function.
* Migrations are embedded SQL files applied by goose under an advisory lock
  at start-up.

## Consequences
* Every request runs in an explicit transaction; this is a deliberate
  constraint and costs one `set_config` round trip.
* Background jobs use the `System` scope explicitly, which is easy to grep
  for in review.
* Tests run against a real PostgreSQL with the same roles (`server/internal/testdb`).
