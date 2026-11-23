-- Recovery, slice R3 (ADR-0069, Part R): the EasyPatch agent repairs the
-- EasyRMM agent, through the patching engine's RepairCompanion job.

-- +goose Up

-- What a step's carrying agent returned besides its message: redacted log
-- lines and facts, at most 256 KiB (octets), kept 14 days after the repair
-- ended (the server's maintenance loop empties it). Agent log records
-- (slice L1) take this over once the table exists; until then the repair
-- keeps the last step's.
ALTER TABLE agent_repairs
    ADD COLUMN diagnostics text NOT NULL DEFAULT '' CHECK (octet_length(diagnostics) <= 262144);

-- +goose Down
ALTER TABLE agent_repairs DROP COLUMN diagnostics;
