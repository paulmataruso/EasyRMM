-- Software deployment (ADR-0028): installing, updating and removing
-- packages through a device's package manager, as jobs that run one of
-- EasyRMM's own scripts with the package as an argument.

-- +goose Up

-- kind: a library script someone chose, or a software action. software
-- holds the action ({"action","manager","package","version"}) for people
-- and filters to read; the job's body and arguments are what runs.
ALTER TABLE jobs
    ADD COLUMN kind text NOT NULL DEFAULT 'script' CHECK (kind IN ('script', 'software')),
    ADD COLUMN software jsonb,
    ADD CONSTRAINT jobs_software_kind CHECK ((kind = 'software') = (software IS NOT NULL)),
    ADD CONSTRAINT jobs_software_object CHECK (software IS NULL OR jsonb_typeof(software) = 'object');

CREATE INDEX jobs_kind_created ON jobs (kind, created_at DESC);

-- +goose Down
DROP INDEX jobs_kind_created;
DELETE FROM jobs WHERE kind = 'software';
ALTER TABLE jobs
    DROP CONSTRAINT jobs_software_object,
    DROP CONSTRAINT jobs_software_kind,
    DROP COLUMN software,
    DROP COLUMN kind;
