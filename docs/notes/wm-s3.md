# wm-s3: agent protocol `params` (ADR-0073 slice 3)

## Changelog lines

- Jobs can carry `params`, a JSON object (at most 16 KiB) that the agent writes to the script's standard input; never the command line, environment or a file. Agent protocol level 3.
- The job signature covers the script hash and the params hash (payload version 2, its own signature context). An agent that cannot verify either hash refuses the job.
- The server sends a params job only to agents that list `job.params`, and refuses to create one for an older agent.

## Implementation-status rows

- Job params, signed script and params hashes, stdin delivery, protocol level 3: built and tested (Linux agent, real agent worker against the server). Windows PowerShell stdin path: cross-compiled only, not run on a Windows computer.

## Privacy notes

- `jobs.params` holds params without secrets; the audit holds only `paramsSha256`. Nothing logs params. Secret sealing and delivery-time placement are slice 5.

## For slice 5

- `spec.params` (server/internal/jobs) is the entry point; `create` sets the `job.params` requirement and the audit hash. Delivery-time secret overlay goes in `claim` before `SignJob`; `SignJob` canonicalises and hashes whatever `Params` it is given.
