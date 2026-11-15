# ADR-0010: EasyPatch integration through a service API

* Status: Accepted (2026-11-15)

## Context
EasyPatch is a separate .NET product (FSL-1.1-ALv2) with its own agent, API,
policies and database. It currently has no service credentials, blocks
framing, and uses bridge networking with Caddy on host ports 80/443.

## Options
(a) Server-to-server API with mapped identities; (b) our installer also
installs the EasyPatch agent; (c) our agent re-implements EasyPatch agent
duties; (d) shared database/backend.

## Decision
(a) + (b): EasyRMM calls EasyPatch's API with a new integration credential
and renders patching natively; our agent installs and supervises the
EasyPatch agent, **downloading it from the customer's EasyPatch server**
(never redistributing it), enrolling it with a single-use token bound to the
EasyRMM device id. EasyPatch stays the single source of truth for patch state
and patch jobs; EasyRMM never writes Windows Update policy or runs its own
patch engine. (c) and (d) are rejected (duplication; schema coupling).
Required EasyPatch changes are documented in `docs/integrations/easypatch.md`
and implemented in the EasyPatch repository before the integration ships.
