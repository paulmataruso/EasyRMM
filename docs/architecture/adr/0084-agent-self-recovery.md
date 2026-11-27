# ADR-0084: Agent Self-Recovery

**Status:** Accepted  
**Date:** 2026-11-27

## Context

A dirty shutdown or Defender quarantine can leave the agent's binary missing
while the enrollment and recovery copy remain intact. The Windows Service
Control Manager (SCM) restarts the service, but the restart fails because
the binary it points at is gone. With only `ServiceRestart` configured, all
three failure actions fail the same way and the agent stays down.

A second failure mode: `CheckAbove` walks every folder from the agent's
directory up to the drive root (C:\). On real-world Windows machines, C:\
often has non-standard ACLs (Everyone:FullControl from an old setup, or
permissions broken by a failed Set-Acl), so the check fails and Defender
exclusions and PowerShell verification are rejected.

## Decision

### 1. SCM recovery command

The first two service failure actions use `RunCommand` instead of
`ServiceRestart`. The SCM runs the recovery copy's `repair-install`:

    "C:\ProgramData\EasyRMM\Agent\recovery\easyrmm-agent.exe" repair-install

`repair-install` copies the binary back, protects its directory, registers
the service and starts it. The third failure action remains `ServiceRestart`
as a fallback: if the recovery copy itself is damaged, a simple restart is
the only thing left to try.

### 2. CheckAbove stops at well-known system roots

`CheckAbove` stops walking after checking a well-known Windows system
directory: `%ProgramData%`, `%ProgramFiles%`, `%ProgramFiles(x86)%` or
`%SystemRoot%`. It does not walk further up to the drive root.

These directories are managed by the OS with well-known default ACLs. The
agent already protects its own directories with explicit ACLs
(`protectedDACL`). Walking above the system roots adds no practical
security: if someone can modify C:\ itself, the entire machine is
compromised.

### 3. Install directory protection

`putService` now calls `Protect` on the install directory
(`C:\Program Files\EasyRMM\Agent`) after copying the binary, ensuring the
directory and its contents are locked to SYSTEM and Administrators
regardless of the installing user or inherited ACLs.

## Consequences

- An agent whose binary is missing recovers automatically through the SCM
  recovery command, with no manual intervention.
- Defender exclusions and PowerShell verification work on machines with
  non-standard drive-root permissions.
- The recovery copy at `C:\ProgramData\EasyRMM\Agent\recovery\` is the
  critical fallback; `KeepRecovery` already maintains it on every startup.
- Existing agents pick up the new SCM recovery actions on the next service
  update (re-install or `repair-install`).
