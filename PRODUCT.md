# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React + TypeScript + Vite in `web/`, with Tailwind CSS 4 (semantic tokens in
`web/src/index.css`), TanStack Query, React Router and lucide icons: the same
stack and versions as the sister product EasyPatch's frontend, so the two
consoles share one design system. No component kit. The production build is
embedded into the Go server binary and served from the same origin as the
API. Confirmed by the project owner.

## Users

Primary: technicians and administrators at managed service providers (MSPs).
They look after many customer organizations, each with sites and endpoints,
and spend their working day in the console: triaging alerts across tenants,
jumping into a device, running a script or remote session, then moving to
the next customer. They are fluent, impatient with ceremony, and often work
on a large desktop monitor with the console open for hours.

Secondary (served by the same flows, never at the expense of the primary):
internal IT teams managing a single organization's fleet.

Roles in the product (built in): super administrator (platform), organization
administrator, site administrator, technician, read-only.

## Product Purpose

EasyRMM is an open-source remote monitoring and management platform for
Windows and Linux endpoints. It gives an MSP one place to see the state of
every customer's devices, act on them (scripts, jobs, software, patches,
remote access), and prove what was done (audit log, reports).

Success means a technician can find the device or problem they need in
seconds, act on it safely, and trust that tenant boundaries and the audit
trail hold.

## Positioning

- Self-hosted and open source (AGPL-3.0-or-later): the MSP owns its data
  and deployment.
- Remote access is powered by the real MeshCentral server and agent, embedded
  in the console in its own browser origin; everything else (tenancy,
  inventory, monitoring, scripting, jobs, alerts, audit, enrollment) is
  EasyRMM's own.
- One unified endpoint install (MSI, EXE, PowerShell one-liner, DEB/RPM,
  script) installs and manages both the MeshCentral agent and the EasyRMM
  agent.
- Patch management integrates with EasyPatch, the owner's separate patching
  product, through a service API.

## Operating Context

- Deployed with Docker on a single Linux host using host networking; one
  public port (443, optionally 80). Optional NGINX in front.
- Hierarchy: organization → site → device group → device. Permissions are
  granted per organization or per site.
- Sign-in always uses a second factor (TOTP) by default; first-run setup is
  claimed with a one-time token from the server's data directory.
- Remote sessions open MeshCentral inside the console (iframe on the
  dedicated mesh host name).

## Capabilities and Constraints

Implemented (server): sign-in with mandatory TOTP enrollment, recovery codes,
session management, password reset (e-mail or administrator link), first-run
setup, organizations/sites/device groups, user invitations and role
management with escalation protection, tamper-evident audit log.

Planned by phase (see ROADMAP.md): MeshCentral remote access, unified
agent and installers, inventory, monitoring and alerts, scripts and jobs,
software deployment, reporting, EasyPatch integration.

Constraints:
- No mock data, no placeholder buttons: the UI shows only what the server
  actually provides. Features from later phases are absent, not faked.
- Terminology: "organization" (not tenant/customer/client), "site",
  "device group", "device", "technician".
- Content Security Policy is strict: same-origin scripts, styles, fonts and
  images (plus `data:` images); no inline scripts or styles, no third-party
  CDNs or web fonts loaded at runtime.

## Brand Commitments

- Name: EasyRMM.
- Visual direction set by the owner (binding, 2026-11-15): EasyRMM matches
  its sister project EasyPatch (github.com/paulmataruso/EasyPatch). Same
  semantic tokens, flat dark and light themes (dark by default, switchable),
  system font stack, navy sidebar, blue accent, the same component
  vocabulary (cards, page headers, toolbars, badges, tables, native dialogs,
  toasts). This replaces the earlier glassmorphism direction.
- Logo: the EasyPatch ring badge carrying a monitor with a pulse line, and
  the EasyPatch wordmark construction with "RMM" in the aqua-to-blue
  gradient (`web/public/logo.svg`, `wordmark.svg`, `wordmark-light.svg`).
- The frontend is designed with Impeccable.

## Evidence on Hand

No customer testimonials, logos, benchmarks or screenshots exist yet. Do not
fabricate any. The EasyRMM mark and wordmarks above are the only brand
assets; they derive from EasyPatch's.

## Product Principles

1. Speed to the right device: every screen helps a technician narrow from
   many organizations to one device quickly.
2. Safety is visible: scope (which organization/site), permission and the
   consequence of destructive actions are always clear before acting.
3. Truth over decoration: show real state from the server; empty states
   explain what to do next rather than simulating data.
4. Calm density: lots of information, low noise, for people who live in the
   console all day.

## Accessibility & Inclusion

Best effort, no formal standard committed (owner's choice): full keyboard
operation, visible focus, sufficient text contrast in both themes, and
reduced-motion support are followed as good practice.
