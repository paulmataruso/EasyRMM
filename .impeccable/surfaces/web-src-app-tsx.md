---
version: 1
slug: "web-src-app-tsx"
primary_target: "web/src/App.tsx"
related_targets: ["web/src"]
---

# Console (web app)

Scope: the signed-in EasyRMM console and its sign-in flows (setup, sign-in,
MFA enrollment/verification, invitation and password reset). Mode: Operate.

Audience and job: MSP technicians and administrators triaging many customer
organizations; get from "where do things stand" to the right organization or
site in seconds, act, and trust scope and audit.

Content and states: real API data only. Overview leads with the setup path
(organizations, sites, team, second factor) plus recent audit activity in
the caller's scope. Empty, loading, error, forbidden and read-only states on
every board. Later phases (devices, alerts, jobs) join as boards of the same
grammar; nothing is shown before it exists.

Constraints: strict CSP (no inline scripts or styles, no runtime web fonts),
embedded in the Go binary, keyboard operable, reduced-motion respected.

## Direction contract

THESIS: One console: a technician moving between devices, scripts and patching should not notice a seam. Calm, dense, flat operator UI; no KPI-tile theatre, no decoration the server's data does not earn.

OWN-WORLD: EasyRMM's design system (web/src/index.css is the source of truth for every token). Semantic tokens canvas/surface/raised/hover/line/fg/muted/subtle, blue accent, ok/warn/danger/info with soft fills, navy sidebar; class-based dark theme by default with a light theme toggle; system UI font, 14px base, tabular figures in tables; bordered cards with header rows, uppercase table heads, small pill badges.

STORY: A technician signs in (password, then authenticator), sees where setup stands and what changed in their scope, and reaches the organization or site they need in a couple of keystrokes.

FIRST VIEWPORT: Left navy sidebar (EasyRMM wordmark, Dashboard, Organizations, Settings; account and sign-out at the foot, name over role). Header bar with the theme toggle; its status slot stays empty until a live readout exists (alerts, jobs). Main: page header, four stat tiles (organizations, sites, device groups, users), then two columns: while setup is incomplete, Get started beside the Organizations card with Recent activity full width below; once complete, Recent activity beside Organizations. Cards keep their own height.

FORM: React 19, Tailwind 4, TanStack Query, React Router, lucide. No rolled form: the earlier roll (Departures Board, seed:27d69541b36292f7) was retired with the glass direction on 2026-11-15. Signature details that are EasyRMM's own: j/k row travel with prefetch on focus, live filters with a match readout, one-time secrets (links, recovery codes) that cannot be dismissed before they are copied.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, and DESIGN.md recording the shared system.
