# ADR-0013: The console shares EasyPatch's design system

* Status: Accepted (2026-11-15)
* Supersedes: the styling part of [ADR-0012](0012-frontend-stack-and-impeccable.md)
  ("plain CSS with design tokens, no UI kit"). The rest of ADR-0012 stands.

## Context
EasyRMM has a sister product, EasyPatch, from the same owner, and the two
will be sold and used side by side (patching is integrated through EasyPatch's
service API, ADR-0010). The owner directed that EasyRMM's theme match
EasyPatch. A first console had been built in a separate visual direction
(dark glassmorphism, condensed display type) with hand-written CSS.

A technician who moves between the two consoles should not notice a change of
product family, and one design system is cheaper to maintain than two.

## Options
* Keep a distinct EasyRMM look and align only colours: two systems to keep in
  step, and the products still feel unrelated.
* Re-create EasyPatch's look in EasyRMM's own CSS: duplicates the work and
  drifts on every EasyPatch change.
* **Adopt EasyPatch's frontend system as-is**: the same stack, versions,
  tokens and component vocabulary.

## Decision
* Same stack and versions as EasyPatch's `frontend/`: React 19, TypeScript,
  Vite, Tailwind CSS 4 (via `@tailwindcss/vite`), TanStack Query, React
  Router, lucide-react.
* `web/src/index.css` mirrors EasyPatch's `frontend/src/index.css`: the
  semantic tokens (canvas, surface, raised, line, fg, muted, accent, ok, warn,
  danger, info, sidebar) for a light and a class-based dark theme, the system
  font stack, and the shared `.input` and `.table-base` component classes.
  EasyRMM-only additions are marked in that file (keyboard hints, focused-row
  highlight, one input height for toolbars).
* Components follow EasyPatch's vocabulary: Button variants, Card, PageHeader,
  Toolbar, Badge, Alert, Field, native `<dialog>` dialogs, toasts, a navy
  sidebar with header bar and theme toggle. Dark is the default theme.
* The EasyRMM mark and wordmark reuse EasyPatch's badge and wordmark
  construction with RMM-specific content (a monitor with a pulse line).
* Design changes that belong to both products are made in EasyPatch first and
  copied here, so the two stay in step.

## Consequences
* The console and EasyPatch read as one family; patching screens added in
  Phase 8 need no visual bridging.
* Tailwind brings native build tools (Oxide, Rolldown). They ship as prebuilt
  platform packages, so `npm ci --ignore-scripts` still works, including in
  the Alpine (musl) image build; CI checks both.
* The Content-Security-Policy is unaffected: Tailwind emits one static
  stylesheet, and no fonts or scripts load from third parties.
* Licensing: EasyPatch was published under FSL-1.1-ALv2, and EasyRMM under
  AGPL-3.0-or-later (ADR-0011). The shared stylesheet values and the logo
  construction come from EasyPatch, so the licensor had to license those
  portions to EasyRMM. *Resolved 2026-11-18:* both are under FSL-1.1-ALv2
  with one licensor ([ADR-0037](0037-one-licence.md)), so no separate grant
  is needed.
