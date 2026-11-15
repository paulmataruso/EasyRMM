# ADR-0012: React/TypeScript frontend designed with Impeccable

* Status: Accepted (2026-11-15)

## Decision
* React + TypeScript + Vite, TanStack Query for server state, React Router.
  Plain CSS with design tokens (custom properties) generated from the design
  system, no UI kit, so the visual system is our own.
* Built assets are embedded in the server binary (`go:embed`) and served with
  a strict Content-Security-Policy (no inline scripts).
* Design work follows the Impeccable workflow (`/impeccable init`, `shape`,
  `critique`, `audit`, `polish`, `harden`…). `PRODUCT.md` and `DESIGN.md` are
  the design contract. The deterministic detector runs on every edit (Claude
  Code hook) and in CI as a failing check.
* Tests: Vitest + Testing Library for components; Playwright for end-to-end
  flows against a real server and database.
