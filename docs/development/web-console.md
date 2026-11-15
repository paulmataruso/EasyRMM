# Developing the technician console

The console lives in `web/`. It is a React 19 + TypeScript single-page app
built with Vite and Tailwind CSS 4, using TanStack Query for server state and
React Router for navigation. Its look is EasyPatch's design system
([ADR-0013](../architecture/adr/0013-easypatch-design-system.md)); keep
`web/src/index.css` in step with EasyPatch's `frontend/src/index.css`.

The production build is embedded in the server binary (`server/internal/webui`)
and served from the same origin as the API, under a strict
Content-Security-Policy: no inline scripts or styles, nothing loaded from
third parties.

## Running it

The console talks to a real server; there is no mock API.

1. Start a disposable PostgreSQL: `make test-db`.
2. Start a server in offload mode on loopback. The quickest way is the script
   the end-to-end tests use, which creates a fresh database, roles and secret
   key on every start:

   ```bash
   make build
   EASYRMM_E2E_PORT=18080 scripts/e2e/start-server.sh
   ```

   The setup token is written to `web/e2e/.run/data/setup-token`.
3. In `web/`: `npm ci`, then `npm run dev`, and open http://127.0.0.1:5173.
   Vite proxies `/api` to `EASYRMM_DEV_API` (default
   `http://127.0.0.1:18080`) with the public host name the server expects
   (`EASYRMM_DEV_HOST`, default `rmm.localhost`).

Session cookies are `Secure` in production. The script above sets
`EASYRMM_DEV_INSECURE_COOKIES=true` so they work over plain HTTP on loopback;
never set it on a real deployment.

## Layout

| Path | Contents |
|---|---|
| `src/api/` | Fetch client (CSRF token, error envelope, session-ended handling), query hooks, API types |
| `src/auth/` | Session state and the sign-in stages (setup, sign-in, second factor, enrollment, signed in) |
| `src/components/` | Shared UI: buttons, cards, fields, tables, dialogs, toasts, layout |
| `src/pages/` | One folder per area: auth, organizations, settings, account |
| `src/lib/` | Formatting, URL state, keyboard row travel, theme |
| `src/test/` | Test harness: a fake API (`fakeApi.ts`), fixtures, render helpers |
| `e2e/` | Playwright end-to-end suite |

## Tests

* `make web-test` runs the typecheck and the Vitest suite with coverage
  floors (`vite.config.ts`). Page tests render the real app with an
  in-memory API (`src/test/fakeApi.ts`); a request without a matching route
  fails the test.
* `make e2e` builds the console, embeds it, builds the server, and runs the
  Playwright suite. Playwright starts `scripts/e2e/start-server.sh` and a
  `vite preview` of the production build, then walks through first-run setup,
  authenticator enrollment, organizations and sites, an invitation, the
  invited technician's restricted view, and the audit log. It needs
  `make test-db` first. Point `CHROME_PATH` at a Chromium binary to use one
  that is already installed.
* The Impeccable design detector runs in CI:
  `.claude/skills/impeccable/scripts/impeccable detect web/src`.

## Conventions

* Show only what the server provides. Features from later phases are absent,
  not faked.
* Use the project's terms: organization, site, device group, device,
  technician.
* Destructive actions use `ConfirmDialog`, with `confirmText` (type the name)
  when the action cannot be undone.
* One-time secrets (invitation and reset links, recovery codes) are shown in
  dialogs that cannot be dismissed by accident.
* Server field errors appear on their fields (`fieldError`); everything else
  goes through `InlineError`.
