# EasyPatch administrator web UI

Single-page React application for EasyPatch administrators. It talks only to the EasyPatch
administrator API (`/api/v1/...`, see `docs/api.md`) and links to agent downloads under
`/downloads/...`. All URLs are relative, so the UI must be served from the same origin as the API.

## Stack

All versions are pinned exactly in `package.json` (`.npmrc` sets `save-exact=true`) and locked in
`package-lock.json`.

| Package | Version |
|---|---|
| react, react-dom | 19.3.1 |
| react-router | 8.5.1 |
| @tanstack/react-query | 5.105.0 |
| lucide-react | 1.64.0 |
| typescript | 6.0.3 |
| vite | 8.3.5 |
| @vitejs/plugin-react | 6.1.2 |
| tailwindcss, @tailwindcss/vite | 4.3.3 |
| vitest | 4.1.12 |

Requires Node.js 22.12 or later. Developed with Node.js 24.

## Scripts

```sh
npm ci              # install exactly what package-lock.json specifies
npm run dev         # Vite dev server on http://localhost:5173
npm run typecheck   # tsc -b --noEmit
npm run lint        # same as typecheck (no separate linter is configured)
npm run test        # vitest run (unit tests for formatting, API client and validation rules)
npm run build       # tsc -b && vite build → dist/
npm run preview     # serve dist/ locally
```

The dev server proxies `/api`, `/downloads` and `/health` to `http://localhost:8080` (the API's
listen address). Set `EASYPATCH_API_URL` to proxy to another address:

```sh
EASYPATCH_API_URL=http://192.0.2.10:8080 npm run dev
```

## Serving the build

`npm run build` writes static files to `dist/`. Whatever serves them must:

- serve `index.html` for any path that is not a file (client-side routes such as `/endpoints/…`);
- serve the UI from the same origin as `/api/v1` (the UI uses relative URLs and same-origin cookies);
- be able to send the strict Content Security Policy below. The build contains no inline scripts or
  styles, no CDN references and no web fonts, and Vite is configured with `assetsInlineLimit: 0`.

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'
```

`img-src data:` is needed for the MFA QR code, which the API returns as a data URI.

## Security behavior

- **Session and CSRF.** The API uses a session cookie. On start the UI calls `GET /api/v1/auth/me`,
  which also refreshes the `XSRF-TOKEN` cookie. Every POST/PUT/PATCH/DELETE sends the cookie value in
  the `X-XSRF-TOKEN` header. On a `403 csrf_failed` response the UI fetches `/auth/me` again and
  retries the request once.
- **Auth stages.** A `401` sends the user to `/login?returnTo=…` (only same-site paths are accepted
  as return targets). `403` with `mfa_required`, `mfa_setup_required` or `password_change_required`
  moves the user to MFA verification, forced MFA enrollment or the forced password change screen.
- **Password reset links** have the form `/reset-password#token=epr_…`. The token is read from the
  URL fragment (never sent to the server in a URL) and removed from the address bar immediately.
- **One-time secrets.** Enrollment tokens, MFA recovery codes and password reset links are shown
  once, with copy/download buttons and a "you will not see this again" warning. The token dialog
  cannot be closed until the administrator confirms they copied the tokens. Secrets are never
  written to `localStorage` or logged to the console.
- **No restart action.** The UI never restarts endpoints. It shows the restart-pending state and its
  reasons and tells the administrator to restart through their own process.
- The only browser storage used is the theme preference (`localStorage["easypatch.theme"]`).

## Roles

The UI hides controls the signed-in role cannot use; the API enforces the same rules.

| Role | UI access |
|---|---|
| SuperAdmin | Everything, including users, server settings, global policy and OS lifecycle edits |
| Admin | Operate: installs, scans, organizations, sites, policies, tokens, deployment codes, approvals, audit log |
| ReadOnly | View only; all mutating controls are hidden. Users and audit log tabs are not shown. |

## Layout

```
src/
  main.tsx               QueryClient, router, providers
  App.tsx                routes and the auth-stage gate
  index.css              Tailwind 4 theme tokens (light/dark) and a few component classes
  api/
    types.ts             TypeScript mirror of backend/API/Contracts/AdminDtos.cs (nullable = T | null)
    client.ts            fetch wrapper: problem+json errors, XSRF header, csrf retry, auth listener
    hooks.ts             react-query helpers (useApi, useList, useApiMutation, shared queries)
  auth/AuthContext.tsx   current user, auth stage, role helpers
  components/            UI primitives, native <dialog>, toasts, policy editor, install dialog, …
  lib/                   formatting, URL-state, theme, trend aggregation, time zones
  pages/
    auth/                login, MFA verify/enroll, forced password change, password reset
    DashboardPage.tsx
    organizations/       list, detail (overview, sites, endpoints, policy, deploy)
    endpoints/           list with bulk actions, detail with tabs and the Install All dialog
    updates/             fleet update list and per-update detail with fleet install
    jobs/                job list and detail (timeline, items, cancel, retry)
    reports/             compliance, installations (CSV export), compliance trend
    agents/              enrollment tokens, deployment codes, approvals, packages
    settings/            global policy, server settings, users, OS lifecycle, audit log
    account/             profile, password, MFA, sessions
```
