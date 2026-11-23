// A small in-memory stand-in for the EasyRMM HTTP API, installed as the global fetch in tests.
// Routes are "METHOD /path" with ":param" segments, relative to /api/v1. Unmatched requests fail
// the test loudly instead of hanging, so a page that calls an endpoint the test did not expect is caught.

import { vi } from "vitest";
import type { SessionView } from "../api/types";

export interface FakeRequest {
  method: string;
  path: string;
  params: Record<string, string>;
  query: URLSearchParams;
  body: unknown;
  headers: Record<string, string>;
}

export interface FakeReply {
  status?: number;
  body?: unknown;
}

export type FakeHandler = (req: FakeRequest) => FakeReply | Promise<FakeReply>;

export function ok(body: unknown): FakeReply {
  return { status: 200, body };
}

export function fail(status: number, code: string, message: string, fields?: Record<string, string>): FakeReply {
  return { status, body: { error: { code, message, fields } } };
}

export const noContent: FakeReply = { status: 204 };

interface Route {
  method: string;
  pattern: RegExp;
  names: string[];
  handler: FakeHandler;
}

function compile(key: string, handler: FakeHandler): Route {
  const [method = "", path = ""] = key.split(" ");
  const names: string[] = [];
  const source = path.replace(/:([a-zA-Z]+)/g, (_, name: string) => {
    names.push(name);
    return "([^/]+)";
  });
  return { method, pattern: new RegExp(`^${source}$`), names, handler };
}

export interface FakeApi {
  calls: FakeRequest[];
  /** Requests no route answered; the shared test teardown fails the test if any are left. */
  unmatched: string[];
  /** Adds or replaces a route. */
  on: (key: string, handler: FakeHandler | FakeReply) => void;
  /** Requests made to one route key, in order. */
  callsTo: (key: string) => FakeRequest[];
  /** The nth request to a route key; throws when there was none. */
  call: (key: string, n?: number) => FakeRequest;
}

export function installFakeApi(routes: Record<string, FakeHandler | FakeReply> = {}): FakeApi {
  let table: Route[] = [];
  const calls: FakeRequest[] = [];
  const unmatched: string[] = [];
  const on = (key: string, handler: FakeHandler | FakeReply) => {
    const route = compile(key, typeof handler === "function" ? handler : () => handler);
    table = [route, ...table.filter((r) => r.method !== route.method || r.pattern.source !== route.pattern.source)];
  };
  for (const [key, handler] of Object.entries(routes)) on(key, handler);

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "https://rmm.test");
    const method = (init.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const headers = Object.fromEntries(Object.entries((init.headers as Record<string, string>) ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    // JSON is parsed; a file sent as it is (api.upload) is kept as the Blob.
    const body = typeof init.body === "string" ? JSON.parse(init.body) : init.body instanceof Blob ? init.body : undefined;
    for (const route of table) {
      if (route.method !== method) continue;
      const m = route.pattern.exec(path);
      if (!m) continue;
      const params = Object.fromEntries(route.names.map((n, i) => [n, decodeURIComponent(m[i + 1] ?? "")]));
      const req: FakeRequest = { method, path, params, query: url.searchParams, body, headers };
      calls.push(req);
      const reply = await route.handler(req);
      const status = reply.status ?? 200;
      if (status === 204 || reply.body === undefined) return new Response(null, { status });
      return new Response(JSON.stringify(reply.body), { status, headers: { "Content-Type": "application/json" } });
    }
    // The device tree (ADR-0069) follows from the devices a test gives, unless it gives a tree of its own.
    if (method === "GET" && path === "/device-tree") {
      const list = table.find((r) => r.method === "GET" && r.pattern.test("/devices"));
      if (list) {
        const reply = await list.handler({ method, path: "/devices", params: {}, query: new URLSearchParams(), body: undefined, headers: {} });
        const items = ((reply.body as { items?: { siteId: string; deviceGroupId: string | null; online: boolean }[] } | undefined)?.items ?? []);
        const counts = new Map<string, { siteId: string; groupId: string | null; total: number; online: number }>();
        for (const d of items) {
          const key = `${d.siteId}/${d.deviceGroupId ?? ""}`;
          const n = counts.get(key) ?? { siteId: d.siteId, groupId: d.deviceGroupId ?? null, total: 0, online: 0 };
          n.total += 1;
          if (d.online) n.online += 1;
          counts.set(key, n);
        }
        return new Response(JSON.stringify({ groups: [], counts: [...counts.values()] }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
    }
    unmatched.push(`${method} ${path}${url.search}`);
    throw new Error(`fakeApi: no route for ${method} ${path}${url.search}`);
  });
  vi.stubGlobal("fetch", fetchMock);

  active = {
    calls,
    unmatched,
    on,
    callsTo: (key) => {
      const r = compile(key, () => ok(null));
      return calls.filter((c) => c.method === r.method && r.pattern.test(c.path));
    },
    call: (key, n = 0) => {
      const found = active?.callsTo(key)[n];
      if (!found) throw new Error(`fakeApi: no request #${n} to ${key}`);
      return found;
    },
  };
  return active;
}

let active: FakeApi | null = null;

/** Called after each test: an endpoint the test did not expect is a failure, not a silent network error. */
export function takeUnmatched(): string[] {
  const left = active?.unmatched ?? [];
  active = null;
  return left;
}

export function sessionView(overrides: Partial<SessionView> = {}): SessionView {
  return {
    state: "active",
    user: { id: "u-alex", email: "alex@example.com", displayName: "Alex Rivera", status: "active", mfaEnabled: true, totp: true, securityKeys: 0 },
    csrfToken: "csrf-1",
    expiresAt: "2030-01-01T00:00:00Z",
    permissions: ["org.view", "org.manage", "org.create", "site.view", "site.manage", "user.view", "user.manage", "audit.view", "settings.manage"],
    globalPermissions: [],
    isSuperAdmin: true,
    features: { remoteAccess: true },
    ...overrides,
  };
}

/** A device whose agent has not reported its inventory or any measurements yet. */
export function unreportedRoutes(): Record<string, FakeHandler | FakeReply> {
  return {
    "GET /devices/:id/inventory": ok({ inventory: null, metrics: null }),
    "GET /devices/:id/metrics": (r) =>
      ok({ range: r.query.get("range") ?? "24h", bucketSeconds: 300, from: "2026-10-31T10:00:00Z", to: "2026-11-01T10:00:00Z", samples: [] }),
  };
}

/** Routes every signed-in page needs: setup done, the given session, sign-in options, and no alerts (the nav and device pages ask). */
export function baseRoutes(session: SessionView | null): Record<string, FakeHandler | FakeReply> {
  return {
    "GET /setup": ok({ required: false, passwordMinLength: 12 }),
    "GET /auth/session": session ? ok(session) : fail(401, "unauthenticated", "Sign in to continue."),
    "GET /auth/options": ok({
      passwordResetAvailable: false,
      mfaRequired: true,
      passwordMinLength: 12,
      webauthn: { available: false, reason: "Security keys and passkeys need EasyRMM to be reached by a name (EASYRMM_PUBLIC_URL), not an IP address." },
    }),
    "POST /auth/logout": noContent,
    // Single sign-on: none set up. The sign-in and account pages ask.
    "GET /auth/sso": ok({ providers: [] }),
    "GET /auth/identities": ok({ items: [] }),
    "GET /alerts/summary": ok({ active: 0, critical: 0, warning: 0, acknowledged: 0, devices: 0 }),
    "GET /alerts": ok({ items: [] }),
    // The sidebar's section navigation (nav/SectionNav) and the dashboard's recent connections. Tests that care
    // replace these.
    "GET /organizations": ok({ items: [] }),
    "GET /sites": ok({ items: [] }),
    "GET /devices": ok({ items: [] }),
    "GET /sites/:id/device-groups": ok({ items: [] }),
    "GET /alerts/devices": ok({ items: [] }),
    "GET /scripts": ok({ items: [] }),
    "GET /devices/recent-connections": ok({ items: [] }),
  };
}
