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
    const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
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
    user: { id: "u-alex", email: "alex@example.com", displayName: "Alex Rivera", status: "active", mfaEnabled: true },
    csrfToken: "csrf-1",
    expiresAt: "2030-01-01T00:00:00Z",
    permissions: ["org.view", "org.manage", "org.create", "site.view", "site.manage", "user.view", "user.manage", "audit.view", "settings.manage"],
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
    "GET /auth/options": ok({ passwordResetAvailable: false, mfaRequired: true, passwordMinLength: 12 }),
    "POST /auth/logout": noContent,
    "GET /alerts/summary": ok({ active: 0, critical: 0, warning: 0, acknowledged: 0, devices: 0 }),
    "GET /alerts": ok({ items: [] }),
    // The sidebar's section navigation (nav/SectionNav) and the dashboard's recent connections. Tests that care
    // replace these.
    "GET /organizations": ok({ items: [] }),
    "GET /sites": ok({ items: [] }),
    "GET /devices": ok({ items: [] }),
    "GET /alerts/devices": ok({ items: [] }),
    "GET /scripts": ok({ items: [] }),
    "GET /devices/recent-connections": ok({ items: [] }),
  };
}
