// Minimal fetch wrapper for the EasyRMM API.
// - Same-origin cookies: the session cookie is HttpOnly and never touched by script.
// - CSRF: unsafe methods send the session's synchronizer token in X-CSRF-Token.
//   The token comes from the session view and is held in memory only.
// - Errors use the server envelope {"error":{"code","message","fields"}} and become ApiError.

export const API_BASE = "/api/v1";

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export interface ErrorEnvelope {
  error?: { code?: string; message?: string; fields?: Record<string, string> };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly fields: Record<string, string>;

  constructor(status: number, code: string, message: string, fields: Record<string, string> = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.fields = fields;
  }

  /** The message for one request field, if the server rejected it. */
  field(name: string): string | null {
    return this.fields[name] ?? null;
  }
}

function defaultMessage(status: number): string {
  if (status === 0) return "The server could not be reached. Check your connection.";
  if (status === 429) return "Too many requests. Wait a moment and try again.";
  if (status >= 500) return "The server encountered an error. Try again later.";
  return `Request failed (${status}).`;
}

function defaultCode(status: number): string {
  switch (status) {
    case 0:
      return "network_error";
    case 400:
      return "bad_request";
    case 401:
      return "unauthenticated";
    case 403:
      return "forbidden";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 429:
      return "rate_limited";
    default:
      return status >= 500 ? "server_error" : "error";
  }
}

/** Turns any thrown value into a user-facing message. Validation errors name the first field problem. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const fields = Object.values(error.fields);
    if (error.code === "validation_failed" && fields.length === 1 && fields[0]) return fields[0];
    return error.message;
  }
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}

/** The server's message for one form field, or null. */
export function fieldError(error: unknown, name: string): string | null {
  return error instanceof ApiError ? error.field(name) : null;
}

export type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue>;

/** Builds a query string, skipping null/undefined/empty values. */
export function buildQuery(params?: QueryParams): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.append(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export function apiUrl(path: string, params?: QueryParams): string {
  return `${API_BASE}${path}${buildQuery(params)}`;
}

let csrfToken: string | null = null;

/** Set from every session view the server returns (sign-in, MFA, session probe). */
export function setCsrfToken(token: string | null): void {
  csrfToken = token || null;
}

type AuthListener = (error: ApiError) => void;
let authListener: AuthListener | null = null;

/** Registered by the auth provider: told when the session ends or still needs its second factor. */
export function setAuthErrorListener(listener: AuthListener | null): void {
  authListener = listener;
}

export interface RequestOptions {
  params?: QueryParams;
  body?: unknown;
  signal?: AbortSignal;
  /** Do not notify the auth listener (sign-in screens and the session probe). */
  silentAuth?: boolean;
}

async function send(method: string, path: string, options: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (UNSAFE_METHODS.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  return fetch(apiUrl(path, options.params), {
    method,
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    credentials: "same-origin",
    cache: "no-store",
    signal: options.signal,
  });
}

async function readError(response: Response): Promise<ApiError> {
  let body: ErrorEnvelope = {};
  if ((response.headers.get("content-type") ?? "").includes("json")) {
    try {
      body = (await response.json()) as ErrorEnvelope;
    } catch {
      body = {};
    }
  }
  const e = body.error ?? {};
  return new ApiError(
    response.status,
    e.code || defaultCode(response.status),
    e.message || defaultMessage(response.status),
    e.fields ?? {},
  );
}

/** Refreshes the CSRF token from the current session; true when a token was obtained. */
async function refreshCsrf(): Promise<boolean> {
  try {
    const r = await send("GET", "/auth/session", {});
    if (!r.ok) return false;
    const view = (await r.json()) as { csrfToken?: string };
    setCsrfToken(view.csrfToken ?? null);
    return Boolean(view.csrfToken);
  } catch {
    return false;
  }
}

export async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  let response: Response;
  try {
    response = await send(method, path, options);
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    throw new ApiError(0, "network_error", defaultMessage(0));
  }

  if (!response.ok) {
    let error = await readError(response);
    // The session rotated (sign-in elsewhere in this browser, MFA step): fetch the new token and retry once.
    if (error.code === "csrf_failed" && UNSAFE_METHODS.has(method) && (await refreshCsrf())) {
      try {
        response = await send(method, path, options);
      } catch {
        throw new ApiError(0, "network_error", defaultMessage(0));
      }
      if (response.ok) return parse<T>(response);
      error = await readError(response);
    }
    const sessionProblem =
      (error.status === 401 && error.code === "unauthenticated") || (error.status === 403 && error.code === "mfa_required");
    if (sessionProblem && !options.silentAuth) authListener?.(error);
    throw error;
  }
  return parse<T>(response);
}

async function parse<T>(response: Response): Promise<T> {
  if (response.status === 204) return undefined as T;
  if ((response.headers.get("content-type") ?? "").includes("json")) return (await response.json()) as T;
  return (await response.text()) as T;
}

export const api = {
  get: <T>(path: string, params?: QueryParams, signal?: AbortSignal) => request<T>("GET", path, { params, signal }),
  post: <T = void>(path: string, body?: unknown) => request<T>("POST", path, { body: body ?? {} }),
  put: <T = void>(path: string, body?: unknown) => request<T>("PUT", path, { body: body ?? {} }),
  patch: <T = void>(path: string, body?: unknown) => request<T>("PATCH", path, { body: body ?? {} }),
  del: <T = void>(path: string) => request<T>("DELETE", path),
};
