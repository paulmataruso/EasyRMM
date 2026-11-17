// Minimal fetch wrapper for the EasyPatch admin API.
// - Same-origin cookies (session cookie is HttpOnly; never touched by script).
// - CSRF double-submit: unsafe methods echo the XSRF-TOKEN cookie in X-XSRF-TOKEN.
// - RFC 9457 problem+json errors become ApiError.

export const API_BASE = '/api/v1';

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export interface ProblemDetails {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  code?: string;
  correlationId?: string;
  errors?: Record<string, string[]>;
  [extension: string]: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly correlationId: string | null;
  readonly errors: Record<string, string[]> | null;
  readonly problem: ProblemDetails;

  constructor(status: number, problem: ProblemDetails) {
    super(problemMessage(status, problem));
    this.name = 'ApiError';
    this.status = status;
    this.problem = problem;
    this.code = typeof problem.code === 'string' && problem.code ? problem.code : defaultCode(status);
    this.correlationId = typeof problem.correlationId === 'string' ? problem.correlationId : null;
    this.errors = problem.errors && typeof problem.errors === 'object' ? problem.errors : null;
  }

  /** Reads a problem extension member (e.g. existingJobId for duplicate_job). */
  extension<T = unknown>(name: string): T | undefined {
    return this.problem[name] as T | undefined;
  }
}

function defaultCode(status: number): string {
  switch (status) {
    case 400:
      return 'bad_request';
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    case 429:
      return 'rate_limited';
    default:
      return status >= 500 ? 'server_error' : 'error';
  }
}

export function problemMessage(status: number, problem: ProblemDetails): string {
  if (problem.detail) return problem.detail;
  if (problem.errors) {
    const first = Object.values(problem.errors).flat()[0];
    if (first) return first;
  }
  if (problem.title) return problem.title;
  if (status === 0) return 'The server could not be reached. Check your connection.';
  if (status === 429) return 'Too many requests. Wait a moment and try again.';
  if (status >= 500) return 'The server encountered an error. Try again later.';
  return `Request failed (${status}).`;
}

/** Turns any thrown value into a user-facing message. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return 'Something went wrong.';
}

export function readCookie(name: string): string | null {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      try {
        return decodeURIComponent(trimmed.slice(prefix.length));
      } catch {
        return trimmed.slice(prefix.length);
      }
    }
  }
  return null;
}

export type QueryValue = string | number | boolean | null | undefined | readonly (string | number)[];
export type QueryParams = Record<string, QueryValue>;

/** Builds a query string, skipping null/undefined/empty values. Arrays repeat the key. */
export function buildQuery(params?: QueryParams): string {
  if (!params) return '';
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      for (const v of value) search.append(key, String(v));
    } else {
      search.append(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

export function apiUrl(path: string, params?: QueryParams): string {
  return `${API_BASE}${path}${buildQuery(params)}`;
}

type AuthListener = (error: ApiError) => void;
let authListener: AuthListener | null = null;

/** Registered by the auth provider: called for 401 and auth-stage 403 responses. */
export function setAuthErrorListener(listener: AuthListener | null): void {
  authListener = listener;
}

export const AUTH_STAGE_CODES = new Set(['mfa_required', 'mfa_setup_required', 'password_change_required']);

export interface RequestOptions {
  params?: QueryParams;
  body?: unknown;
  signal?: AbortSignal;
  /** Do not notify the auth listener (used by the session probe and login screens). */
  silentAuth?: boolean;
}

async function send(method: string, path: string, options: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json, application/problem+json' };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (UNSAFE_METHODS.has(method)) {
    const xsrf = readCookie('XSRF-TOKEN');
    if (xsrf) headers['X-XSRF-TOKEN'] = xsrf;
  }
  return fetch(apiUrl(path, options.params), {
    method,
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    credentials: 'same-origin',
    cache: 'no-store',
    signal: options.signal,
  });
}

async function readProblem(response: Response): Promise<ProblemDetails> {
  const type = response.headers.get('content-type') ?? '';
  if (type.includes('json')) {
    try {
      return (await response.json()) as ProblemDetails;
    } catch {
      return {};
    }
  }
  return {};
}

export async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  let response: Response;
  try {
    response = await send(method, path, options);
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, {});
  }

  if (!response.ok) {
    let problem = await readProblem(response);
    // CSRF token missing/rotated: refresh the cookie via /auth/me and retry once.
    if (response.status === 403 && problem.code === 'csrf_failed' && UNSAFE_METHODS.has(method)) {
      try {
        await send('GET', '/auth/me', { silentAuth: true });
        response = await send(method, path, options);
        if (response.ok) return parse<T>(response);
        problem = await readProblem(response);
      } catch {
        throw new ApiError(0, {});
      }
    }

    const error = new ApiError(response.status, problem);
    if (!options.silentAuth && (error.status === 401 || (error.status === 403 && AUTH_STAGE_CODES.has(error.code)))) {
      authListener?.(error);
    }
    throw error;
  }

  return parse<T>(response);
}

async function parse<T>(response: Response): Promise<T> {
  if (response.status === 204) return undefined as T;
  const type = response.headers.get('content-type') ?? '';
  if (type.includes('json')) return (await response.json()) as T;
  return (await response.text()) as T;
}

export const api = {
  get: <T>(path: string, params?: QueryParams, signal?: AbortSignal) => request<T>('GET', path, { params, signal }),
  post: <T = void>(path: string, body?: unknown, params?: QueryParams) => request<T>('POST', path, { body: body ?? {}, params }),
  put: <T = void>(path: string, body?: unknown) => request<T>('PUT', path, { body: body ?? {} }),
  del: <T = void>(path: string, params?: QueryParams) => request<T>('DELETE', path, { params }),
};
