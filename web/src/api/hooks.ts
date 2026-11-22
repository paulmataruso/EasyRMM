import { keepPreviousData, useMutation, useQuery, useQueryClient, type QueryKey, type UseQueryResult } from "@tanstack/react-query";
import { api, type QueryParams } from "./client";
import type { DeviceAlertCount, List, Organization, Site } from "./types";

/** Query keys are the path segments plus the params object, so invalidating ['users', id]
 * refreshes everything under /users/{id}. */
export function keyFor(path: string, params?: QueryParams): QueryKey {
  const segments = (path.split("?")[0] ?? "").split("/").filter(Boolean);
  return params && Object.keys(params).length > 0 ? [...segments, params] : segments;
}

export function pathKey(path: string): QueryKey {
  return path.split("/").filter(Boolean);
}

export interface ApiQueryOptions<T = unknown> {
  enabled?: boolean;
  refetchInterval?: number | false | ((data: T | undefined) => number | false);
  keepPrevious?: boolean;
  staleTime?: number;
  /** A key of its own instead of the path's, so that invalidating the path's prefix leaves the query alone. */
  key?: QueryKey;
  /** False: not asked again when the window regains focus. */
  refetchOnWindowFocus?: boolean;
  /** How long the result is kept once no page uses it; 0 drops it when the page closes. */
  gcTime?: number;
}

export function useApi<T>(path: string | null, params?: QueryParams, options: ApiQueryOptions<T> = {}): UseQueryResult<T> {
  const interval = options.refetchInterval;
  return useQuery<T>({
    queryKey: path ? (options.key ?? keyFor(path, params)) : ["__disabled__"],
    queryFn: ({ signal }) => api.get<T>(path as string, params, signal),
    enabled: path !== null && (options.enabled ?? true),
    refetchInterval: typeof interval === "function" ? (query) => interval(query.state.data) : interval,
    placeholderData: options.keepPrevious ? keepPreviousData : undefined,
    staleTime: options.staleTime,
    // Left out unless given, so the client's defaults hold.
    ...(options.refetchOnWindowFocus !== undefined && { refetchOnWindowFocus: options.refetchOnWindowFocus }),
    ...(options.gcTime !== undefined && { gcTime: options.gcTime }),
  });
}

/**
 * Options for a read that is audited on the server (ADR-0063): asked once while the page is open, never again on
 * focus, and not kept once the page closes. The key is outside the path's prefix, so refreshing the run or the job
 * does not ask again.
 */
export function auditedRead(key: QueryKey): ApiQueryOptions {
  return { key, refetchOnWindowFocus: false, gcTime: 0, staleTime: Infinity };
}

/** Shared by every list without data yet, so `items` keeps one identity across renders (safe as a memo dependency). */
const NO_ITEMS: never[] = [];

/** A list endpoint: `items` is always an array. */
export function useList<T>(path: string | null, params?: QueryParams, options: ApiQueryOptions<List<T>> = {}) {
  const query = useApi<List<T>>(path, params, options);
  return { ...query, items: query.data?.items ?? (NO_ITEMS as T[]), next: query.data?.next ?? null };
}

/** Warms the cache for a path (hover and j/k focus on list rows), so the detail view opens instantly. */
export function usePrefetch() {
  const client = useQueryClient();
  return (path: string) =>
    void client.prefetchQuery({
      queryKey: keyFor(path),
      queryFn: ({ signal }) => api.get(path, undefined, signal),
      staleTime: 15_000,
    });
}

export interface ApiMutationOptions<TResult, TVars> {
  /** Path prefixes to invalidate after success, e.g. ['/organizations', '/audit']. */
  invalidate?: string[] | ((result: TResult, vars: TVars) => string[]);
  onSuccess?: (result: TResult, vars: TVars) => void;
}

export function useApiMutation<TVars, TResult = void>(
  fn: (vars: TVars) => Promise<TResult>,
  options: ApiMutationOptions<TResult, TVars> = {},
) {
  const client = useQueryClient();
  return useMutation<TResult, Error, TVars>({
    mutationFn: fn,
    onSuccess: async (result, vars) => {
      const prefixes = typeof options.invalidate === "function" ? options.invalidate(result, vars) : (options.invalidate ?? []);
      await Promise.all(prefixes.map((p) => client.invalidateQueries({ queryKey: pathKey(p) })));
      options.onSuccess?.(result, vars);
    },
  });
}

export function useOrganizations() {
  return useList<Organization>("/organizations", undefined, { staleTime: 30_000 });
}

/**
 * How many devices wait for approval (ADR-0024), for those who may decide them: the menu, the devices tree and the
 * approvals page share the one query.
 */
export function useWaitingDevices(enabled: boolean): number {
  const q = useApi<{ waiting: number }>(enabled ? "/enrollment-requests/waiting" : null, undefined, { refetchInterval: 30_000, staleTime: 5_000 });
  return enabled ? (q.data?.waiting ?? 0) : 0;
}

/**
 * Active and critical alerts on each device that has any (GET /alerts/devices): the menu's alerts tree and the alerts
 * page share the one query, so a device's name can pulse in both without a request per row.
 */
export function useDeviceAlertCounts(enabled: boolean) {
  return useList<DeviceAlertCount>(enabled ? "/alerts/devices" : null, undefined, { refetchInterval: 30_000 });
}

export function useSites(organizationId?: string | null) {
  return useList<Site>("/sites", organizationId ? { organizationId } : undefined, { staleTime: 30_000 });
}
