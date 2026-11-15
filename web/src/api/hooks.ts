import { keepPreviousData, useMutation, useQuery, useQueryClient, type QueryKey, type UseQueryResult } from "@tanstack/react-query";
import { api, type QueryParams } from "./client";
import type { List, Organization, Site } from "./types";

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
}

export function useApi<T>(path: string | null, params?: QueryParams, options: ApiQueryOptions<T> = {}): UseQueryResult<T> {
  const interval = options.refetchInterval;
  return useQuery<T>({
    queryKey: path ? keyFor(path, params) : ["__disabled__"],
    queryFn: ({ signal }) => api.get<T>(path as string, params, signal),
    enabled: path !== null && (options.enabled ?? true),
    refetchInterval: typeof interval === "function" ? (query) => interval(query.state.data) : interval,
    placeholderData: options.keepPrevious ? keepPreviousData : undefined,
    staleTime: options.staleTime,
  });
}

/** A list endpoint: `items` is always an array. */
export function useList<T>(path: string | null, params?: QueryParams, options: ApiQueryOptions<List<T>> = {}) {
  const query = useApi<List<T>>(path, params, options);
  return { ...query, items: query.data?.items ?? [], next: query.data?.next ?? null };
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

export function useSites(organizationId?: string | null) {
  return useList<Site>("/sites", organizationId ? { organizationId } : undefined, { staleTime: 30_000 });
}
