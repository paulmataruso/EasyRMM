import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryKey,
  type UseQueryResult,
} from '@tanstack/react-query';
import { api, ApiError, type QueryParams } from './client';
import type {
  CurrentUserDto,
  OrganizationSummaryDto,
  PagedResult,
  PolicyDto,
  SiteDto,
} from './types';

/** Query keys are the path segments plus the params object, so invalidating ['endpoints', id]
 * refreshes everything under /endpoints/{id}. */
export function keyFor(path: string, params?: QueryParams): QueryKey {
  const segments = path.split('?')[0].split('/').filter(Boolean);
  return params && Object.keys(params).length > 0 ? [...segments, params] : segments;
}

export function pathKey(path: string): QueryKey {
  return path.split('/').filter(Boolean);
}

export interface ApiQueryOptions<T = unknown> {
  enabled?: boolean;
  /** Milliseconds, false, or a function of the latest data (e.g. poll fast only while a job runs). */
  refetchInterval?: number | false | ((data: T | undefined) => number | false);
  keepPrevious?: boolean;
  staleTime?: number;
}

export function useApi<T>(path: string | null, params?: QueryParams, options: ApiQueryOptions<T> = {}): UseQueryResult<T> {
  const interval = options.refetchInterval;
  return useQuery<T>({
    queryKey: path ? keyFor(path, params) : ['__disabled__'],
    queryFn: ({ signal }) => api.get<T>(path as string, params, signal),
    enabled: path !== null && (options.enabled ?? true),
    refetchInterval: typeof interval === 'function' ? (query) => interval(query.state.data) : interval,
    placeholderData: options.keepPrevious ? keepPreviousData : undefined,
    staleTime: options.staleTime,
  });
}

/** Accepts either a plain array or a paged envelope, so list views work with both API shapes. */
export function toPage<T>(data: T[] | PagedResult<T> | undefined): PagedResult<T> {
  if (!data) return { items: [], page: 1, pageSize: 0, totalCount: 0 };
  if (Array.isArray(data)) return { items: data, page: 1, pageSize: data.length, totalCount: data.length };
  return data;
}

export function useList<T>(path: string | null, params?: QueryParams, options: ApiQueryOptions<T[] | PagedResult<T>> = {}) {
  const query = useApi<T[] | PagedResult<T>>(path, params, options);
  return { ...query, page: toPage(query.data) };
}

export interface ApiMutationOptions<TResult, TVars> {
  /** Path prefixes to invalidate after success, e.g. ['/endpoints', `/jobs`]. */
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
      const prefixes = typeof options.invalidate === 'function' ? options.invalidate(result, vars) : (options.invalidate ?? []);
      await Promise.all(prefixes.map((p) => client.invalidateQueries({ queryKey: pathKey(p) })));
      options.onSuccess?.(result, vars);
    },
  });
}

// ---------------------------------------------------------------------------------------------
// Frequently shared queries
// ---------------------------------------------------------------------------------------------

export const ME_KEY: QueryKey = ['auth', 'me'];

export function useOrganizations(includeArchived = false) {
  return useList<OrganizationSummaryDto>('/organizations', { pageSize: 200, includeArchived: includeArchived || undefined }, { staleTime: 30_000 });
}

export function useSites(organizationId: string | null | undefined) {
  return useList<SiteDto>(organizationId ? `/organizations/${organizationId}/sites` : null, { pageSize: 200 }, { staleTime: 30_000 });
}

export type { CurrentUserDto };

/** Fetches a policy layer; a missing layer (404 or empty body) is returned as null. */
export function usePolicy(path: string | null) {
  return useQuery<PolicyDto | null>({
    queryKey: path ? keyFor(path) : ['__disabled__'],
    queryFn: async ({ signal }) => {
      try {
        const result = await api.get<PolicyDto | null | ''>(path as string, undefined, signal);
        return result ? result : null;
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return null;
        throw e;
      }
    },
    enabled: path !== null,
  });
}
