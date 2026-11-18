import { useCallback } from 'react';
import { useSearchParams } from 'react-router';
import type { SortState } from '../components/ui';

export type UrlValue = string | number | boolean | null | undefined;

/** Filter, sort and paging state kept in the URL so views are linkable and survive reloads. */
export function useUrlState() {
  const [params, setParams] = useSearchParams();

  const get = useCallback((key: string, fallback = ''): string => params.get(key) ?? fallback, [params]);

  const set = useCallback(
    (updates: Record<string, UrlValue>, options: { resetPage?: boolean } = {}) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [key, value] of Object.entries(updates)) {
            if (value === null || value === undefined || value === '' || value === false) next.delete(key);
            else next.set(key, String(value));
          }
          if (options.resetPage ?? !('page' in updates)) next.delete('page');
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  const page = Math.max(1, Number.parseInt(params.get('page') ?? '1', 10) || 1);

  const sort: SortState = {
    sort: params.get('sort'),
    dir: params.get('dir') === 'asc' ? 'asc' : 'desc',
  };

  const toggleSort = useCallback(
    (field: string) => {
      const current = params.get('sort');
      const dir = params.get('dir') === 'asc' ? 'asc' : 'desc';
      if (current === field) set({ sort: field, dir: dir === 'asc' ? 'desc' : 'asc' });
      else set({ sort: field, dir: 'asc' });
    },
    [params, set],
  );

  return { params, get, set, page, sort, toggleSort };
}
