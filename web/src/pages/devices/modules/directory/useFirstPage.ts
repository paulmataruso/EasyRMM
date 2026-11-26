import { useWinmodRead } from "../winmod";

/**
 * The first page of a directory list (users, groups, computers, privileged groups), read by itself when the card
 * opens: the stored result shows at once, a new read starts when it is old, and it is kept fresh while the card is
 * open. Searching and paging are explicit and go through `useWinmod`.
 */
export function useFirstPage<P>(deviceId: string, action: string, params: Record<string, unknown>, enabled = true) {
  const q = useWinmodRead<P>(deviceId, `active_directory.${action}`, params, enabled);
  return {
    page: q.data?.data ?? null,
    problem: q.data?.failure?.message ?? (q.data && !q.data.data ? q.data.lost : null),
    loading: enabled && q.data === undefined && !q.error,
    refreshing: q.isFetching,
    error: q.error,
  };
}
