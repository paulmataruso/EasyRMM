import { useCallback } from "react";
import { useLocation, useSearchParams } from "react-router";

export type UrlValue = string | number | boolean | null | undefined;

/**
 * The query the last change asked for, until the router renders it. React Router hands a functional update the
 * parameters of the last render, so two changes before the next render (a handler that sets the URL twice, or someone
 * changing two filters faster than the page renders) would otherwise lose the first. Shared by every component.
 */
let pending: { path: string; from: string; to: string } | null = null;

/** Filter state kept in the URL so views are linkable and survive reloads. */
export function useUrlState() {
  const [params, setParams] = useSearchParams();
  const { pathname } = useLocation();
  // A render of anything but the query the pending change started from means the router has caught up or moved on.
  if (pending && (pending.path !== pathname || pending.from !== params.toString())) pending = null;

  const get = useCallback((key: string, fallback = ""): string => params.get(key) ?? fallback, [params]);

  const set = useCallback(
    (updates: Record<string, UrlValue>) => {
      setParams(
        (prev) => {
          const from = prev.toString();
          const next = new URLSearchParams(pending && pending.path === pathname && pending.from === from ? pending.to : from);
          for (const [key, value] of Object.entries(updates)) {
            if (value === null || value === undefined || value === "" || value === false) next.delete(key);
            else next.set(key, String(value));
          }
          pending = { path: pathname, from, to: next.toString() };
          return next;
        },
        { replace: true },
      );
    },
    [setParams, pathname],
  );

  return { params, get, set };
}
