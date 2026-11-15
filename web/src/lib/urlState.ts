import { useCallback } from "react";
import { useSearchParams } from "react-router";

export type UrlValue = string | number | boolean | null | undefined;

/** Filter state kept in the URL so views are linkable and survive reloads. */
export function useUrlState() {
  const [params, setParams] = useSearchParams();

  const get = useCallback((key: string, fallback = ""): string => params.get(key) ?? fallback, [params]);

  const set = useCallback(
    (updates: Record<string, UrlValue>) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [key, value] of Object.entries(updates)) {
            if (value === null || value === undefined || value === "" || value === false) next.delete(key);
            else next.set(key, String(value));
          }
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  return { params, get, set };
}
