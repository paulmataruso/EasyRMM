import { useEffect, useRef } from "react";
import { useLocation } from "react-router";

/**
 * Notices that the server was upgraded while this page was open. The server names the console build it serves on
 * every API response (the module script its index.html loads, whose name changes with every build); a page loaded
 * from an older build loads the new one at its next page change, so nothing typed into the current page is lost.
 */
export const BUILD_HEADER = "X-EasyRMM-Console";

let running: string | null | undefined;
let outdated = false;

/** The build this page runs: the module script it was loaded with. */
function runningBuild(): string | null {
  if (running === undefined) running = document.querySelector<HTMLScriptElement>('script[type="module"][src]')?.getAttribute("src") ?? null;
  return running;
}

/** Whether a page running `mine` should load `announced`. Development servers announce nothing or another build. */
export function isOutdated(mine: string | null, announced: string | null): boolean {
  return Boolean(mine && announced && mine.startsWith("/assets/") && mine !== announced);
}

/** Called with each API response's header. */
export function noteServerBuild(announced: string | null): void {
  if (outdated || !announced || !import.meta.env.PROD) return;
  outdated = isOutdated(runningBuild(), announced);
}

/** Loads the new build at the first page change after the server announced one. */
export function useReloadWhenOutdated(): void {
  const { pathname } = useLocation();
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    if (outdated) window.location.reload();
  }, [pathname]);
}
