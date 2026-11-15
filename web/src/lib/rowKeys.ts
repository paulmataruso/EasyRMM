import { useEffect, type RefObject } from "react";

/**
 * j/k (and the arrow keys while a row link has focus) move between the row links of a
 * table; Enter follows the focused link as usual. Each row marks its main link with
 * data-row-link. `onFocusRow` lets the list warm the cache for the row that has focus.
 */
export function useRowKeys(container: RefObject<HTMLElement | null>, onFocusRow?: (link: HTMLAnchorElement) => void) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const root = container.current;
      if (!root) return;
      const target = e.target instanceof HTMLElement ? e.target : null;
      const typing = target && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));
      const inRow = target?.hasAttribute("data-row-link") && root.contains(target);
      let step = 0;
      if (!typing && (e.key === "j" || (inRow && e.key === "ArrowDown"))) step = 1;
      else if (!typing && (e.key === "k" || (inRow && e.key === "ArrowUp"))) step = -1;
      if (step === 0) return;
      const links = Array.from(root.querySelectorAll<HTMLAnchorElement>("a[data-row-link]"));
      if (links.length === 0) return;
      e.preventDefault();
      const index = inRow ? links.indexOf(target as HTMLAnchorElement) : -1;
      const next = links[index === -1 ? (step > 0 ? 0 : links.length - 1) : Math.min(links.length - 1, Math.max(0, index + step))];
      if (!next) return;
      next.focus();
      next.closest("tr")?.scrollIntoView({ block: "nearest" });
      onFocusRow?.(next);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [container, onFocusRow]);
}
