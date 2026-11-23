import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { cx } from "../components/ui";

export interface RowMenuItem {
  key: string;
  label: string;
  icon?: ReactNode;
  tone?: "danger";
  onSelect: () => void;
}

const WIDTH = 208;

/**
 * A row's menu in the tree (ADR-0069): the keyboard and screen-reader way to move a device, create a group, or
 * rename and delete one. Opens beside the row, closes on Escape, on a press elsewhere and when an item is chosen;
 * focus returns to the row.
 */
export function RowMenu({ anchor, label, items, onClose }: { anchor: HTMLElement; label: string; items: RowMenuItem[]; onClose: (returnFocus: boolean) => void }) {
  const menu = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ left: number; top: number } | null>(null);

  useLayoutEffect(() => {
    const r = anchor.getBoundingClientRect();
    const left = Math.max(8, Math.min(r.left + 24, window.innerWidth - WIDTH - 8));
    const height = menu.current?.offsetHeight ?? items.length * 36 + 8;
    const top = r.bottom + height > window.innerHeight - 8 ? Math.max(8, r.top - height) : r.bottom;
    setPosition({ left, top });
  }, [anchor, items.length]);

  useEffect(() => {
    menu.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    const away = (e: MouseEvent) => {
      if (!menu.current?.contains(e.target as Node)) onClose(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [onClose]);

  function onKeyDown(e: KeyboardEvent) {
    const els = [...(menu.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])];
    const i = els.indexOf(document.activeElement as HTMLElement);
    switch (e.key) {
      case "Escape":
      case "Tab":
        e.preventDefault();
        e.stopPropagation();
        return onClose(true);
      case "ArrowDown":
        e.preventDefault();
        return els[(i + 1) % els.length]?.focus();
      case "ArrowUp":
        e.preventDefault();
        return els[(i - 1 + els.length) % els.length]?.focus();
      case "Home":
        e.preventDefault();
        return els[0]?.focus();
      case "End":
        e.preventDefault();
        return els.at(-1)?.focus();
    }
  }

  return createPortal(
    <div
      ref={menu}
      role="menu"
      aria-label={label}
      onKeyDown={onKeyDown}
      style={{ left: position?.left ?? -9999, top: position?.top ?? 0, width: WIDTH }}
      className="popover-enter fixed z-50 rounded-lg border border-line bg-surface p-1 text-fg shadow-xl"
    >
      {items.map((it) => (
        <button
          key={it.key}
          type="button"
          role="menuitem"
          tabIndex={-1}
          onClick={() => {
            onClose(false);
            it.onSelect();
          }}
          className={cx(
            "flex h-9 w-full items-center gap-2 rounded-md px-2.5 text-left text-sm hover:bg-hover focus:bg-hover focus:outline-none",
            it.tone === "danger" && "text-danger",
          )}
        >
          {it.icon && <span className="text-muted">{it.icon}</span>}
          {it.label}
        </button>
      ))}
    </div>,
    document.body,
  );
}
