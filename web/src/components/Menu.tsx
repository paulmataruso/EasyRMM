import { useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { ChevronDown } from "lucide-react";
import { Button, cx, type ButtonVariant } from "./ui";

export interface MenuItem {
  id: string;
  label: ReactNode;
  icon?: ReactNode;
  /** A route to follow; otherwise onSelect runs. */
  to?: string;
  onSelect?: () => void;
}

const itemClasses =
  "flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-sm text-fg whitespace-nowrap hover:bg-hover focus:bg-hover focus-visible:outline-none";

/**
 * A button that opens a short menu of actions (WAI-ARIA menu button): the first item takes focus when it opens,
 * arrow keys, Home and End move between items, Escape closes it and returns focus to the button, and a click
 * outside or Tab closes it.
 */
export function MenuButton({ items, children, icon, variant = "secondary", size = "md", label, className }: {
  items: MenuItem[];
  children: ReactNode;
  icon?: ReactNode;
  variant?: ButtonVariant;
  size?: "sm" | "md";
  /** Accessible name of the menu, e.g. "Open Terminal". */
  label: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [alignLeft, setAlignLeft] = useState(false);
  const wrapper = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const entries = () => Array.from(menu.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);

  useLayoutEffect(() => {
    if (!open) {
      setAlignLeft(false);
      return;
    }
    // Right-aligned under the button unless that would run off the left edge (header actions wrap on phones).
    if ((menu.current?.getBoundingClientRect().left ?? 0) < 8) setAlignLeft(true);
    entries()[0]?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: PointerEvent) => {
      if (!wrapper.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  function close(returnFocus: boolean) {
    setOpen(false);
    if (returnFocus) button.current?.focus();
  }

  function onMenuKey(e: KeyboardEvent) {
    const list = entries();
    const index = list.indexOf(document.activeElement as HTMLElement);
    const move = (to: number) => {
      e.preventDefault();
      list[(to + list.length) % list.length]?.focus();
    };
    switch (e.key) {
      case "ArrowDown":
        return move(index + 1);
      case "ArrowUp":
        return move(index - 1);
      case "Home":
        return move(0);
      case "End":
        return move(list.length - 1);
      case "Escape":
        e.preventDefault();
        return close(true);
      case "Tab":
        return close(false);
    }
  }

  return (
    <div ref={wrapper} className="relative">
      <Button
        ref={button}
        variant={variant}
        size={size}
        icon={icon}
        className={className}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => {
          if ((e.key === "ArrowDown" || e.key === "ArrowUp") && !open) {
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        {children}
        <ChevronDown className={cx("size-3.5 opacity-70 transition-transform", open && "rotate-180")} aria-hidden />
      </Button>
      {open && (
        <div
          ref={menu}
          id={menuId}
          role="menu"
          aria-label={label}
          onKeyDown={onMenuKey}
          className={cx("absolute top-full z-30 mt-1 min-w-48 rounded-lg border border-line bg-surface p-1 shadow-lg", alignLeft ? "left-0" : "right-0")}
        >
          {items.map((item) =>
            item.to ? (
              <Link key={item.id} to={item.to} role="menuitem" tabIndex={-1} className={itemClasses} onClick={() => setOpen(false)}>
                <span className="text-muted">{item.icon}</span>
                {item.label}
              </Link>
            ) : (
              <button
                key={item.id}
                type="button"
                role="menuitem"
                tabIndex={-1}
                className={itemClasses}
                onClick={() => {
                  close(true);
                  item.onSelect?.();
                }}
              >
                <span className="text-muted">{item.icon}</span>
                {item.label}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  );
}
