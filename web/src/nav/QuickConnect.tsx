import { useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router";
import { AppWindow, ArrowRight, ScreenShare } from "lucide-react";
import type { Device, RemoteKind } from "../api/types";
import { REMOTE_KIND_NAMES } from "../components/StatusBadges";
import { useToast } from "../components/Toast";
import { cx, Dot } from "../components/ui";
import { allowedKinds, KIND_ICONS, unavailableReason } from "../pages/devices/remote";
import { openSessionWindow, sessionPath } from "../pages/devices/sessionWindow";

/** Whether a device offers quick connect to the caller: some session kind is allowed and MeshAgent is there. */
export function canQuickConnect(d: Device): boolean {
  return d.remoteAgent && allowedKinds(d).length > 0;
}

const PANEL_WIDTH = 288;
const GAP = 8;

/**
 * Quick connect: a small panel beside a device's row that opens a remote session in a window of its own (one per
 * device, see sessionWindow) or in this tab. Escape, a click elsewhere, or a choice closes it.
 */
export function QuickConnectPanel({ device, anchor, onClose }: { device: Device; anchor: HTMLElement; onClose: (returnFocus: boolean) => void }) {
  const toast = useToast();
  const panel = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const [position, setPosition] = useState<{ left: number; top: number } | null>(null);
  const kinds = allowedKinds(device);
  const reason = unavailableReason(device);

  // Beside the row, or under it when the sidebar fills the screen (phones); always inside the window.
  useLayoutEffect(() => {
    const place = () => {
      const row = anchor.getBoundingClientRect();
      const height = panel.current?.offsetHeight ?? 0;
      const beside = row.right + GAP + PANEL_WIDTH <= window.innerWidth - GAP;
      const left = beside ? row.right + GAP : Math.max(GAP, Math.min(row.left, window.innerWidth - PANEL_WIDTH - GAP));
      const wanted = beside ? row.top - 6 : row.bottom + 4;
      const top = Math.max(GAP, Math.min(wanted, window.innerHeight - height - GAP));
      setPosition({ left, top });
    };
    place();
    window.addEventListener("resize", place);
    return () => window.removeEventListener("resize", place);
  }, [anchor]);

  useEffect(() => {
    panel.current?.querySelector<HTMLElement>("button:not(:disabled), a[href]")?.focus();
  }, []);

  useEffect(() => {
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (!panel.current?.contains(target) && !anchor.contains(target)) onClose(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [anchor, onClose]);

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      onClose(true);
    }
  }

  function openWindow(kind: RemoteKind) {
    onClose(false);
    if (!openSessionWindow(device.id, kind)) {
      toast.error("Your browser blocked the new window. Allow pop-ups for this site, or open the session in this tab.");
    }
  }

  return createPortal(
    <div
      ref={panel}
      role="dialog"
      aria-labelledby={titleId}
      onKeyDown={onKeyDown}
      onBlur={(e) => {
        const next = e.relatedTarget as Node | null;
        if (next && !panel.current?.contains(next)) onClose(false);
      }}
      style={{ left: position?.left ?? -9999, top: position?.top ?? 0, width: PANEL_WIDTH }}
      className="popover-enter fixed z-50 rounded-lg border border-line bg-surface p-3 text-fg shadow-xl"
    >
      <div className="flex items-start gap-2.5">
        <span className="mt-0.5 inline-flex size-7 shrink-0 items-center justify-center rounded-md bg-accent-soft text-accent">
          <ScreenShare className="size-4" aria-hidden />
        </span>
        <div className="min-w-0 flex-1">
          <h2 id={titleId} className="truncate text-sm font-semibold" title={device.name}>
            {device.name}
          </h2>
          <p className="flex items-center gap-1.5 truncate text-xs text-muted">
            <Dot tone={reason ? "neutral" : "ok"} />
            {reason ? (device.online ? "Remote access not connected" : "Offline") : "Ready to connect"}
            <span aria-hidden>·</span>
            <span className="truncate">{device.siteName}</span>
          </p>
        </div>
      </div>
      {reason && <p className="mt-2.5 text-xs text-muted">{reason}</p>}
      <ul className="mt-3 flex flex-col gap-1.5" aria-label="Open a session">
        {kinds.map((k) => (
          <li key={k} className="flex gap-1.5">
            <button
              type="button"
              disabled={reason !== null}
              onClick={() => openWindow(k)}
              className="flex h-9 flex-1 items-center gap-2 rounded-md border border-line bg-raised px-3 text-sm font-medium hover:border-accent/50 hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:border-line disabled:hover:bg-raised"
              title={reason ?? `Open ${REMOTE_KIND_NAMES[k]} in a new window`}
            >
              <span className="text-muted">{KIND_ICONS[k]}</span>
              {REMOTE_KIND_NAMES[k]}
            </button>
            {reason === null ? (
              <Link
                to={sessionPath(device.id, k)}
                onClick={() => onClose(false)}
                aria-label={`Open ${REMOTE_KIND_NAMES[k]} in this tab`}
                title="In this tab"
                className="inline-flex size-9 shrink-0 items-center justify-center rounded-md border border-line text-muted hover:bg-hover hover:text-fg"
              >
                <AppWindow className="size-4" aria-hidden />
              </Link>
            ) : null}
          </li>
        ))}
      </ul>
      <Link
        to={`/devices/${encodeURIComponent(device.id)}`}
        onClick={() => onClose(false)}
        className={cx("mt-3 inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline")}
      >
        Device page
        <ArrowRight className="size-3" aria-hidden />
      </Link>
    </div>,
    document.body,
  );
}
