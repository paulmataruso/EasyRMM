import { TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { cx } from "./ui";

export type UsageTone = "normal" | "warn" | "danger";

/** How full something is, as a tone: from 80% a warning, from 90% critical. */
export function usageTone(percent: number): UsageTone {
  return percent >= 90 ? "danger" : percent >= 80 ? "warn" : "normal";
}

const TRACK: Record<UsageTone, string> = { normal: "bg-accent-soft", warn: "bg-warn-soft", danger: "bg-danger-soft" };
const FILL: Record<UsageTone, string> = { normal: "bg-accent", warn: "bg-warn", danger: "bg-danger" };

/** A labelled usage bar. The fill carries severity; the percentage and an icon say it too. */
export function UsageMeter({ label, percent, detail, className, hideLabel = false }: {
  label: string;
  percent: number;
  detail?: ReactNode;
  className?: string;
  /** In a table row whose header already names it; the label stays for assistive technology. */
  hideLabel?: boolean;
}) {
  const p = Math.min(100, Math.max(0, Number.isFinite(percent) ? percent : 0));
  const tone = usageTone(p);
  const shown = p > 0 && p < 1 ? "<1" : String(Math.round(p));
  return (
    <div className={className}>
      <div className="flex items-baseline justify-between gap-3 text-xs">
        <span className={cx("font-medium text-muted", hideLabel && "sr-only")}>{label}</span>
        <span className="flex min-w-0 items-center gap-1 text-right tabular-nums">
          {tone !== "normal" && <TriangleAlert className={cx("size-3.5 shrink-0 self-center", tone === "danger" ? "text-danger" : "text-warn")} aria-hidden />}
          <span className="font-semibold text-fg">{shown}%</span>
          {detail && <span className="truncate text-muted">· {detail}</span>}
        </span>
      </div>
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(p)}
        aria-valuetext={`${shown}%${tone === "danger" ? ", critical" : tone === "warn" ? ", high" : ""}`}
        className={cx("mt-1.5 h-2 overflow-hidden rounded-full", TRACK[tone])}
      >
        <div className={cx("h-full rounded-full", FILL[tone])} style={{ width: `${p}%` }} />
      </div>
    </div>
  );
}
