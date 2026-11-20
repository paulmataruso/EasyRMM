import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { cx } from "./ui";

/** One line of a time chart. color is a CSS colour, normally a --series-N token. */
export interface TimeSeries<T> {
  key: string;
  label: string;
  color: string;
  value: (point: T) => number;
}

interface Props<T extends { at: string }> {
  data: T[];
  series: TimeSeries<T>[];
  /** The period shown, so a sparse period still spans the whole width. */
  from: string;
  to: string;
  /** The spacing of points; a longer silence breaks the line. */
  stepSeconds: number;
  /** Names the chart for assistive technology: "Processor, memory and disk use, last 24 hours". */
  label: string;
  format: (value: number) => string;
  /** The value axis runs from 0 to max (100 for percentages). */
  max?: number;
  height?: number;
  /** While new data loads, the previous render stays, dimmed. */
  stale?: boolean;
  /** Each point is a day (at local midnight): the tooltip and table show dates without times. */
  daily?: boolean;
}

const MARGIN = { top: 10, right: 14, bottom: 24, left: 40 };

/**
 * A line chart over time with one value axis: hairline grid, 2px lines, a legend, a crosshair that
 * snaps to the nearest point with every series' value, keyboard travel, and a data table.
 */
export function TimeChart<T extends { at: string }>({
  data,
  series,
  from,
  to,
  stepSeconds,
  label,
  format,
  max = 100,
  height = 200,
  stale,
  daily = false,
}: Props<T>) {
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [active, setActive] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  const id = useId();

  useEffect(() => {
    const el = box.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([entry]) => entry && setWidth(Math.max(240, Math.round(entry.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const t0 = new Date(from).getTime();
  const t1 = Math.max(new Date(to).getTime(), t0 + 1);
  const when = (at: string) => (daily ? formatDay(at) : formatWhen(at, t1 - t0));
  const plotW = width - MARGIN.left - MARGIN.right;
  const plotH = height - MARGIN.top - MARGIN.bottom;
  const x = (t: number) => MARGIN.left + ((t - t0) / (t1 - t0)) * plotW;
  const y = (v: number) => MARGIN.top + plotH - (Math.min(Math.max(v, 0), max) / max) * plotH;
  const points = useMemo(() => data.map((p) => ({ p, t: new Date(p.at).getTime() })), [data]);

  // Lines break where a device was silent for more than a couple of intervals.
  const gapMs = stepSeconds * 2500;
  const paths = series.map((s) => {
    let d = "";
    const lone: { t: number; v: number }[] = [];
    points.forEach(({ p, t }, i) => {
      const prev = points[i - 1];
      const next = points[i + 1];
      const gap = !prev || t - prev.t > gapMs;
      const v = s.value(p);
      d += `${gap ? "M" : "L"}${x(t).toFixed(1)},${y(v).toFixed(1)}`;
      if (gap && (!next || next.t - t > gapMs)) lone.push({ t, v });
    });
    return { s, d, lone };
  });
  const ticks = timeTicks(t0, t1, plotW);
  const grid = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
  const last = points.length - 1;
  const latest = points.at(-1);

  const nearest = (clientX: number): number | null => {
    const rect = box.current?.getBoundingClientRect();
    if (!rect || points.length === 0) return null;
    const t = t0 + ((clientX - rect.left - MARGIN.left) / plotW) * (t1 - t0);
    let lo = 0;
    let hi = last;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((points[mid]?.t ?? 0) < t) lo = mid + 1;
      else hi = mid;
    }
    const before = points[lo - 1];
    const at = points[lo];
    return before && at && t - before.t < at.t - t ? lo - 1 : lo;
  };
  const onKey = (e: KeyboardEvent) => {
    if (points.length === 0) return;
    const step = { ArrowLeft: -1, ArrowRight: 1, PageUp: -10, PageDown: 10 }[e.key];
    if (step !== undefined) setActive((i) => Math.min(last, Math.max(0, (i ?? last) + step)));
    else if (e.key === "Home") setActive(0);
    else if (e.key === "End") setActive(last);
    else if (e.key === "Escape") setActive(null);
    else return;
    e.preventDefault();
  };

  const hovered = active !== null ? points[active] : undefined;
  const point = hovered?.p;
  const px = hovered ? x(hovered.t) : 0;
  const tipLeft = px > width - 190;

  return (
    <div className="min-w-0">
      <ul className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted" aria-label="Legend">
        {series.map((s) => (
          <li key={s.key} className="flex items-center gap-1.5">
            <span className="h-0.5 w-3.5 rounded-full" style={{ background: s.color }} aria-hidden />
            {s.label}
            {latest && <span className="font-medium text-fg tabular-nums">{format(s.value(latest.p))}</span>}
          </li>
        ))}
      </ul>
      <div
        ref={box}
        className={cx("relative rounded-md outline-offset-2 transition-opacity", stale && "opacity-60")}
        role="group"
        tabIndex={points.length > 0 ? 0 : -1}
        aria-label={`${label}. Use the arrow keys to read the values.`}
        aria-describedby={`${id}-readout`}
        onKeyDown={onKey}
        onBlur={() => setActive(null)}
        onPointerMove={(e: PointerEvent) => setActive(nearest(e.clientX))}
        onPointerLeave={() => setActive(null)}
      >
        <svg width={width} height={height} className="block max-w-full" aria-hidden>
          {grid.map((v) => (
            <g key={v}>
              <line x1={MARGIN.left} x2={width - MARGIN.right} y1={y(v)} y2={y(v)} stroke="var(--line)" strokeWidth={1} shapeRendering="crispEdges" />
              <text x={MARGIN.left - 8} y={y(v)} dy="0.32em" textAnchor="end" className="fill-subtle text-[11px] tabular-nums">
                {format(v)}
              </text>
            </g>
          ))}
          {ticks.map((t) => (
            <text key={t.at} x={x(t.at)} y={height - 6} textAnchor="middle" className="fill-subtle text-[11px] tabular-nums">
              {t.label}
            </text>
          ))}
          {paths.map(({ s, d, lone }) => (
            <g key={s.key}>
              <path d={d} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              {lone.map((l) => (
                <circle key={l.t} cx={x(l.t)} cy={y(l.v)} r={3} fill={s.color} />
              ))}
              {latest && !hovered && <circle cx={x(latest.t)} cy={y(s.value(latest.p))} r={4} fill={s.color} stroke="var(--surface)" strokeWidth={2} />}
            </g>
          ))}
          {point && (
            <g>
              <line x1={px} x2={px} y1={MARGIN.top} y2={MARGIN.top + plotH} stroke="var(--line-strong)" strokeWidth={1} shapeRendering="crispEdges" />
              {series.map((s) => (
                <circle key={s.key} cx={px} cy={y(s.value(point))} r={4} fill={s.color} stroke="var(--surface)" strokeWidth={2} />
              ))}
            </g>
          )}
        </svg>
        {point && (
          <div
            className="pointer-events-none absolute top-1 z-10 min-w-36 rounded-md border border-line bg-raised px-3 py-2 text-xs shadow-md"
            style={tipLeft ? { right: width - px + 10 } : { left: px + 10 }}
          >
            <div className="mb-1 text-muted">{when(point.at)}</div>
            {series.map((s) => (
              <div key={s.key} className="flex items-center gap-2">
                <span className="h-0.5 w-3 rounded-full" style={{ background: s.color }} aria-hidden />
                <span className="font-semibold text-fg tabular-nums">{format(s.value(point))}</span>
                <span className="text-muted">{s.label}</span>
              </div>
            ))}
          </div>
        )}
        {points.length === 0 && (
          <p className="absolute inset-x-0 top-1/2 -translate-y-1/2 text-center text-sm text-muted">No measurements in this period.</p>
        )}
        <p id={`${id}-readout`} className="sr-only" aria-live="polite">
          {point ? `${when(point.at)}: ${series.map((s) => `${s.label} ${format(s.value(point))}`).join(", ")}` : ""}
        </p>
      </div>
      {points.length > 0 && (
        <div className="mt-2">
          <button type="button" className="text-xs text-accent hover:underline" aria-expanded={table} onClick={() => setTable((v) => !v)}>
            {table ? "Hide the data table" : "Show as a table"}
          </button>
          {table && (
            <div className="mt-2 max-h-64 overflow-auto rounded-md border border-line">
              <table className="w-full text-xs">
                <caption className="sr-only">{label}</caption>
                <thead className="sticky top-0 bg-raised text-left text-muted">
                  <tr>
                    <th scope="col" className="px-3 py-1.5 font-medium">
                      {daily ? "Day" : "Time"}
                    </th>
                    {series.map((s) => (
                      <th key={s.key} scope="col" className="px-3 py-1.5 text-right font-medium">
                        {s.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line tabular-nums">
                  {[...data].reverse().map((p) => (
                    <tr key={p.at}>
                      <td className="px-3 py-1 text-muted">{when(p.at)}</td>
                      {series.map((s) => (
                        <td key={s.key} className="px-3 py-1 text-right">
                          {format(s.value(p))}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** The narrowest spacing that keeps time labels ("08:00 AM") from touching. */
const MIN_TICK_PX = 76;

/**
 * Axis ticks on round local times: quarter hours for an hour, four hours for a day, days for a week or more,
 * thinned to every second or third one (or more) when the plot is too narrow for them all. Past two weeks a
 * day is named by its month rather than its weekday.
 */
export function timeTicks(t0: number, t1: number, width = Infinity): { at: number; label: string }[] {
  const span = t1 - t0;
  const step = span <= 2 * HOUR ? 15 * 60_000 : span <= 36 * HOUR ? 4 * HOUR : DAY;
  const offset = new Date(t0).getTimezoneOffset() * 60_000;
  const out: { at: number; label: string }[] = [];
  for (let t = Math.ceil((t0 - offset) / step) * step + offset; t <= t1; t += step) {
    const d = new Date(t);
    const label =
      step !== DAY
        ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
        : span > 14 * DAY
          ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
          : d.toLocaleDateString(undefined, { weekday: "short", day: "numeric" });
    out.push({ at: t, label });
  }
  const every = Math.max(1, Math.ceil((out.length * MIN_TICK_PX) / width));
  return out.filter((_, i) => i % every === 0);
}

function formatDay(at: string): string {
  return new Date(at).toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short", year: "numeric" });
}

function formatWhen(at: string, span: number): string {
  const d = new Date(at);
  return span > 36 * HOUR
    ? d.toLocaleString(undefined, { weekday: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
