import { useId, useState } from 'react';
import type { ComplianceTrendPoint } from '../api/types';
import { formatDate } from '../lib/format';

/** Compliance % over time as an inline SVG line chart (no chart library; CSP-safe). */
export function ComplianceTrendChart({ points, height = 180 }: { points: ComplianceTrendPoint[]; height?: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const gradientId = useId();
  const width = 640;
  const pad = { top: 12, right: 12, bottom: 22, left: 36 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;

  if (points.length === 0) {
    return <p className="py-8 text-center text-sm text-muted">No trend data yet. Snapshots are recorded daily per organization.</p>;
  }

  const x = (i: number) => pad.left + (points.length === 1 ? innerW / 2 : (i / (points.length - 1)) * innerW);
  const y = (pct: number) => pad.top + innerH - (Math.max(0, Math.min(100, pct)) / 100) * innerH;
  const line = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(p.compliancePercent).toFixed(1)}`).join(' ');
  const area = `${line} L${x(points.length - 1).toFixed(1)},${pad.top + innerH} L${x(0).toFixed(1)},${pad.top + innerH} Z`;
  const ticks = [0, 25, 50, 75, 100];
  const labelIdx = Array.from(new Set([0, Math.floor((points.length - 1) / 2), points.length - 1]));
  const active = hover !== null ? points[hover] : points[points.length - 1];

  return (
    <figure className="w-full">
      <figcaption className="mb-2 flex flex-wrap items-baseline gap-x-3 text-sm">
        <span className="text-2xl font-semibold tabular-nums">{active.compliancePercent.toFixed(1)}%</span>
        <span className="text-muted">
          compliant on {formatDate(active.date)} · {active.compliant} of {active.totalEndpoints} endpoints · {active.missingRequiredUpdates} missing updates
        </span>
      </figcaption>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full text-accent"
        role="img"
        aria-label={`Compliance trend from ${formatDate(points[0].date)} to ${formatDate(points[points.length - 1].date)}`}
        onMouseLeave={() => setHover(null)}
      >
        <defs>
          <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.28" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
        </defs>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} className="stroke-line" strokeDasharray={t === 0 ? undefined : '3 4'} />
            <text x={pad.left - 6} y={y(t) + 3.5} textAnchor="end" className="fill-subtle text-[10px]">
              {t}%
            </text>
          </g>
        ))}
        <path d={area} fill={`url(#${gradientId})`} />
        <path d={line} fill="none" stroke="currentColor" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {labelIdx.map((i) => (
          <text key={i} x={x(i)} y={height - 6} textAnchor={i === 0 ? 'start' : i === points.length - 1 ? 'end' : 'middle'} className="fill-subtle text-[10px]">
            {formatDate(points[i].date)}
          </text>
        ))}
        {hover !== null && (
          <g>
            <line x1={x(hover)} x2={x(hover)} y1={pad.top} y2={pad.top + innerH} className="stroke-line-strong" />
            <circle cx={x(hover)} cy={y(points[hover].compliancePercent)} r={4} fill="currentColor" className="stroke-surface" strokeWidth={2} />
          </g>
        )}
        {points.map((_, i) => {
          const left = i === 0 ? pad.left : (x(i - 1) + x(i)) / 2;
          const right = i === points.length - 1 ? width - pad.right : (x(i) + x(i + 1)) / 2;
          return <rect key={i} x={left} y={pad.top} width={Math.max(1, right - left)} height={innerH} fill="transparent" onMouseEnter={() => setHover(i)} />;
        })}
      </svg>
    </figure>
  );
}
