import type { ComplianceTrendPoint } from '../api/types';

/** Merges per-organization snapshots into one point per date (no-op if the server already aggregated). */
export function aggregateTrend(points: ComplianceTrendPoint[]): ComplianceTrendPoint[] {
  const byDate = new Map<string, ComplianceTrendPoint>();
  for (const p of points) {
    const prev = byDate.get(p.date);
    if (!prev) {
      byDate.set(p.date, { ...p });
      continue;
    }
    prev.totalEndpoints += p.totalEndpoints;
    prev.compliant += p.compliant;
    prev.missingUpdates += p.missingUpdates;
    prev.failedUpdates += p.failedUpdates;
    prev.rebootRequired += p.rebootRequired;
    prev.scanStale += p.scanStale;
    prev.neverScanned += p.neverScanned;
    prev.offline += p.offline;
    prev.missingRequiredUpdates += p.missingRequiredUpdates;
  }
  return [...byDate.values()]
    .map((p) => ({ ...p, compliancePercent: p.totalEndpoints > 0 ? (p.compliant / p.totalEndpoints) * 100 : 0 }))
    .sort((a, b) => a.date.localeCompare(b.date));
}

export function isoDate(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

export function daysAgo(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return isoDate(d);
}
