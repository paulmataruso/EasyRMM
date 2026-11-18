import { useState, type ReactNode } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { useApi } from "../../api/hooks";
import type { DeviceInventory, DeviceMetrics, Filesystem, MetricSample, MetricsHistory, MetricsRange } from "../../api/types";
import { UsageMeter } from "../../components/Meter";
import { TimeChart, type TimeSeries } from "../../components/TimeChart";
import { Card, EmptyState, ErrorState, KeyValueList, Segmented, Spinner } from "../../components/ui";
import { formatDateTime, formatDuration, formatRelative, formatSize, plural } from "../../lib/format";

export function percentOf(used: number, total: number): number {
  return total > 0 ? Math.min(100, (used / total) * 100) : 0;
}

/** Filesystems fullest first, so the one about to run out leads. */
export function byFullness(list: Filesystem[]): Filesystem[] {
  return [...list].sort((a, b) => percentOf(b.usedBytes, b.totalBytes) - percentOf(a.usedBytes, a.totalBytes) || a.mount.localeCompare(b.mount));
}

const SHOWN_FILESYSTEMS = 4;

/** The device's latest measurements: processor, memory, swap and its fullest filesystems. */
export function HealthCard({ query, online, windows = false, onShowAll }: {
  query: UseQueryResult<DeviceInventory>;
  online: boolean;
  /** Windows has no load average, and calls swap its page file. */
  windows?: boolean;
  onShowAll: () => void;
}) {
  const m = query.data?.metrics ?? null;
  return (
    <Card
      title="Health"
      actions={
        m && (
          <span className="text-xs text-muted" title={formatDateTime(m.at)}>
            {online ? "Live" : `As of ${formatRelative(m.at)}`}
          </span>
        )
      }
    >
      {query.isPending ? (
        <Spinner />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />
      ) : m ? (
        <Measurements m={m} windows={windows} onShowAll={onShowAll} />
      ) : (
        <EmptyState title="No measurements yet" compact>
          The agent sends processor, memory and disk use with every check-in.
        </EmptyState>
      )}
    </Card>
  );
}

function Measurements({ m, windows, onShowAll }: { m: DeviceMetrics; windows: boolean; onShowAll: () => void }) {
  const fs = byFullness(m.filesystems);
  const shown = fs.slice(0, SHOWN_FILESYSTEMS);
  return (
    <>
      <div className="flex flex-col gap-3.5">
        <UsageMeter label="Processor" percent={m.cpuPercent} />
        <UsageMeter label="Memory" percent={percentOf(m.memoryUsed, m.memoryTotal)} detail={`${formatSize(m.memoryUsed)} of ${formatSize(m.memoryTotal)}`} />
        {m.swapTotal > 0 && (
          <UsageMeter
            label={windows ? "Page file" : "Swap"}
            percent={percentOf(m.swapUsed, m.swapTotal)}
            detail={`${formatSize(m.swapUsed)} of ${formatSize(m.swapTotal)}`}
          />
        )}
        {shown.map((f) => (
          <UsageMeter
            key={f.mount}
            label={f.mount}
            percent={percentOf(f.usedBytes, f.totalBytes)}
            detail={`${formatSize(f.totalBytes - f.usedBytes)} free`}
          />
        ))}
        {fs.length > shown.length && (
          <button type="button" className="self-start text-xs text-accent hover:underline" onClick={onShowAll}>
            {plural(fs.length - shown.length, "more filesystem")} on the Hardware tab
          </button>
        )}
      </div>
      <KeyValueList
        narrow
        className="mt-4 border-t border-line pt-4"
        items={[
          ...loadAverage(m, windows),
          ["Up for", formatDuration(m.uptimeSeconds)],
          ["Processes", m.processes.toLocaleString()],
        ]}
      />
    </>
  );
}

/** The load average row; Windows has none. */
function loadAverage(m: DeviceMetrics, windows: boolean): [ReactNode, ReactNode][] {
  if (windows) return [];
  return [["Load average", <span className="tabular-nums">{[m.load1, m.load5, m.load15].map((v) => v.toFixed(2)).join(" · ")}</span>]];
}

const RANGES: { value: MetricsRange; label: string; long: string }[] = [
  { value: "1h", label: "1 hour", long: "last hour" },
  { value: "24h", label: "24 hours", long: "last 24 hours" },
  { value: "7d", label: "7 days", long: "last 7 days" },
];

const SERIES: TimeSeries<MetricSample>[] = [
  { key: "cpu", label: "Processor", color: "var(--series-1)", value: (p) => p.cpuPercent },
  { key: "memory", label: "Memory", color: "var(--series-2)", value: (p) => p.memoryPercent },
  { key: "disk", label: "Fullest disk", color: "var(--series-3)", value: (p) => p.diskPercent },
];

const percent = (v: number) => `${Math.round(v)}%`;

/** Processor, memory and disk use over time, averaged into the range's intervals. */
export function PerformanceCard({ deviceId }: { deviceId: string }) {
  const [range, setRange] = useState<MetricsRange>("24h");
  const history = useApi<MetricsHistory>(`/devices/${deviceId}/metrics`, { range }, { keepPrevious: true, refetchInterval: 60_000 });
  const period = RANGES.find((r) => r.value === range)?.long ?? range;
  return (
    <Card
      title="Performance"
      actions={<Segmented label="Period" options={RANGES} value={range} onChange={setRange} />}
    >
      {history.isPending ? (
        <Spinner />
      ) : history.isError ? (
        <ErrorState error={history.error} onRetry={() => void history.refetch()} compact />
      ) : (
        <>
          <TimeChart
            data={history.data.samples}
            series={SERIES}
            from={history.data.from}
            to={history.data.to}
            stepSeconds={history.data.bucketSeconds}
            label={`Processor, memory and fullest disk use, ${period}`}
            format={percent}
            stale={history.isPlaceholderData}
          />
          <p className="mt-2 text-xs text-muted">
            {history.data.bucketSeconds >= 120
              ? `Each point is the average over ${formatDuration(history.data.bucketSeconds)}. `
              : ""}
            Gaps are periods the device did not check in.
          </p>
        </>
      )}
    </Card>
  );
}

/** Loads the device's inventory and latest metrics; shared by the overview and the hardware tab. */
export function useDeviceInventory(deviceId: string, enabled: boolean) {
  return useApi<DeviceInventory>(`/devices/${deviceId}/inventory`, undefined, { enabled, refetchInterval: 60_000 });
}
