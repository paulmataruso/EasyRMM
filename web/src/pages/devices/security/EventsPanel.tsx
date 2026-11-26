import type { Device } from "../../../api/types";
import { useApi } from "../../../api/hooks";
import { Alert, Badge, Card, ErrorState, Spinner } from "../../../components/ui";
import { formatDateTime } from "../../../lib/format";
import { EVENT_TEXT, SEVERITY_TEXT } from "./text";
import type { DefenderEvent, DefenderEvents } from "./types";

/** What the summary says of a configuration change, without its value (only a holder of view_sensitive sees that). */
function changeText(e: DefenderEvent): string | null {
  if (e.eventId !== 5007 && e.eventId !== 5004) return null;
  return e.summary.class === "exclusion" ? "An exclusion changed" : e.summary.class === "setting" ? "A protection setting changed" : "A Defender setting changed";
}

/** The events the agent read from Defender's log: stored, so no job, shown as they came. */
export function EventsPanel({ device }: { device: Device }) {
  const events = useApi<DefenderEvents>(`/devices/${device.id}/defender/events`, { limit: 100 });
  return (
    <Card title="Events">
      <div className="flex flex-col gap-3">
        {events.isPending && <Spinner />}
        {events.error && <ErrorState error={events.error} onRetry={() => void events.refetch()} compact />}
        {events.data?.gap && <Alert tone="warn">Events may have been missed since {formatDateTime(events.data.gap)}: the log was cleared or wrapped.</Alert>}
        {events.data && events.data.items.length === 0 && <p className="text-sm text-muted">No events yet. The agent reads Defender's log about once a minute.</p>}
        {events.data && events.data.items.length > 0 && (
          <ul className="divide-y divide-border">
            {events.data.items.map((e) => (
              <li key={e.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5 text-sm">
                <span className="w-44 text-xs text-muted">{formatDateTime(e.at)}</span>
                <span className="min-w-0 flex-1">
                  {changeText(e) ?? EVENT_TEXT[e.eventId] ?? `Event ${e.eventId}`}
                  {e.threatName ? `: ${e.threatName}` : ""}
                  {e.sensitive?.path && <span className="ml-2 break-all font-mono text-xs text-muted">{e.sensitive.path}</span>}
                  {typeof e.summary.count === "number" && <span className="ml-2 text-xs text-muted">({String(e.summary.count)} events counted together)</span>}
                </span>
                {e.severity > 0 && <Badge tone={e.severity >= 4 ? "danger" : "warn"}>{SEVERITY_TEXT[e.severity] ?? e.severity}</Badge>}
                {e.ours && <Badge tone="info">Made by EasyRMM</Badge>}
                {e.backfill && <Badge>Earlier</Badge>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
