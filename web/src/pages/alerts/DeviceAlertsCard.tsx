import { Link } from "react-router";
import { useList } from "../../api/hooks";
import type { AlertEntry } from "../../api/types";
import { Card, EmptyState, ErrorState, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { AlertActions, useAlertAction } from "./AlertActions";
import { AlertLink } from "./alertLink";
import { ActiveCount, AlertFlashToggle, conditionText, DiskSubject, risingHint, SeverityBadge, valueText } from "./alertText";

/** A device's active alerts, to acknowledge or resolve in place. Each pulses in red, and the title counts them
 * (index.css, "Active alerts"); Stop flashing holds them still. */
export function DeviceAlertsCard({ deviceId }: { deviceId: string }) {
  const list = useList<AlertEntry>("/alerts", { deviceId, status: "active" }, { refetchInterval: 30_000 });
  const actions = useAlertAction();
  // The server lists active alerts only.
  const active = list.items.length;
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          {"Alerts "}
          {active > 0 && <ActiveCount count={active} more={list.next !== null} />}
        </span>
      }
      padded={false}
      actions={
        <span className="flex items-center gap-2">
          {active > 0 && <AlertFlashToggle />}
          <Link to={`/alerts?deviceId=${deviceId}&status=all`} className="text-xs text-accent hover:underline">
            History
          </Link>
        </span>
      }
    >
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : list.items.length === 0 ? (
        <EmptyState title="No active alerts" compact>
          This device is within its alert policies.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {list.items.map((a) => (
            <li key={a.id} className="alert-active-pulse alert-active-pulse--row flex flex-col gap-2 px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <AlertLink id={a.id} label={`${a.name}, details`} title="Show the alert's details" className="block text-sm font-medium break-words hover:underline">
                    {a.name}
                  </AlertLink>
                  <DiskSubject alert={a} />
                  <p className="text-xs text-muted">
                    <span className="font-medium text-fg tabular-nums">{valueText(a)}</span> · {conditionText(a)}
                  </p>
                  {a.canManage && risingHint(a) && <p className="mt-0.5 text-xs text-muted">{risingHint(a)}</p>}
                </div>
                <SeverityBadge severity={a.severity} />
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs text-muted">
                  <span title={formatDateTime(a.openedAt)}>Opened {formatRelative(a.openedAt)}</span>
                  {a.status === "acknowledged" && <> · acknowledged{a.acknowledgedBy ? ` by ${a.acknowledgedBy}` : ""}</>}
                </p>
                <AlertActions alert={a} actions={actions} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
