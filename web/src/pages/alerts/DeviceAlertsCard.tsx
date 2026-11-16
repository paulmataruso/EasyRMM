import { Link } from "react-router";
import { useList } from "../../api/hooks";
import type { AlertEntry } from "../../api/types";
import { Card, EmptyState, ErrorState, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { AlertActions, useAlertAction } from "./AlertActions";
import { conditionText, SeverityBadge, valueText } from "./alertText";

/** A device's active alerts, to acknowledge or resolve in place. */
export function DeviceAlertsCard({ deviceId }: { deviceId: string }) {
  const list = useList<AlertEntry>("/alerts", { deviceId, status: "active" }, { refetchInterval: 30_000 });
  const actions = useAlertAction();
  return (
    <Card
      title="Alerts"
      padded={false}
      actions={
        <Link to={`/alerts?deviceId=${deviceId}&status=all`} className="text-xs text-accent hover:underline">
          History
        </Link>
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
            <li key={a.id} className="flex flex-col gap-2 px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{a.name}</p>
                  <p className="text-xs text-muted">
                    <span className="font-medium text-fg tabular-nums">{valueText(a)}</span> · {conditionText(a)}
                  </p>
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
