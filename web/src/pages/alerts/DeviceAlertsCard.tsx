import { Link } from "react-router";
import { useList } from "../../api/hooks";
import type { AlertEntry } from "../../api/types";
import { Card, cx, EmptyState, ErrorState, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { AlertActions, useAlertAction } from "./AlertActions";
import { conditionText, DiskSubject, isActive, risingHint, SeverityBadge, valueText } from "./alertText";

/** A device's active alerts, to acknowledge or resolve in place. Each pulses in red while it is active, and the
 * title counts them (index.css, "Active alerts"). */
export function DeviceAlertsCard({ deviceId }: { deviceId: string }) {
  const list = useList<AlertEntry>("/alerts", { deviceId, status: "active" }, { refetchInterval: 30_000 });
  const actions = useAlertAction();
  const active = list.items.filter(isActive).length;
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
            <li key={a.id} className={cx("flex flex-col gap-2 px-4 py-3", isActive(a) && "alert-active-pulse alert-active-pulse--row")}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{a.name}</p>
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

/** How many alerts are active, beside the card's title and pulsing with them; "100+" past the first page. */
function ActiveCount({ count, more }: { count: number; more: boolean }) {
  const label = more ? `More than ${plural(count, "active alert")}` : plural(count, "active alert");
  return (
    <span
      title={label}
      className="alert-active-pulse alert-active-pulse--filled min-w-5 rounded-full px-1.5 text-center text-xs leading-5 font-semibold tabular-nums"
    >
      {count.toLocaleString()}
      {more && "+"}{" "}
      <span className="sr-only">active</span>
    </span>
  );
}
