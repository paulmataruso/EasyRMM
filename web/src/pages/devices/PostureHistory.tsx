import { useApi } from "../../api/hooks";
import type { PostureHistoryList } from "../../api/types";
import { Badge, Card, ErrorState, Spinner, TableWrap } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { postureBadge, POSTURE_PHRASES } from "./postureText";

/**
 * How a device's security posture moved (ADR-0082, slice P4): a row each time its word or score changed, newest first.
 * The server keeps the last 90 days and answers 30 unless asked for more.
 */
export function PostureHistory({ deviceId }: { deviceId: string }) {
  const q = useApi<PostureHistoryList>(`/devices/${deviceId}/posture/history`);
  const items = q.data?.items ?? [];
  return (
    <Card className="mb-4" title="Posture history">
      {q.isPending ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
      ) : items.length === 0 ? (
        <p className="text-sm text-muted">No change in this device&apos;s posture has been recorded in the last 30 days.</p>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Posture</th>
                <th scope="col">Does not meet</th>
                <th scope="col">Cannot tell</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => {
                const b = postureBadge(e);
                return (
                  <tr key={e.recordedAt}>
                    <td title={formatDateTime(e.recordedAt)}>{formatRelative(e.recordedAt)}</td>
                    <td>
                      <Badge tone={b.tone} title={POSTURE_PHRASES[e.word]} className="tabular-nums">
                        {b.label}
                      </Badge>
                    </td>
                    <td className="tabular-nums">{e.failing}</td>
                    <td className="tabular-nums">{e.cannotTell}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}
