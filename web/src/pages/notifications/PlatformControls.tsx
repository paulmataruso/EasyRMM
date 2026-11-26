import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { FleetSilence, QuarantinedRow } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, EmptyState, InlineError, TableWrap } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";

const SILENCE = "/notifications/silence";
const QUARANTINED = "/notifications/quarantined";

/**
 * What only super administrators control (ADR-0053): the fleet-wide hold, which keeps organizations' offline alerts
 * waiting while most devices are silent at once, and the journal rows set aside after failing to be planned.
 */
export function PlatformControls() {
  return (
    <>
      <FleetHold />
      <Quarantine />
    </>
  );
}

function FleetHold() {
  const toast = useToast();
  const q = useApi<{ silence: FleetSilence | null }>(SILENCE, undefined, { refetchInterval: 20_000 });
  const end = useApiMutation(() => api.post(`${SILENCE}/end`), {
    invalidate: [SILENCE, "/notices", "/audit"],
    onSuccess: () => toast.success("The hold ended. Organizations' offline alerts still open are being sent."),
  });
  const s = q.data?.silence;
  return (
    <Card title="Fleet-wide hold">
      {s ? (
        <Alert tone="warn" title="Most devices stopped checking in at once">
          <p>
            {s.counted} devices that had been checking in went silent {formatRelative(s.startedAt)} ({formatDateTime(s.startedAt)}). EasyRMM may be unreachable from them. Organizations&apos; rules send no offline alerts while this
            lasts; the platform&apos;s do. It ends when more than half of them are back.
          </p>
          <div className="mt-2">
            <Button variant="primary" loading={end.isPending} onClick={() => end.mutate()}>
              End now
            </Button>
          </div>
          <InlineError error={end.error} />
        </Alert>
      ) : (
        <p className="text-sm text-muted">No hold is in force. It starts when at least half, and at least 20, of the devices that were checking in go silent within five minutes.</p>
      )}
    </Card>
  );
}

function Quarantine() {
  const toast = useToast();
  const q = useApi<{ rows: QuarantinedRow[] }>(QUARANTINED, undefined, { refetchInterval: 30_000 });
  const act = useApiMutation((v: { row: number; what: "retry" | "discard" }) => api.post(`${QUARANTINED}/${v.row}/${v.what}`), {
    invalidate: [QUARANTINED, "/notices", "/audit"],
    onSuccess: (_d, v) => toast.success(v.what === "retry" ? "The row will be planned again." : "The row was discarded and the alert's current state planned."),
  });
  const rows = q.data?.rows ?? [];
  return (
    <Card title="Quarantined changes" padded={false}>
      {rows.length === 0 ? (
        <EmptyState title="Nothing is set aside" compact>
          A change that cannot be planned after three tries is set aside here; later changes about the same alert wait behind it.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-muted">
                <th className="px-4 py-2 font-medium">Change</th>
                <th className="px-4 py-2 font-medium">Why</th>
                <th className="px-4 py-2 font-medium">Waiting behind it</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-b border-line last:border-0">
                  <td className="px-4 py-2 align-top">
                    {r.subjectType} {r.event}
                    <div className="text-xs text-muted">{formatDateTime(r.createdAt)}</div>
                  </td>
                  <td className="px-4 py-2 align-top text-xs">{r.error}</td>
                  <td className="px-4 py-2 align-top">{r.held}</td>
                  <td className="whitespace-nowrap px-4 py-2 text-right align-top">
                    <Button size="sm" variant="ghost" onClick={() => act.mutate({ row: r.id, what: "retry" })}>
                      Retry
                    </Button>
                    <Button size="sm" variant="danger-ghost" onClick={() => act.mutate({ row: r.id, what: "discard" })}>
                      Discard
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <InlineError error={act.error} />
    </Card>
  );
}
