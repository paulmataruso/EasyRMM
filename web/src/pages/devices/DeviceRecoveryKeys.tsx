// A device's BitLocker recovery-key escrow, volume by volume (ADR-0081, slice 1). It shows where each volume's
// recovery key stands and why, never the key: reads come with the next slice.
import { useApi } from "../../api/hooks";
import type { DeviceEscrow, EscrowState, KeystoreSummary } from "../../api/types";
import { Alert, Badge, Card, EmptyState, ErrorState, Mono, Spinner, TableWrap } from "../../components/ui";
import { formatRelative } from "../../lib/format";

export const ESCROW_STATE_TEXT: Record<EscrowState, { label: string; tone: "ok" | "warn" | "danger" | "neutral" | "info"; help: string }> = {
  verified: { label: "Verified", tone: "ok", help: "The keystore opened the sealed key and it matches what the device holds." },
  pending: { label: "Pending", tone: "info", help: "Stored, waiting for the keystore to check it." },
  missing: { label: "Missing", tone: "warn", help: "No recovery key is escrowed for this volume yet." },
  stale: { label: "Stale", tone: "danger", help: "The sealed key did not match. The agent sends it again." },
  conflict: { label: "Conflict", tone: "danger", help: "A different key arrived for a protector that already has a verified one. The verified one is kept." },
};

/** Why escrow is not running, in words, or null while the keystore is ready. */
export function keystoreNotice(k: KeystoreSummary): string | null {
  switch (k.state) {
    case "uninitialised":
      return "The keystore is not initialised, so recovery-key escrow is off. Run easyrmm-keystore init at the host.";
    case "sealed":
      return `The keystore is sealed${k.detail ? ` (${k.detail})` : ""}. Keys already escrowed stay safe; new ones wait until it is unsealed at the host.`;
    case "unavailable":
      return "The keystore cannot be reached, so escrow waits.";
    default:
      return k.recoveryVerified ? null : "The keystore's recovery has not been verified, so it wraps nothing yet. Run easyrmm-keystore verify-recovery.";
  }
}

export function RecoveryKeysCard({ deviceId }: { deviceId: string }) {
  const q = useApi<DeviceEscrow>(`/devices/${deviceId}/escrow`, undefined, { refetchInterval: 60_000, staleTime: 15_000 });
  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />;
  const e = q.data;
  if (!e.applicable) return null;
  const notice = keystoreNotice(e.keystore);
  return (
    <Card title="Disk recovery keys" padded={false}>
      <div className="flex flex-col gap-3 p-4">
        {notice && <Alert tone="info">{notice}</Alert>}
        {e.keystore.fileMode && (
          <Alert tone="warn" title="Keystore protection: file (stand-in)">
            The keystore’s key is in a file on the host; a copy of the host’s disk opens it.
          </Alert>
        )}
        <p className="text-xs text-muted">
          The agent seals each BitLocker recovery key to your organization’s key before it leaves the device. The server stores it and has the
          keystore check it; it cannot open it, and this page never shows it.
        </p>
      </div>
      {e.volumes.length === 0 ? (
        <div className="border-t border-line">
          <EmptyState title="No BitLocker volumes reported" compact>
            Volumes appear once the agent has the organization’s key and finds BitLocker on a disk.
          </EmptyState>
        </div>
      ) : (
        <TableWrap>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-y border-line text-left text-xs text-muted">
                <th className="px-4 py-2 font-medium">Volume</th>
                <th className="px-4 py-2 font-medium">Recovery key</th>
                <th className="px-4 py-2 font-medium">Protectors</th>
              </tr>
            </thead>
            <tbody>
              {e.volumes.map((v) => {
                const t = ESCROW_STATE_TEXT[v.state];
                return (
                  <tr key={v.id} className="border-b border-line last:border-0">
                    <td className="px-4 py-2 align-top">
                      <span className="font-medium text-fg">{v.mount || "Volume"}</span>
                      <span className="ml-2 text-xs text-muted">{v.status}</span>
                    </td>
                    <td className="px-4 py-2 align-top">
                      <Badge tone={t.tone} title={t.help}>
                        {t.label}
                      </Badge>
                      {v.protectors.length === 0 && <span className="ml-2 text-xs text-muted">No recovery password protector</span>}
                    </td>
                    <td className="px-4 py-2 align-top">
                      <ul className="flex flex-col gap-1">
                        {v.protectors.map((p) => (
                          <li key={p.id} className="flex flex-wrap items-center gap-2">
                            <Mono>{p.id}</Mono>
                            <Badge tone={ESCROW_STATE_TEXT[p.state].tone} title={ESCROW_STATE_TEXT[p.state].help}>
                              {ESCROW_STATE_TEXT[p.state].label}
                            </Badge>
                            {p.verifiedAt && <span className="text-xs text-muted">verified {formatRelative(p.verifiedAt)}</span>}
                          </li>
                        ))}
                      </ul>
                    </td>
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
