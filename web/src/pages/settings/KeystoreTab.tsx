import { useApi } from "../../api/hooks";
import type { KeystoreStatus } from "../../api/types";
import { KeystoreAlerts } from "../../components/KeystoreAlerts";
import { keystoreNotice } from "../devices/DeviceRecoveryKeys";
import {
  Alert,
  Badge,
  Card,
  ErrorState,
  Spinner,
  TableWrap,
} from "../../components/ui";
import { formatDateTime } from "../../lib/format";

const STATE_TONE = {
  unsealed: "ok",
  sealed: "danger",
  unavailable: "danger",
  uninitialised: "warn",
} as const;

/**
 * Settings > Keystore (ADR-0081): what the keystore is, which key versions it holds and whether their recovery was proved,
 * and every open keystore alert with a control to resolve it. An organization's own reads and switch are on its page.
 */
export function KeystoreTab() {
  const q = useApi<KeystoreStatus>("/keystore", undefined, {
    refetchInterval: 30_000,
    staleTime: 10_000,
  });
  const notice = q.data
    ? keystoreNotice({
        state: q.data.state,
        recoveryVerified: q.data.recoveryVerified,
        detail: q.data.detail,
        fileMode: q.data.mode === "file",
      })
    : null;
  return (
    <div className="flex flex-col gap-4">
      <Card title="Keystore">
        {q.isPending ? (
          <Spinner />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Badge tone={STATE_TONE[q.data.state]}>{q.data.state}</Badge>
              {q.data.mode && (
                <span className="text-muted">protected by {q.data.mode}</span>
              )}
              {q.data.detail && (
                <span className="text-muted">({q.data.detail})</span>
              )}
            </div>
            {notice && <Alert tone="warn">{notice}</Alert>}
            {q.data.versions.length > 0 && (
              <TableWrap>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-line text-left text-xs text-muted">
                      <th className="px-3 py-2 font-medium">Version</th>
                      <th className="px-3 py-2 font-medium">Made</th>
                      <th className="px-3 py-2 font-medium">Recovery</th>
                      <th className="px-3 py-2 font-medium">In use</th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.versions.map((v) => (
                      <tr key={v.version} className="border-b border-line last:border-0">
                        <td className="px-3 py-2">
                          v{v.version}
                          {v.version === q.data.primary && (
                            <span className="ml-2 text-xs text-muted">primary</span>
                          )}
                        </td>
                        <td className="px-3 py-2">{formatDateTime(v.createdAt)}</td>
                        <td className="px-3 py-2">
                          {v.recoveryVerifiedAt ? (
                            <Badge tone="ok">
                              verified {formatDateTime(v.recoveryVerifiedAt)}
                            </Badge>
                          ) : (
                            <Badge tone="warn">not verified</Badge>
                          )}
                        </td>
                        <td className="px-3 py-2">{v.open ? "yes" : "no"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </div>
        )}
      </Card>
      <Card title="Keystore alerts">
        <KeystoreAlerts canResolve />
      </Card>
    </div>
  );
}
