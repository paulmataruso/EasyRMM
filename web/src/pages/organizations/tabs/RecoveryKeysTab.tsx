import { api } from "../../../api/client";
import { useApi, useApiMutation } from "../../../api/hooks";
import type { KeystoreNotice, KeystoreOrgSettings } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { KeystoreAlerts } from "../../../components/KeystoreAlerts";
import { useToast } from "../../../components/Toast";
import {
  Alert,
  Card,
  EmptyState,
  ErrorState,
  InlineError,
  Spinner,
  TableWrap,
} from "../../../components/ui";
import { formatDateTime } from "../../../lib/format";
import type { LevelTabProps } from "../levelTabs";

/**
 * The "Recovery keys" tab of an organization (ADR-0081, ADR-0072): its keystore settings, the notices of every read of a
 * disk recovery key, and the keystore alerts that concern it. The two-person switch is off until an organization turns it
 * on; the console recommends it.
 */
export function RecoveryKeysTab({ level, id }: LevelTabProps) {
  if (level !== "organization") return null;
  return (
    <div className="flex flex-col gap-4">
      <SettingsCard id={id} />
      <Card title="Keystore alerts">
        <KeystoreAlerts organizationId={id} canResolve />
      </Card>
      <NoticesCard id={id} />
    </div>
  );
}

function SettingsCard({ id }: { id: string }) {
  const toast = useToast();
  const path = `/organizations/${id}/keystore-settings`;
  const q = useApi<KeystoreOrgSettings>(path);
  const set = useApiMutation(
    (twoPerson: boolean) => api.put<KeystoreOrgSettings>(path, { twoPerson }),
    {
      invalidate: [path, "/audit"],
      onSuccess: () => toast.success("Saved."),
    },
  );
  return (
    <Card title="Recovery key reads">
      <div className="flex max-w-2xl flex-col gap-3.5">
        <p className="text-sm text-muted">
          A person with the Recovery Key Reader add-on may read a device&apos;s
          disk recovery key after giving a reason and confirming with their
          second factor. Your administrators are told of every read.
        </p>
        {q.isPending ? (
          <Spinner />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
        ) : (
          <>
            <label className="flex items-start gap-2.5 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 size-4 accent-accent"
                checked={q.data.twoPerson}
                disabled={set.isPending}
                onChange={(e) => set.mutate(e.target.checked)}
              />
              <span>
                <span className="font-medium text-fg">
                  Ask a second person to approve each read
                </span>
                <span className="block text-xs text-muted">
                  Off by default. We recommend turning it on: no one then reads
                  a key alone. It needs at least two people with the Recovery
                  Key Approver add-on here (now {q.data.approvers}) and asks
                  for your second factor.
                </span>
              </span>
            </label>
            {!q.data.twoPerson && (
              <Alert tone="info">
                Reads here are decided by one person. Turn the switch on to
                require a second.
              </Alert>
            )}
          </>
        )}
        <InlineError error={set.error} />
      </div>
    </Card>
  );
}

function NoticesCard({ id }: { id: string }) {
  const { can } = useAuth();
  const q = useApi<{ notices: KeystoreNotice[] }>("/keystore/notices", undefined, {
    staleTime: 15_000,
  });
  if (!can("user.manage")) return null;
  const rows = (q.data?.notices ?? []).filter((n) => n.organizationId === id);
  return (
    <Card title="Recovery key reads" padded={false}>
      {q.isPending ? (
        <div className="p-4">
          <Spinner />
        </div>
      ) : q.isError ? (
        <div className="p-4">
          <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState title="No recovery key has been read" compact>
          Each read appears here with who read it, which device and why. The key
          itself is never shown.
        </EmptyState>
      ) : (
        <TableWrap>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-muted">
                <th className="px-4 py-2 font-medium">When</th>
                <th className="px-4 py-2 font-medium">Device</th>
                <th className="px-4 py-2 font-medium">Read by</th>
                <th className="px-4 py-2 font-medium">Approved by</th>
                <th className="px-4 py-2 font-medium">Reason</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((n) => (
                <tr key={n.id} className="border-b border-line last:border-0">
                  <td className="whitespace-nowrap px-4 py-2 align-top">
                    {formatDateTime(n.at)}
                  </td>
                  <td className="px-4 py-2 align-top">{n.device}</td>
                  <td className="px-4 py-2 align-top">{n.by}</td>
                  <td className="px-4 py-2 align-top text-muted">
                    {n.approver || "-"}
                  </td>
                  <td className="px-4 py-2 align-top">{n.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}
