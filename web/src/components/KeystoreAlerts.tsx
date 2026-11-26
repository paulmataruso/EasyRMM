// The keystore's open alerts with a control to resolve each (ADR-0081, section 7). Used on an organization's Recovery keys
// tab (its own alerts) and in Settings > Keystore (the keystore-wide ones and every organization's).
import { api } from "../api/client";
import { useApi, useApiMutation } from "../api/hooks";
import type { KeystoreAlert } from "../api/types";
import { useToast } from "./Toast";
import {
  Alert,
  Badge,
  Button,
  EmptyState,
  ErrorState,
  InlineError,
  Spinner,
} from "./ui";
import { formatRelative } from "../lib/format";

export const ALERT_TITLES: Record<string, string> = {
  keystore_unreachable: "The keystore cannot be reached",
  keystore_sealed: "The keystore is sealed",
  keystore_file_mode: "The keystore's key is in a file",
  keystore_tpm_policy: "The TPM policy changed",
  recovery_not_verified: "A recovery has not been verified",
  kek_verification_overdue: "A key version is overdue for verification",
  escrow_conflict: "A recovery key conflicts with the verified one",
  unaudited_read: "A key was read outside the console",
  keystore_log_broken: "The keystore's log does not verify",
  read_limit: "Reads reached a limit",
};

export function KeystoreAlerts({
  organizationId,
  canResolve,
}: {
  /** Show only this organization's alerts; absent shows every alert the viewer may see. */
  organizationId?: string;
  canResolve: boolean;
}) {
  const toast = useToast();
  const q = useApi<{ alerts: KeystoreAlert[] }>("/keystore/alerts", undefined, {
    refetchInterval: 60_000,
    staleTime: 15_000,
  });
  const resolve = useApiMutation(
    (id: string) => api.post(`/keystore/alerts/${id}/resolve`),
    {
      invalidate: ["/keystore/alerts", "/audit"],
      onSuccess: () => toast.success("Alert resolved."),
    },
  );
  if (q.isPending) return <Spinner />;
  if (q.isError)
    return (
      <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
    );
  const alerts = q.data.alerts.filter(
    (a) => organizationId === undefined || a.organizationId === organizationId,
  );
  if (alerts.length === 0)
    return (
      <EmptyState title="No open keystore alerts" compact>
        Alerts about the keystore, the keys it holds and who read them appear
        here.
      </EmptyState>
    );
  return (
    <div className="flex flex-col gap-3">
      <InlineError error={resolve.error} />
      <ul className="flex flex-col gap-2">
        {alerts.map((a) => (
          <li key={a.id}>
            <Alert tone={a.severity === "critical" ? "danger" : "warn"}>
              <div className="flex flex-wrap items-start gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <strong className="font-medium">
                      {ALERT_TITLES[a.kind] ?? a.kind}
                    </strong>
                    <Badge tone={a.severity === "critical" ? "danger" : "warn"}>
                      {a.severity}
                    </Badge>
                    <span className="text-xs text-muted">
                      opened {formatRelative(a.openedAt)}
                    </span>
                  </div>
                  <p className="mt-1 text-sm">{a.detail}</p>
                </div>
                {canResolve && (
                  <Button
                    size="sm"
                    variant="secondary"
                    loading={resolve.isPending && resolve.variables === a.id}
                    onClick={() => resolve.mutate(a.id)}
                    aria-label={`Resolve: ${ALERT_TITLES[a.kind] ?? a.kind}`}
                  >
                    Resolve
                  </Button>
                )}
              </div>
            </Alert>
          </li>
        ))}
      </ul>
    </div>
  );
}
