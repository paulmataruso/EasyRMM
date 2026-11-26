import { useState } from "react";
import { RefreshCw, Stethoscope } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { TlsCheck, TlsNameStatus, TlsOverview } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, ErrorState, InlineError, Spinner, TableWrap } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";

const STATE_LABEL: Record<TlsNameStatus["state"], string> = {
  valid: "Valid",
  renewing: "Renewing",
  waiting_dns: "Waiting for DNS",
  failing: "Failing",
  expired: "Expired",
  pending: "Waiting for its first certificate",
};

const STATE_TONE: Record<TlsNameStatus["state"], "ok" | "info" | "warn" | "danger" | "neutral"> = {
  valid: "ok",
  renewing: "info",
  waiting_dns: "warn",
  failing: "danger",
  expired: "danger",
  pending: "neutral",
};

const MODE_TEXT: Record<string, string> = {
  manual: "This server serves the certificate files you gave it (EASYRMM_TLS_CERT_FILE). Renew them where you got them; the server picks up a changed file within half a minute.",
  internal: "This server uses its own certificate authority, which every device it enrolled trusts. Browsers will warn until they trust that authority.",
  offload: "TLS ends at your reverse proxy, which holds the certificates. Nothing is obtained here.",
};

/**
 * Settings > Certificates (ADR-0055). In acme mode: each name's certificate, when it renews, what is failing and why, and
 * the controls to check, retry and order without waiting for DNS. The server shows no key and never sends one.
 */
export function CertificatesTab() {
  const q = useApi<TlsOverview>("/settings/certificates", undefined, { refetchInterval: 10_000, staleTime: 5_000 });
  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const { mode, managed, status } = q.data;
  if (!managed || !status) {
    return (
      <Card title="Certificates">
        <p className="text-sm">
          TLS mode: <strong>{mode}</strong>
        </p>
        <p className="mt-2 text-sm text-muted">{MODE_TEXT[mode] ?? "This server does not obtain certificates."}</p>
      </Card>
    );
  }
  return (
    <div className="flex flex-col gap-4">
      {status.held && <Alert tone="warn">The server is held for an update: no certificate is ordered or renewed until it ends.</Alert>}
      {!status.account && <Alert tone="warn">The server has not yet reached the certificate authority to set up its account. It tries every minute; its log says why it cannot.</Alert>}
      {status.warnings.map((w) => (
        <Alert key={w} tone="warn">
          {w}
        </Alert>
      ))}
      <Card title="Certificate authority">
        <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
          <dt className="text-muted">Directory</dt>
          <dd className="break-all">{status.directory}</dd>
          <dt className="text-muted">Contact address</dt>
          <dd>{status.email || "none: Let's Encrypt sends no expiry email, so EasyRMM watches expiry and alerts here"}</dd>
        </dl>
      </Card>
      {status.names.length === 0 ? (
        <Alert tone="info">This server has no DNS name to hold a certificate for.</Alert>
      ) : (
        status.names.map((n) => <NameCard key={n.name} n={n} />)
      )}
    </div>
  );
}

function NameCard({ n }: { n: TlsNameStatus }) {
  const toast = useToast();
  const [checks, setChecks] = useState<TlsCheck[] | null>(null);
  const path = `/settings/certificates/${encodeURIComponent(n.name)}`;
  const check = useApiMutation(() => api.post<{ checks: TlsCheck[] }>(`${path}/check`), { onSuccess: (r) => setChecks(r.checks) });
  const retry = useApiMutation(() => api.post(`${path}/retry`), {
    invalidate: ["/settings/certificates", "/audit"],
    onSuccess: () => toast.success("An attempt has started."),
  });
  const order = useApiMutation(() => api.post(`${path}/order-anyway`), {
    invalidate: ["/settings/certificates", "/audit"],
    onSuccess: () => toast.success("An order has started."),
  });
  const refused = n.retryRefusedUntil ? `Retry now is refused until ${formatDateTime(n.retryRefusedUntil)}: Let's Encrypt allows 5 failed validations an hour.` : null;
  const busy = n.state === "renewing" || retry.isPending || order.isPending;
  return (
    <Card
      title={
        <span className="flex flex-wrap items-center gap-2">
          {n.name}
          {n.role && <span className="text-xs font-normal text-muted">{n.role}</span>}
        </span>
      }
      actions={
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => check.mutate(undefined)} disabled={check.isPending}>
            <Stethoscope className="size-4" aria-hidden /> Check
          </Button>
          {n.state === "waiting_dns" && (
            <Button variant="secondary" onClick={() => order.mutate(undefined)} disabled={busy}>
              Order anyway
            </Button>
          )}
          <Button variant="secondary" onClick={() => retry.mutate(undefined)} disabled={busy || refused !== null}>
            <RefreshCw className="size-4" aria-hidden /> Retry now
          </Button>
        </div>
      }
    >
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Badge tone={STATE_TONE[n.state]}>{STATE_LABEL[n.state]}</Badge>
          {n.alert !== "none" && <Badge tone={n.alert === "critical" ? "danger" : "warn"}>{n.alert === "critical" ? "Critical" : "Warning"}</Badge>}
          {n.imported && <Badge>Kept from before this release</Badge>}
          {n.waitingDnsSince && n.state === "waiting_dns" && <span className="text-muted">waiting for DNS since {formatDateTime(n.waitingDnsSince)}</span>}
          {n.failingSince && n.state === "failing" && <span className="text-muted">failing since {formatDateTime(n.failingSince)}</span>}
        </div>
        <InlineError error={retry.error ?? order.error ?? check.error} />
        {n.alertReason && <Alert tone={n.alert === "critical" ? "danger" : "warn"}>{n.alertReason}.</Alert>}
        {n.lastError && (
          <Alert tone="danger" title="The certificate authority's last answer">
            <span className="break-words">{n.lastError}</span>
          </Alert>
        )}
        {refused && <Alert tone="warn">{refused}</Alert>}
        {n.serial && (
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
            <dt className="text-muted">Serial</dt>
            <dd className="break-all font-mono text-xs">{n.servedSerial || n.serial}</dd>
            <dt className="text-muted">Issued by</dt>
            <dd>{n.issuer || "—"}</dd>
            <dt className="text-muted">Valid</dt>
            <dd>
              {formatDateTime(n.notBefore)} to {formatDateTime(n.notAfter)}
            </dd>
            <dt className="text-muted">Renews automatically</dt>
            <dd>
              {n.ariStart ? (
                <>
                  in the window the CA suggests, {formatDateTime(n.ariStart)} to {formatDateTime(n.ariEnd)}
                  {n.ariExplanation && (
                    <>
                      {" "}
                      (<a className="underline" href={n.ariExplanation} target="_blank" rel="noreferrer noopener">why</a>)
                    </>
                  )}
                </>
              ) : (
                <>from {formatDateTime(n.renewalDue)}, a third of its life before it expires</>
              )}
              {n.nextAttemptAt && n.state !== "valid" && <>; next attempt {formatRelative(n.nextAttemptAt)}</>}
            </dd>
            {n.pendingSerial && (
              <>
                <dt className="text-muted">Waiting to apply</dt>
                <dd>
                  <span className="break-all font-mono text-xs">{n.pendingSerial}</span>, ready {formatRelative(n.pendingReadyAt)}. MeshCentral's agents follow it only
                  once MeshCentral has read it, so it is applied three minutes after MeshCentral's last read, and in fifteen minutes at the latest.
                </dd>
              </>
            )}
          </dl>
        )}
        {checks && <Checks checks={checks} />}
        <p className="text-xs text-muted">The same checks run with <code>docker compose exec server easyrmm-server tls check</code>.</p>
      </div>
    </Card>
  );
}

function Checks({ checks }: { checks: TlsCheck[] }) {
  return (
    <TableWrap>
      <table className="w-full text-sm">
        <tbody>
          {checks.map((c) => (
            <tr key={c.id} className="border-b border-line last:border-0 align-top">
              <td className="w-24 px-3 py-2">
                <Badge tone={c.status === "ok" ? "ok" : c.status === "warn" ? "warn" : "danger"}>{c.status === "ok" ? "Passed" : c.status === "warn" ? "Warning" : "Failed"}</Badge>
              </td>
              <td className="px-3 py-2">
                <p className="font-medium">{c.title}</p>
                <p className="text-muted">{c.detail}</p>
                {c.fix && c.status !== "ok" && <p className="mt-1">{c.fix}</p>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
