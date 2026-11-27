import { useState } from "react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { TlsMoveDevice, TlsMoveProgress, TlsSource, TlsSourceName } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, InlineError, Select, Spinner, TableWrap } from "../../components/ui";
import { formatRelative } from "../../lib/format";

export const SOURCE_LABEL: Record<TlsSource, string> = {
  env: "The source .env gives it (your files, or the internal authority)",
  authority: "The internal authority",
  acme: "Let's Encrypt",
};

const SHORT: Record<TlsSource, string> = { env: "the .env source", authority: "the internal authority", acme: "Let's Encrypt" };

const DEVICE_LABEL: Record<TlsMoveDevice["state"], string> = {
  passed: "Passed",
  failed: "Failed",
  pending: "Not reported",
  stale: "Not seen in 30 days (does not block)",
  outside_scope: "Outside the development scope (blocks)",
};

const DEVICE_TONE: Record<TlsMoveDevice["state"], "ok" | "danger" | "warn" | "neutral"> = {
  passed: "ok",
  failed: "danger",
  pending: "warn",
  stale: "neutral",
  outside_scope: "danger",
};

/**
 * Moving a DNS name's certificate between sources (ADR-0055, 5b2). Starting a move asks for a step-up (the api client
 * opens the dialog on `step_up_required`). The certificate is held, every device that uses the name verifies the new
 * chain, and the server swaps the source by itself once all have; the operator can cancel while it waits.
 */
export function CertificateMove({ name, source, canAcme }: { name: string; source: TlsSource; canAcme: boolean }) {
  const toast = useToast();
  const path = `/settings/certificates/${encodeURIComponent(name)}/move`;
  const progress = useApi<TlsMoveProgress>(path, undefined, { refetchInterval: 5_000 });
  const moving = progress.data !== undefined;
  const [target, setTarget] = useState<TlsSource | "">("");
  const [confirm, setConfirm] = useState(false);
  const refresh = ["/settings/certificates", "/audit"];
  const start = useApiMutation((t: TlsSource) => api.post(path, { target: t }), {
    invalidate: refresh,
    onSuccess: () => {
      setConfirm(false);
      toast.success("The move is waiting for the devices to verify the new certificate.");
    },
  });
  const cancel = useApiMutation(() => api.del(path), { invalidate: refresh, onSuccess: () => toast.success("The move was cancelled; nothing changed.") });
  const options = (["env", "authority", "acme"] as TlsSource[]).filter((s) => s !== source && (s !== "acme" || canAcme));

  if (progress.isPending) return <Spinner />;
  return (
    <Card title={`Certificate source: ${name}`}>
      <div className="flex flex-col gap-3 text-sm">
        <p>
          Served now from <strong>{SOURCE_LABEL[source]}</strong>.
        </p>
        {moving ? (
          <Progress p={progress.data} onCancel={() => cancel.mutate(undefined)} cancelling={cancel.isPending} />
        ) : (
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex flex-col gap-1">
              <span className="text-muted">Move to</span>
              <Select value={target} onChange={(e) => setTarget(e.target.value as TlsSource | "")} aria-label={`New source for ${name}`}>
                <option value="">Choose a source…</option>
                {options.map((s) => (
                  <option key={s} value={s}>
                    {SOURCE_LABEL[s]}
                  </option>
                ))}
              </Select>
            </label>
            <Button variant="primary" disabled={target === "" || start.isPending} onClick={() => setConfirm(true)}>
              Move…
            </Button>
          </div>
        )}
        <InlineError error={start.error ?? cancel.error} />
        {!moving && options.length === 0 && <Alert tone="info">This server cannot serve another source for this name in its TLS mode.</Alert>}
      </div>
      <ConfirmDialog
        open={confirm && target !== ""}
        onClose={() => setConfirm(false)}
        onConfirm={() => target !== "" && start.mutate(target)}
        title={target === "" ? "" : `Move ${name} to ${SHORT[target]}?`}
        confirmLabel="Start the move"
        loading={start.isPending}
        error={start.error}
      >
        <p>
          The new certificate is obtained and held, not served. Every device that uses this name is asked to verify it. Nothing changes for them until all
          have, and you can cancel before then. You will be asked to confirm it is you.
        </p>
      </ConfirmDialog>
    </Card>
  );
}

function Progress({ p, onCancel, cancelling }: { p: TlsMoveProgress; onCancel: () => void; cancelling: boolean }) {
  return (
    <div className="flex flex-col gap-3">
      <Alert tone="info" title={`Moving to ${SHORT[p.target]}`}>
        Started {formatRelative(p.startedAt)}. The certificate is held and not served. It is swapped in, without a restart, once every device below has verified
        it; connections already open keep the old certificate.
        {p.waiting === 0 && p.swapDelaySeconds > 0 && <> Waiting for MeshCentral's next read of its certificate (up to two minutes).</>}
      </Alert>
      {p.notes.map((n) => (
        <Alert key={n} tone="warn">
          {n}
        </Alert>
      ))}
      {p.devices.length === 0 ? (
        <p className="text-muted">No device uses this name, so the swap happens at the next check.</p>
      ) : (
        <TableWrap>
          <table className="w-full text-left text-sm">
            <thead>
              <tr>
                <th className="py-1 pr-3">Device</th>
                <th className="py-1 pr-3">Verifies</th>
                <th className="py-1 pr-3">Result</th>
                <th className="py-1">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {p.devices.map((d) => (
                <tr key={d.deviceId}>
                  <td className="py-1 pr-3">{d.hostname}</td>
                  <td className="py-1 pr-3">{d.scopes.map((s) => (s === "easypatch" ? "EasyPatch agent" : "EasyRMM agent")).join(", ")}</td>
                  <td className="py-1 pr-3">
                    <Badge tone={DEVICE_TONE[d.state]}>{DEVICE_LABEL[d.state]}</Badge>
                    {d.error && <span className="ml-2 break-words text-xs text-muted">{d.error}</span>}
                  </td>
                  <td className="py-1">{d.lastSeen ? formatRelative(d.lastSeen) : "never"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <div>
        <Button variant="secondary" onClick={onCancel} disabled={cancelling}>
          Cancel the move
        </Button>
      </div>
    </div>
  );
}

/** One card per DNS name; shown on Settings > Certificates in every TLS mode but offload. */
export function CertificateSources({ names, canAcme }: { names: string[]; canAcme: boolean }) {
  const q = useApi<{ names: TlsSourceName[] }>("/settings/certificates/sources", undefined, { refetchInterval: 10_000 });
  if (q.isPending) return <Spinner />;
  const by = new Map((q.data?.names ?? []).map((n) => [n.name, n.source]));
  return (
    <>
      {names.map((n) => (
        <CertificateMove key={n} name={n} source={by.get(n) ?? "env"} canAcme={canAcme} />
      ))}
    </>
  );
}
