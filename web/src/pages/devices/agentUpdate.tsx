import { ArrowUpCircle } from "lucide-react";
import { api } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { AgentUpdateStatus, Device } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Badge, Button, Dot, type Tone } from "../../components/ui";
import { formatDateTime } from "../../lib/format";

/** How the console names where an agent stands against the server's build (ADR-0027). */
export const AGENT_UPDATE_STATUS: Record<AgentUpdateStatus, { label: string; tone: Tone }> = {
  current: { label: "Up to date", tone: "ok" },
  available: { label: "Update available", tone: "info" },
  queued: { label: "Waiting to update", tone: "neutral" },
  updating: { label: "Updating", tone: "accent" },
  failed: { label: "Update failed", tone: "danger" },
  unsupported: { label: "Cannot update itself", tone: "warn" },
  waiting: { label: "Waiting for a signed build", tone: "warn" },
};

/** The name in a certificate's subject or issuer: its common name, or the whole name without one. */
export function commonName(dn: string): string {
  const m = /(?:^|,\s*)CN=((?:\\.|[^,])+)/.exec(dn);
  return m?.[1] ? m[1].replace(/\\(.)/g, "$1") : dn;
}

export function AgentUpdateBadge({ status }: { status: AgentUpdateStatus }) {
  const s = AGENT_UPDATE_STATUS[status];
  return (
    <Badge tone={s.tone} icon={<Dot tone={s.tone} />}>
      {s.label}
    </Badge>
  );
}

/** What the console says of the package that installed an agent (ADR-0056). */
export const INSTALLER_NAMES: Record<string, string> = { deb: "DEB package", rpm: "RPM package", msi: "MSI package" };

export function installerName(installer: string | undefined): string {
  return (installer && INSTALLER_NAMES[installer]) || "Install command";
}

/** The device page's line about its agent: version, update status, and the button to update it. */
export function AgentLine({ device: d }: { device: Device }) {
  const toast = useToast();
  const request = useApiMutation(() => api.post<Device>(`/devices/${d.id}/agent-update`), {
    invalidate: [`/devices/${d.id}`, "/settings/agent-updates"],
    onSuccess: () => toast.success(`${d.name} updates its agent within a few minutes.`),
  });
  const a = d.agent;
  if (!a) return <span className="text-muted">Not installed</span>;
  const u = a.update;
  const canAsk = d.canUpdateAgent && u !== null && (u.status === "available" || u.status === "failed");
  return (
    <span className="block space-y-1.5">
      <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span>
          {a.version} <span className="text-muted">({a.arch})</span>
        </span>
        {u && u.status !== "current" && <AgentUpdateBadge status={u.status} />}
      </span>
      {a.installer !== undefined && <span className="block text-xs text-muted">Installed by: {installerName(a.installer)}</span>}
      {a.ranServerBuildAt !== undefined && (
        <span className="block text-xs text-muted" data-testid="server-build">
          {a.ranServerBuildAt
            ? `Has run the server's build (since ${formatDateTime(a.ranServerBuildAt)}).`
            : "New: has not run the server's build yet. Under When asked it updates at its first check-in; Off holds it."}
        </span>
      )}
      {a.uninstalledAt && (
        <span className="block break-words text-xs text-danger">
          Uninstalled {formatDateTime(a.uninstalledAt)} ({installerName(a.uninstalledInstaller)}) without a request from the console. Remove the device if this was meant.
        </span>
      )}
      {u && u.status !== "current" && u.status !== "unsupported" && u.version && (
        <span className="block text-xs text-muted">The server ships {u.version}.</span>
      )}
      {u?.waitingFor && (
        <span className="block text-xs text-muted">
          Only signed Windows builds are handed out, and {u.waitingFor} is not signed yet
          {u.status === "waiting" ? ": none is handed out for this device." : "."}
        </span>
      )}
      {u?.status === "unsupported" && (
        <span className="block text-xs text-muted">This agent predates self-update. Run the install command on the device once more; later versions update themselves.</span>
      )}
      {u?.error && (u.status === "failed" || u.status === "queued") && (
        <span className="block break-words text-xs text-danger">
          {u.status === "failed" ? `Failed ${u.attempts} times. ` : `Attempt ${u.attempts} failed; trying again soon. `}
          {u.error}
        </span>
      )}
      {request.error && <span className="block text-xs text-danger">{request.error.message}</span>}
      {canAsk && (
        <Button size="sm" icon={<ArrowUpCircle className="size-3.5" aria-hidden />} loading={request.isPending} onClick={() => request.mutate(undefined)}>
          {u.status === "failed" ? "Try again" : "Update agent"}
        </Button>
      )}
    </span>
  );
}
