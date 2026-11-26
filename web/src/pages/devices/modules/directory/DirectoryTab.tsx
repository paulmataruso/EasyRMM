import { useCallback, useState } from "react";
import { useApi } from "../../../../api/hooks";
import type { Device } from "../../../../api/types";
import { useAuth } from "../../../../auth/AuthContext";
import { Alert, Badge, Card, InlineError, KeyValueList, type Tone } from "../../../../components/ui";
import { formatDateTime } from "../../../../lib/format";
import { Link } from "react-router";
import { ModuleTab } from "../ModuleTab";
import { ComputersCard } from "./ComputersCard";
import { PrivilegedCard } from "./PrivilegedCard";
import { GroupsCard } from "./GroupsCard";
import { UsersCard } from "./UsersCard";
import type { AdDomains, CheckState, DirectoryHealth, DirectoryStatus } from "./types";
import { useWinmod } from "./useWinmod";

const CHECK_LABEL: Record<string, string> = {
  replication: "Replication",
  fsmo: "Operations masters",
  services: "Directory services",
  sysvol: "SYSVOL and NETLOGON",
};
const STATE: Record<CheckState, { label: string; tone: Tone }> = {
  ok: { label: "OK", tone: "ok" },
  warning: { label: "Warning", tone: "warn" },
  critical: { label: "Critical", tone: "danger" },
  unknown: { label: "Unknown", tone: "neutral" },
  not_applicable: { label: "Not applicable", tone: "neutral" },
  could_not_run: { label: "Could not run", tone: "neutral" },
};

const FAILURES: Record<string, string> = {
  module_missing: "The ActiveDirectory PowerShell module is not installed on this controller. Install the RSAT-AD-PowerShell feature there; EasyRMM does not change the controller's features.",
  adws_unavailable: "Active Directory Web Services is not running on this controller.",
};

/**
 * The device page's "Directory" tab: Active Directory on a domain controller (ADR-0075). Everything is read from the
 * controller this page is for, when asked; nothing is copied into EasyRMM. The help-desk actions (unlock, enable, disable,
 * reset a password) are on the users; what the person may do follows their permissions, and the server asks again.
 */
export function DirectoryTab({ device }: { device: Device }) {
  const run = useWinmod(device.id);
  const { can } = useAuth();
  const domains = useApi<AdDomains>(`/organizations/${device.organizationId}/ad/domains`, undefined, { staleTime: 30_000 });
  const [status, setStatus] = useState<DirectoryStatus | null>(null);
  const [health, setHealth] = useState<DirectoryHealth | null>(null);
  const [readAt, setReadAt] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [generation, setGeneration] = useState(0);

  // The domain's writes go through one controller; when it is another computer, this view only reads.
  const mine = domains.data?.domains.find((x) => x.controllers.some((c) => c.deviceId === device.id));
  const chosen = mine?.controllers.find((c) => c.deviceId === mine.chosen);
  const other = chosen && chosen.deviceId !== device.id ? chosen : null;

  const refresh = useCallback(async () => {
    setBusy(true);
    setError(null);
    setFailure(null);
    try {
      const s = await run<DirectoryStatus>("status");
      if (!s.ok) {
        setStatus(null);
        setFailure(FAILURES[s.failure?.code ?? ""] ?? s.failure?.message ?? "The controller did not answer.");
        return;
      }
      setStatus(s.data ?? null);
      setReadAt(s.finishedAt);
      setGeneration((g) => g + 1);
      const h = await run<DirectoryHealth>("health_read");
      setHealth(h.ok ? (h.data ?? null) : null);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }, [run]);

  return (
    <ModuleTab name="Active Directory" asOf={status ? readAt : null} onRefresh={() => void refresh()} refreshing={busy} unavailable={failure ?? undefined}>
      <InlineError error={error} />
      {status && (
        <>
          <Alert tone="info">
            Changes are made through this controller, {status.controller}, and reach the others by directory replication, which can
            take a few moments. The directory&apos;s own audit log names this computer, not you; EasyRMM&apos;s audit log records who asked.
          </Alert>
          {status.readOnly && (
            <Alert tone="warn" title="Read-only domain controller">
              Nothing is changed through a read-only controller. Open the tab on a writable one.
            </Alert>
          )}
          <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-2">
            <Card title="Domain">
              <KeyValueList
                items={[
                  ["Domain", status.domain],
                  ["Forest", status.forest],
                  ["Domain level", status.domainMode],
                  ["Forest level", status.forestMode],
                  ["This controller", status.controller],
                  ["Operations master (PDC emulator)", status.pdcEmulator],
                  [
                    "Recycle Bin",
                    <Badge key="rb" tone={status.recycleBinEnabled ? "ok" : "warn"}>
                      {status.recycleBinEnabled ? "Enabled" : "Off: a deleted object is gone for good"}
                    </Badge>,
                  ],
                  [
                    "Password policy",
                    `At least ${status.passwordPolicy.minLength} characters${status.passwordPolicy.complexity ? ", complexity on" : ""}; ` +
                      (status.passwordPolicy.lockoutThreshold > 0
                        ? `locks out after ${status.passwordPolicy.lockoutThreshold} failed sign-ins`
                        : "no lockout"),
                  ],
                ]}
              />
            </Card>
            <Card title="Directory health">
              {health ? (
                <KeyValueList
                  items={[
                    ...health.checks.map((c): [string, React.ReactNode] => [
                      CHECK_LABEL[c.name] ?? c.name,
                      <span key={c.name} className="flex flex-wrap items-center gap-2">
                        <Badge tone={STATE[c.state].tone}>{STATE[c.state].label}</Badge>
                        <span className="text-xs text-muted">{c.detail}</span>
                      </span>,
                    ]),
                    ...(health.replication.failureCount > 0
                      ? ([
                          [
                            "Failing since",
                            health.replication.oldestFailureAt ? formatDateTime(health.replication.oldestFailureAt) : "Not reported",
                          ],
                        ] as [string, React.ReactNode][])
                      : []),
                  ]}
                />
              ) : (
                <p className="text-sm text-muted">The health checks have not answered.</p>
              )}
            </Card>
          </div>
          {other && (
            <Alert tone="warn" title="Changes go to another controller">
              This domain&apos;s changes are made through {other.name}. Open the Directory view there to change anything; this one only reads.{" "}
              <Link to={`/devices/${other.deviceId}?tab=roles`} className="text-accent underline">
                Go to {other.name}
              </Link>
            </Alert>
          )}
          <UsersCard key={`u${generation}`} deviceId={device.id} status={status} writable={!other} />
          <GroupsCard key={`g${generation}`} deviceId={device.id} canManage={can("ad.manage") && !status.readOnly && !other} recycleBin={status.recycleBinEnabled} />
          <ComputersCard key={`c${generation}`} deviceId={device.id} canManage={can("ad.manage") && !status.readOnly && !other} />
          {can("ad.view_sensitive") && <PrivilegedCard key={`p${generation}`} deviceId={device.id} />}
        </>
      )}
    </ModuleTab>
  );
}
