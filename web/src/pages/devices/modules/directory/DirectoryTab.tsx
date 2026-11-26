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
import { SkeletonKeyValue, SkeletonTable } from "../skeletons";
import { useWinmodRead } from "../winmod";

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
 * controller this page is for, by itself when the tab opens; the last result shows at once. Nothing is copied into EasyRMM. The help-desk actions (unlock, enable, disable,
 * reset a password) are on the users; what the person may do follows their permissions, and the server asks again.
 */
export function DirectoryTab({ device }: { device: Device }) {
  const { can } = useAuth();
  const domains = useApi<AdDomains>(`/organizations/${device.organizationId}/ad/domains`, undefined, { staleTime: 30_000 });
  // Both reads start together when the tab opens; each shows its stored result at once and is kept fresh while the tab is open.
  const statusRead = useWinmodRead<DirectoryStatus>(device.id, "active_directory.status", {});
  const healthRead = useWinmodRead<DirectoryHealth>(device.id, "active_directory.health_read", {});
  const status = statusRead.data?.data ?? null;
  const health = healthRead.data?.data ?? null;
  const failureCode = statusRead.data?.failure;
  const failure = failureCode ? (FAILURES[failureCode.code] ?? failureCode.message ?? "The controller did not answer.") : (statusRead.data && !status ? statusRead.data.lost : null);
  const error = statusRead.error;
  const loading = !status && !failure && !error;

  // The domain's writes go through one controller; when it is another computer, this view only reads.
  const mine = domains.data?.domains.find((x) => x.controllers.some((c) => c.deviceId === device.id));
  const chosen = mine?.controllers.find((c) => c.deviceId === mine.chosen);
  const other = chosen && chosen.deviceId !== device.id ? chosen : null;

  return (
    <ModuleTab
      name="Active Directory"
      asOf={status ? (statusRead.data?.finishedAt ?? null) : null}
      refreshing={statusRead.isFetching || healthRead.isFetching}
      loading={loading}
      skeleton={
        <>
          <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-2">
            <SkeletonKeyValue title="Domain" rows={8} />
            <SkeletonKeyValue title="Directory health" rows={4} />
          </div>
          <SkeletonTable title="Users" columns={4} rows={5} toolbar />
          <SkeletonTable title="Groups" columns={4} rows={4} />
        </>
      }
      offline={statusRead.data?.offline}
      unavailable={failure ?? undefined}
    >
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
                <p className="text-sm text-muted">{healthRead.data === undefined ? "Reading the health checks…" : "The health checks have not answered."}</p>
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
          <UsersCard deviceId={device.id} status={status} writable={!other} />
          <GroupsCard deviceId={device.id} canManage={can("ad.manage") && !status.readOnly && !other} recycleBin={status.recycleBinEnabled} />
          <ComputersCard deviceId={device.id} canManage={can("ad.manage") && !status.readOnly && !other} />
          {can("ad.view_sensitive") && <PrivilegedCard deviceId={device.id} />}
        </>
      )}
    </ModuleTab>
  );
}
