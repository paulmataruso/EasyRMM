import { Link } from "react-router";
import { useApi, useList } from "../../api/hooks";
import type { ComplianceSettings, Device, DeviceComplianceResult } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Alert, Badge, Card, EmptyState, ErrorState, Spinner, TableWrap } from "../../components/ui";
import { formatRelative } from "../../lib/format";
import { ComplianceScan } from "./ComplianceScan";
import { FixQueue } from "./FixQueue";
import { FrameworkResults } from "./FrameworkResults";
import { RESULT_WORDS } from "./complianceText";

/** Whether the device page shows its Compliance tab: the module is on for the organization and the viewer may see its results (ADR-0072: hidden, never greyed). */
export function useComplianceEnabled(d: Device | undefined): boolean {
  const { canAt } = useAuth();
  const may = d ? canAt("compliance.view", { organizationId: d.organizationId, siteId: d.siteId }) : false;
  const settings = useApi<ComplianceSettings>(d && may && d.agent ? `/organizations/${d.organizationId}/compliance/settings` : null, undefined, { staleTime: 60_000 });
  return may && settings.data?.enabled === true;
}

/**
 * A computer's compliance (ADR-0078, section 7): its controls by what a scan found, the requirements of a framework for
 * this computer alone, the fix items for it, and Scan now. Results are stored ones; nothing here asks the computer until
 * a scan is started.
 */
export function DeviceCompliance({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const results = useList<DeviceComplianceResult>(`/devices/${device.id}/compliance`, undefined, { refetchInterval: 30_000 });
  const org = device.organizationId;
  const canScan = canAt("compliance.scan", { organizationId: org, siteId: device.siteId });
  const byWord = (w: string) => results.items.filter((r) => r.word === w);
  const latest = results.items.reduce<string | null>((acc, r) => (acc === null || r.checkedAt > acc ? r.checkedAt : acc), null);
  return (
    <div className="flex flex-col gap-5">
      {canScan && (
        <Card title="Scan">
          <ComplianceScan organizationId={org} deviceId={device.id} platform={device.platform} />
        </Card>
      )}
      <Card title="Fix items">
        <FixQueue organizationId={org} deviceId={device.id} siteId={device.siteId} />
      </Card>
      <Card title="Controls" padded={false}>
        {results.isPending ? (
          <Spinner />
        ) : results.isError ? (
          <ErrorState error={results.error} onRetry={() => void results.refetch()} compact />
        ) : results.items.length === 0 ? (
          <EmptyState title="No scan has read this computer yet" compact>
            Start a scan above. The hardening checks it reads can also be run from the <Link className="text-accent underline" to={`/devices/${device.id}?tab=hardening`}>Hardening tab</Link>.
          </EmptyState>
        ) : (
          <>
            <p className="px-4 pt-3 text-sm text-muted">
              {byWord("meets").length} meet, {byWord("does not meet").length} do not meet, {byWord("cannot tell").length} cannot be told. Last read {formatRelative(latest)}.
            </p>
            <TableWrap className="rounded-none border-0">
              <table className="w-full text-left text-sm" aria-label="Controls">
                <thead>
                  <tr className="text-xs text-muted">
                    <th className="px-4 py-2 font-medium">Control</th>
                    <th className="px-2 py-2 font-medium">Result</th>
                    <th className="px-2 py-2 font-medium">Read</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {[...results.items]
                    .sort((a, b) => Number(a.word === "meets") - Number(b.word === "meets") || a.controlId.localeCompare(b.controlId))
                    .map((r) => (
                      <tr key={r.controlId}>
                        <td className="px-4 py-2">{r.title || r.controlId}</td>
                        <td className="px-2 py-2">
                          <Badge tone={RESULT_WORDS[r.word]?.tone ?? "neutral"}>{RESULT_WORDS[r.word]?.label ?? r.word}</Badge>
                          {r.state === "stale" && <span className="ml-1 text-xs text-muted">out of date</span>}
                        </td>
                        <td className="px-2 py-2 text-muted">{formatRelative(r.checkedAt)}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </TableWrap>
          </>
        )}
      </Card>
      <Card title="Requirements for this computer">
        <FrameworkResults organizationId={org} deviceId={device.id} />
      </Card>
      <Alert tone="info">Assessment aid. It reports what EasyRMM could check on this computer. It is not an assessment, an audit, a certification or legal advice.</Alert>
    </div>
  );
}
