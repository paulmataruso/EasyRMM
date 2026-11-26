import { useState } from "react";
import { api } from "../../../api/client";
import { useApi, useApiMutation } from "../../../api/hooks";
import type {
  DefenderStatus,
  Device,
  WinmodResult,
  WinmodRun,
} from "../../../api/types";
import { Badge, Card, InlineError, KeyValueList, type Tone } from "../../../components/ui";
import { formatDateTime } from "../../../lib/format";
import { ModuleTab } from "./ModuleTab";
import { useAuth } from "../../../auth/AuthContext";
import { AsrPanel } from "../security/AsrPanel";
import { CfaPanel } from "../security/CfaPanel";
import { EventsPanel } from "../security/EventsPanel";
import { ExclusionsPanel } from "../security/ExclusionsPanel";
import { ProtectionPanel } from "../security/ProtectionPanel";
import { ScansPanel } from "../security/ScansPanel";
import { ThreatsPanel } from "../security/ThreatsPanel";
import { TAMPER_NOTE } from "../security/text";

const FINISHED = new Set(["succeeded", "failed", "timed_out", "canceled", "expired", "lost"]);

/** Switches as words; null is "the computer does not say", which is not the same as off. */
function onOff(v: boolean | null): { label: string; tone: Tone } {
  if (v === null) return { label: "Not reported", tone: "neutral" };
  return v ? { label: "On", tone: "ok" } : { label: "Off", tone: "danger" };
}

const SWITCHES: [keyof DefenderStatus, string][] = [
  ["antivirusEnabled", "Antivirus"],
  ["antispywareEnabled", "Antispyware"],
  ["realTimeProtectionEnabled", "Real-time protection"],
  ["behaviorMonitorEnabled", "Behavior monitoring"],
  ["ioavProtectionEnabled", "Downloaded files and attachments"],
  ["onAccessProtectionEnabled", "On-access protection"],
  ["nisEnabled", "Network inspection"],
  ["tamperProtected", "Tamper protection"],
];

const FAILURES: Record<string, string> = {
  module_missing: "Microsoft Defender is not installed on this computer.",
};

function age(days: number | null): string {
  if (days === null) return "Never";
  return days === 0 ? "Today" : days === 1 ? "1 day ago" : `${days} days ago`;
}

/** The device page's "Security" tab: the Defender module (ADR-0074), one panel per area, each read on request. */
export function SecurityTab({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const scope = { organizationId: device.organizationId, siteId: device.siteId };
  const canManage = canAt("defender.manage", scope);
  const canWeaken = canAt("defender.weaken", scope);
  const canSeeSensitive = canAt("defender.view_sensitive", scope);
  const [runId, setRunId] = useState<string | null>(null);
  const start = useApiMutation((_: void) =>
    api.post<WinmodRun>(`/devices/${device.id}/winmod/defender.status`, {}),
  );
  const run = useApi<WinmodResult>(runId ? `/winmod/runs/${runId}` : null, undefined, {
    refetchInterval: (r) => (r && (FINISHED.has(r.status) || r.ok !== undefined) ? false : 1500),
  });
  const result = run.data;
  const waiting = start.isPending || (runId !== null && !run.error && !(result && (FINISHED.has(result.status) || result.ok !== undefined)));
  const refresh = () =>
    start.mutate(undefined, { onSuccess: (r) => setRunId(r.runId) });
  const status = result?.ok ? (result.data as DefenderStatus) : null;
  const failure = result && result.ok === false ? result.failure : null;
  const lost = result && result.ok === undefined && FINISHED.has(result.status);
  return (
    <ModuleTab
      name="Microsoft Defender"
      asOf={status ? result?.finishedAt ?? null : null}
      onRefresh={refresh}
      refreshing={waiting}
      unavailable={
        failure
          ? (FAILURES[failure.code] ?? failure.message)
          : lost
            ? (result?.error ?? `The read ended as ${result?.status}.`)
            : undefined
      }
    >
      <InlineError error={start.error ?? run.error} />
      {status && (
        <>
          <Card title="Protection">
            <KeyValueList
              items={SWITCHES.map(([k, label]) => {
                const s = onOff(status[k] as boolean | null);
                return [label, <Badge key={k} tone={s.tone}>{s.label}</Badge>];
              })}
            />
          </Card>
          <Card title="Tamper Protection">
            <p className="text-sm text-muted">
              {status.tamperProtected === null ? "The computer does not say whether Tamper Protection is on. " : status.tamperProtected ? "Tamper Protection is on. " : "Tamper Protection is off. "}
              It is shown here and not changed here. {TAMPER_NOTE}
            </p>
          </Card>
          <Card title="Engine and signatures">
            <KeyValueList
              items={[
                ["Mode", status.runningMode || "—"],
                ["Engine", status.engineVersion || "—"],
                ["Product", status.productVersion || "—"],
                ["Signatures", status.signatureVersion || "—"],
                [
                  "Signatures updated",
                  status.signatureUpdatedAt
                    ? `${formatDateTime(status.signatureUpdatedAt)} (${age(status.signatureAgeDays)})`
                    : "Never",
                ],
                ["Last quick scan", age(status.quickScanAgeDays)],
                ["Last full scan", age(status.fullScanAgeDays)],
              ]}
            />
          </Card>
        </>
      )}
      {canManage && <ScansPanel device={device} />}
      <ProtectionPanel device={device} canManage={canManage} canWeaken={canWeaken} />
      <AsrPanel device={device} canManage={canManage} canWeaken={canWeaken} />
      <CfaPanel device={device} canManage={canManage} canWeaken={canWeaken} />
      {canSeeSensitive && <ExclusionsPanel device={device} canWeaken={canWeaken} canSeeSensitive={canSeeSensitive} />}
      <ThreatsPanel device={device} canManage={canManage} canWeaken={canWeaken} canSeeSensitive={canSeeSensitive} />
      <EventsPanel device={device} />
    </ModuleTab>
  );
}
