import type { DefenderStatus, Device } from "../../../api/types";
import { Badge, Card, InlineError, KeyValueList, type Tone } from "../../../components/ui";
import { formatDateTime } from "../../../lib/format";
import { ModuleTab } from "./ModuleTab";
import { Loading, SkeletonKeyValue } from "./skeletons";
import { useWinmodRead } from "./winmod";
import { useAuth } from "../../../auth/AuthContext";
import { AsrPanel } from "../security/AsrPanel";
import { CfaPanel } from "../security/CfaPanel";
import { EventsPanel } from "../security/EventsPanel";
import { ExclusionsPanel } from "../security/ExclusionsPanel";
import { ProtectionPanel } from "../security/ProtectionPanel";
import { ScansPanel } from "../security/ScansPanel";
import { ThreatsPanel } from "../security/ThreatsPanel";
import { TAMPER_NOTE } from "../security/text";

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

/** The device page's "Security" tab: the Defender module (ADR-0074), one panel per area, each read by itself when the tab opens. */
export function SecurityTab({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const scope = { organizationId: device.organizationId, siteId: device.siteId };
  const canManage = canAt("defender.manage", scope);
  const canWeaken = canAt("defender.weaken", scope);
  const canSeeSensitive = canAt("defender.view_sensitive", scope);
  const read = useWinmodRead<DefenderStatus>(device.id, "defender.status", {});
  const status = read.data?.data ?? null;
  const failure = read.data?.failure ?? null;
  const lost = read.data?.lost ?? null;
  const loading = !status && !failure && !lost && !read.error;
  return (
    <ModuleTab
      name="Microsoft Defender"
      asOf={status ? (read.data?.finishedAt ?? null) : null}
      refreshing={read.isFetching}
      loading={loading}
      offline={read.data?.offline}
      unavailable={failure ? (FAILURES[failure.code] ?? failure.message) : (lost ?? undefined)}
    >
      <InlineError error={read.error} />
      {loading && (
        <Loading name="Microsoft Defender">
          <SkeletonKeyValue title="Protection" rows={8} />
          <SkeletonKeyValue title="Engine and signatures" rows={7} />
        </Loading>
      )}
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
