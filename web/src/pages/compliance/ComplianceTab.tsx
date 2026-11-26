import { useState } from "react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { ComplianceSettings, ComplianceSummary, FixSettings, FixTier } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, EmptyState, ErrorState, InlineError, Spinner, StatTile } from "../../components/ui";
import { formatRelative } from "../../lib/format";
import type { LevelTabProps } from "../organizations/levelTabs";
import { ComplianceScan } from "./ComplianceScan";
import { FixQueue } from "./FixQueue";
import { CmmcWorkspace } from "./cmmc/CmmcWorkspace";
import { FrameworkResults } from "./FrameworkResults";
import { TIERS } from "./complianceText";

/**
 * The organization's Compliance tab (ADR-0078, sections 6 and 7; ADR-0072): the counts from the latest stored results, the
 * frameworks' requirements, the fix queue, the scan, and the module's switch and approval setting. The tab is shown to
 * those who may view compliance; where the module is off it holds the switch and nothing else.
 */
export function ComplianceTab({ id }: LevelTabProps) {
  const { canAt } = useAuth();
  const settings = useApi<ComplianceSettings>(`/organizations/${id}/compliance/settings`);
  if (settings.isPending) return <Spinner />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  const s = settings.data;
  const canEdit = canAt("compliance.edit", { organizationId: id });
  if (!s.enabled) return <Off organizationId={id} settings={s} canEdit={canEdit} />;
  return <On organizationId={id} settings={s} canEdit={canEdit} canScan={canAt("compliance.scan", { organizationId: id })} />;
}

function useSwitch(organizationId: string, settings: ComplianceSettings) {
  const toast = useToast();
  return useApiMutation((enabled: boolean) => api.put<ComplianceSettings>(`/organizations/${organizationId}/compliance/settings`, { ...settings, enabled }), {
    invalidate: [`/organizations/${organizationId}/compliance`, "/devices"],
    onSuccess: (r) => toast.success(r.enabled ? "Compliance checks are on." : "Compliance checks are off."),
  });
}

function Off({ organizationId, settings, canEdit }: { organizationId: string; settings: ComplianceSettings; canEdit: boolean }) {
  const turn = useSwitch(organizationId, settings);
  return (
    <Card title="Compliance">
      <EmptyState
        title="Compliance checks are off for this organization"
        action={
          canEdit ? (
            <Button variant="primary" loading={turn.isPending} onClick={() => turn.mutate(true)}>
              Turn on compliance checks
            </Button>
          ) : undefined
        }
      >
        When they are on, a scan reads what the hardening checks found on each computer and shows which controls meet, which do not, and which could not be told. Nothing runs
        on a computer until you start a scan.
      </EmptyState>
      <InlineError error={turn.error} />
    </Card>
  );
}

function On({ organizationId, settings, canEdit, canScan }: { organizationId: string; settings: ComplianceSettings; canEdit: boolean; canScan: boolean }) {
  const summary = useApi<ComplianceSummary>(`/organizations/${organizationId}/compliance/summary`, undefined, { refetchInterval: 60_000 });
  const turn = useSwitch(organizationId, settings);
  const sm = summary.data;
  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatTile label="Computers with results" value={sm?.devices ?? "…"} />
        <StatTile label="Controls that meet" value={sm?.meets ?? "…"} />
        <StatTile label="Controls that do not meet" value={sm?.doesNotMeet ?? "…"} hint={sm ? `${sm.failingDevices} computer${sm.failingDevices === 1 ? "" : "s"}` : undefined} />
        <StatTile label="Cannot tell" value={sm ? sm.cannotTell + sm.stale : "…"} hint={sm && sm.stale > 0 ? `${sm.stale} are out of date` : undefined} />
        <StatTile label="Last scan" value={sm?.lastScan ? formatRelative(sm.lastScan) : "None yet"} />
      </div>
      {sm && <Alert tone="info">{sm.disclaimer}</Alert>}

      {canScan && (
        <Card title="Scan">
          <ComplianceScan organizationId={organizationId} />
        </Card>
      )}

      <Card title="Fix queue">
        <FixQueue organizationId={organizationId} />
      </Card>

      <Card title="Results by framework">
        <FrameworkResults organizationId={organizationId} />
      </Card>

      <CmmcWorkspace organizationId={organizationId} />

      {canEdit && <ApprovalSetting organizationId={organizationId} />}
      {canEdit && (
        <div className="flex justify-end">
          <Button variant="ghost" loading={turn.isPending} onClick={() => turn.mutate(false)}>
            Turn compliance checks off
          </Button>
        </div>
      )}
    </div>
  );
}

const ALL_TIERS: FixTier[] = ["T1", "T2", "T3"];

/** Which tiers of fix wait for a second person (section 6, rule 7). Off by default; the owner's rule is that the administrator agrees. */
function ApprovalSetting({ organizationId }: { organizationId: string }) {
  const toast = useToast();
  const current = useApi<FixSettings>(`/organizations/${organizationId}/compliance/fix-settings`);
  const save = useApiMutation((tiers: FixTier[]) => api.put<FixSettings>(`/organizations/${organizationId}/compliance/fix-settings`, { requireApproval: tiers }), {
    invalidate: [`/organizations/${organizationId}/compliance`],
    onSuccess: () => toast.success("Saved."),
  });
  const [local, setLocal] = useState<FixTier[] | null>(null);
  if (!current.data) return null;
  const tiers = local ?? current.data.requireApproval;
  return (
    <Card title="Approval">
      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm text-muted">A fix of these tiers waits for a second person, who holds the approval permission and is not the one who asked.</legend>
        {ALL_TIERS.map((t) => (
          <label key={t} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4 accent-accent"
              checked={tiers.includes(t)}
              onChange={(e) => setLocal(e.target.checked ? [...tiers, t] : tiers.filter((x) => x !== t))}
            />
            Require approval for {TIERS[t].label.toLowerCase()} fixes
          </label>
        ))}
      </fieldset>
      <div className="mt-3 flex justify-end">
        <Button disabled={local === null} loading={save.isPending} onClick={() => save.mutate(tiers)}>
          Save
        </Button>
      </div>
      <InlineError error={save.error} />
    </Card>
  );
}
