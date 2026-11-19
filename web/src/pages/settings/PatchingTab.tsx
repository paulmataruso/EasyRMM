import { Link } from "react-router";
import { ArrowLeft, ShieldOff } from "lucide-react";
import { useApi } from "../../api/hooks";
import type { PatchStatus, PatchTagList } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Button, buttonClasses, EmptyState, ErrorState, Segmented, SelectField, Spinner } from "../../components/ui";
import { useUrlState } from "../../lib/urlState";
import { AgentPackagesPanel } from "../patching/AgentPackages";
import { EngineAuditPanel } from "../patching/EngineAudit";
import { LifecyclePanel } from "../patching/Lifecycle";
import { PolicyPanel } from "../patching/PolicyEditor";
import { ReportSchedules } from "../patching/ReportSchedules";
import { ServerSettingsPanel } from "../patching/ServerSettings";
import { TagChip, TagsManager } from "../patching/Tags";

// Settings → Patching (one-product plan, C4): the default policy every organization starts from, and tags, whose
// policies apply to devices across organizations. Both are EasyPatch's server-wide settings, so only super
// administrators change them; others with patching see them, as they shape their own organizations' policies.
// Report schedules (C5) are each organization's, changed by those who configure its patching. EasyPatch's server
// settings, OS lifecycle, agent packages and audit log (C6) are server-wide too: super administrators change them.

type View = "default" | "tags" | "reports" | "server" | "lifecycle" | "packages" | "audit";

/** What a filter of one view means nothing to: cleared when the view changes. */
const VIEW_STATE = { tag: null, organizationId: null, area: null, from: null, to: null, page: null };

export function PatchingTab() {
  const url = useUrlState();
  const { can } = useAuth();
  const status = useApi<PatchStatus>("/patching", undefined, { staleTime: 60_000 });
  if (status.isPending) return <Spinner />;
  if (status.isError) return <ErrorState error={status.error} onRetry={() => void status.refetch()} />;
  if (!status.data.configured) {
    return (
      <EmptyState
        title="EasyPatch is not set up"
        icon={<ShieldOff className="size-8" aria-hidden />}
        action={
          can("settings.manage") ? (
            <Link to="/settings?tab=easypatch" className={buttonClasses("primary")}>
              Set up EasyPatch
            </Link>
          ) : undefined
        }
      >
        Policies, tags, report schedules and EasyPatch&apos;s own settings come with EasyPatch, which patches your devices.
      </EmptyState>
    );
  }
  const options: { value: View; label: string }[] = [
    { value: "default", label: "Default policy" },
    { value: "tags", label: "Tags" },
    ...(can("report.view") ? [{ value: "reports" as const, label: "Report schedules" }] : []),
    { value: "server", label: "Server" },
    { value: "lifecycle", label: "OS lifecycle" },
    { value: "packages", label: "Agent packages" },
    ...(can("audit.view") && can("patch.view") ? [{ value: "audit" as const, label: "Audit log" }] : []),
  ];
  const view = options.find((o) => o.value === url.get("view"))?.value ?? "default";
  const choose = (v: View) => url.set({ view: v === "default" ? null : v, ...VIEW_STATE });
  const tag = url.get("tag");
  return (
    <div className="flex flex-col gap-4">
      {/* Seven views do not fit a phone's width side by side: there, a list. */}
      <SelectField label="Show" className="max-w-64 md:hidden" value={view} onChange={(e) => choose(e.target.value as View)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </SelectField>
      <div className="hidden md:block">
        <Segmented label="Patching settings" options={options} value={view} onChange={choose} />
      </div>
      {view === "default" && <PolicyPanel level="default" />}
      {view === "tags" && !tag && <TagsManager onPolicy={(t) => url.set({ tag: t.id })} />}
      {view === "tags" && tag && <TagPolicy id={tag} onBack={() => url.set({ tag: null })} />}
      {view === "reports" && <ReportSchedules bundled={status.data.bundled} />}
      {view === "server" && <ServerSettingsPanel />}
      {view === "lifecycle" && <LifecyclePanel />}
      {view === "packages" && <AgentPackagesPanel />}
      {view === "audit" && <EngineAuditPanel />}
    </div>
  );
}

function TagPolicy({ id, onBack }: { id: string; onBack: () => void }) {
  const list = useApi<PatchTagList>("/patching/tags");
  const tag = list.data?.items.find((t) => t.id === id);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <Button size="sm" variant="ghost" icon={<ArrowLeft className="size-4" aria-hidden />} onClick={onBack}>
          All tags
        </Button>
        {tag && (
          <span className="flex items-center gap-2 text-sm">
            <TagChip tag={tag} />
            <span className="text-muted">Priority {tag.priority}</span>
          </span>
        )}
      </div>
      <PolicyPanel level="tag" id={id} />
    </div>
  );
}
