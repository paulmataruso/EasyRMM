import { ArrowLeft } from "lucide-react";
import { useApi } from "../../api/hooks";
import type { PatchStatus, PatchTagList } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Button, ErrorState, Segmented, SelectField, Spinner } from "../../components/ui";
import { useUrlState } from "../../lib/urlState";
import { EasyPatchTab } from "./EasyPatchTab";
import { AgentPackagesPanel } from "../patching/AgentPackages";
import { AlertRulesPanel } from "../patching/AlertRules";
import { EngineAuditPanel } from "../patching/EngineAudit";
import { LifecyclePanel } from "../patching/Lifecycle";
import { NotificationsPanel } from "../patching/Notifications";
import { NoPatchingEngine } from "../patching/patchText";
import { PolicyPanel } from "../patching/PolicyEditor";
import { ServerSettingsPanel } from "../patching/ServerSettings";
import { TagChip, TagsManager } from "../patching/Tags";

// Settings → Patching: the default policy every organization starts from, and tags, whose
// policies apply to devices across organizations. Both are EasyPatch's server-wide settings, so only super
// administrators change them; others with patching see them, as they shape their own organizations' policies.
// Report schedules and the automatic agent install are each organization's, on its page (ADR-0072). EasyPatch's server
// settings, OS lifecycle, agent packages and audit log are server-wide too: super administrators change them.
// Alert rules and notification channels are server-wide and send alerts about every organization, so only super
// administrators see them.

type View = "engine" | "default" | "tags" | "server" | "lifecycle" | "packages" | "rules" | "notifications" | "audit";

/** What a filter of one view means nothing to: cleared when the view changes. */
const VIEW_STATE = { tag: null, organizationId: null, area: null, from: null, to: null, page: null };

export function PatchingTab() {
  const url = useUrlState();
  const { can, canGlobal } = useAuth();
  const status = useApi<PatchStatus>("/patching", undefined, { staleTime: 60_000 });
  const engine = can("settings.manage");
  if (status.isPending) return <Spinner />;
  if (status.isError) return <ErrorState error={status.error} onRetry={() => void status.refetch()} />;
  if (!status.data.configured) return <NoPatchingEngine />;
  const options: { value: View; label: string }[] = [
    { value: "default", label: "Default policy" },
    { value: "tags", label: "Tags" },
    ...(engine ? [{ value: "engine" as const, label: "Engine" }] : []),
    { value: "server", label: "Server" },
    { value: "lifecycle", label: "OS lifecycle" },
    { value: "packages", label: "Agent packages" },
    ...(canGlobal("patch.configure")
      ? [
          { value: "rules" as const, label: "Alert rules" },
          { value: "notifications" as const, label: "Notifications" },
        ]
      : []),
    ...(can("audit.view") && can("patch.view") ? [{ value: "audit" as const, label: "Audit log" }] : []),
  ];
  const view = options.find((o) => o.value === url.get("view"))?.value ?? "default";
  const choose = (v: View) => url.set({ view: v === "default" ? null : v, ...VIEW_STATE });
  const tag = url.get("tag");
  return (
    <div className="flex flex-col gap-4">
      {/* Several views do not fit a narrow screen side by side: there, a list. */}
      <SelectField label="Show" className="max-w-64 xl:hidden" value={view} onChange={(e) => choose(e.target.value as View)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </SelectField>
      <div className="hidden xl:block">
        <Segmented label="Patching settings" options={options} value={view} onChange={choose} />
      </div>
      {view === "engine" && <EasyPatchTab />}
      {view === "default" && <PolicyPanel level="default" />}
      {view === "tags" && !tag && <TagsManager onPolicy={(t) => url.set({ tag: t.id })} />}
      {view === "tags" && tag && <TagPolicy id={tag} onBack={() => url.set({ tag: null })} />}
      {view === "server" && <ServerSettingsPanel />}
      {view === "lifecycle" && <LifecyclePanel />}
      {view === "packages" && <AgentPackagesPanel />}
      {view === "rules" && <AlertRulesPanel />}
      {view === "notifications" && <NotificationsPanel />}
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
