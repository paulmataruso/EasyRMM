import { Link } from "react-router";
import { ArrowLeft, ShieldOff } from "lucide-react";
import { useApi } from "../../api/hooks";
import type { PatchStatus, PatchTagList } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Button, buttonClasses, EmptyState, ErrorState, Segmented, Spinner } from "../../components/ui";
import { useUrlState } from "../../lib/urlState";
import { PolicyPanel } from "../patching/PolicyEditor";
import { ReportSchedules } from "../patching/ReportSchedules";
import { TagChip, TagsManager } from "../patching/Tags";

// Settings → Patching (one-product plan, C4): the default policy every organization starts from, and tags, whose
// policies apply to devices across organizations. Both are EasyPatch's server-wide settings, so only super
// administrators change them; others with patching see them, as they shape their own organizations' policies.
// Report schedules (C5) are each organization's, changed by those who configure its patching.

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
        Policies, tags and report schedules come with EasyPatch, which patches your devices.
      </EmptyState>
    );
  }
  const requested = url.get("view");
  const view = requested === "tags" || requested === "reports" ? requested : "default";
  const tag = url.get("tag");
  return (
    <div className="flex flex-col gap-4">
      <Segmented
        label="Patching settings"
        className="self-start"
        options={[
          { value: "default", label: "Default policy" },
          { value: "tags", label: "Tags" },
          ...(can("report.view") ? [{ value: "reports" as const, label: "Report schedules" }] : []),
        ]}
        value={view}
        onChange={(v) => url.set({ view: v === "default" ? null : v, tag: null })}
      />
      {view === "default" && <PolicyPanel level="default" />}
      {view === "tags" && !tag && <TagsManager onPolicy={(t) => url.set({ tag: t.id })} />}
      {view === "tags" && tag && <TagPolicy id={tag} onBack={() => url.set({ tag: null })} />}
      {view === "reports" && <ReportSchedules bundled={status.data.bundled} />}
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
