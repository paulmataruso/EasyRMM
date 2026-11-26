import type { ComponentType, ReactNode } from "react";
import { useApi } from "../../api/hooks";
import type { PatchStatus, Permission } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Tabs } from "../../components/ui";
import { useUrlState } from "../../lib/urlState";
import { ContactsTab } from "./tabs/ContactsTab";
import { InstallTab } from "./tabs/InstallTab";
import { PatchPolicyTab } from "./tabs/PatchPolicyTab";
import { PeopleTab } from "./tabs/PeopleTab";

// The tab strip of the organization and site pages (ADR-0072, slice S4). A tab is one line in LEVEL_TABS: its id (the
// `?tab=` value), label, the permission it needs, the levels it appears at and its component. Order in the array is the
// order on screen, the same at every level. A tab that does not apply is hidden, never greyed.

export type Level = "organization" | "site" | "group";

/** What a tab component receives: the selection it shows. Fetch your own data; the hooks share the page's cache. */
export interface LevelTabProps {
  level: Level;
  id: string;
}

/** What decides whether a tab shows for the selection. */
export interface LevelContext {
  level: Level;
  /** Whether the viewer holds the permission at this selection's level (`useAuth().canAt` for the page's organization or site). */
  can: (permission: Permission) => boolean;
  /** The patching engine is set up (ADR-0030). */
  patchingConfigured: boolean;
}

export interface LevelTab {
  id: string;
  label: string;
  /** The permission checked at the selection's level; null for a tab everyone who can open the page sees. */
  permission: Permission | null;
  levels: readonly Level[];
  /** Extra condition beyond the permission. */
  when?: (ctx: LevelContext) => boolean;
  /** Absent only for Overview, whose content each page passes to LevelTabs as `overview`. */
  component?: ComponentType<LevelTabProps>;
}

/** The registry. S5 to S8 each add one line here and one file under ./tabs. */
export const LEVEL_TABS: readonly LevelTab[] = [
  {
    id: "overview",
    label: "Overview",
    permission: null,
    levels: ["organization", "site"],
  },
  {
    id: "contacts",
    label: "Contacts",
    permission: "doc.view",
    levels: ["organization"],
    component: ContactsTab,
  },
  {
    id: "people",
    label: "People",
    permission: "user.view",
    levels: ["organization"],
    component: PeopleTab,
  },
  {
    id: "patch-policy",
    label: "Patch policy",
    permission: "patch.view",
    levels: ["organization", "site"],
    when: (ctx) => ctx.patchingConfigured,
    component: PatchPolicyTab,
  },
  {
    id: "install",
    label: "Install",
    permission: "enrollment.manage",
    levels: ["organization", "site"],
    component: InstallTab,
  },
];

/** The tabs shown at a level, in order. */
export function visibleTabs(
  ctx: LevelContext,
  tabs: readonly LevelTab[] = LEVEL_TABS,
): LevelTab[] {
  return tabs.filter(
    (t) =>
      t.levels.includes(ctx.level) &&
      (t.permission === null || ctx.can(t.permission)) &&
      (t.when?.(ctx) ?? true),
  );
}

/** The active tab: `?tab=` when it is shown at this level, otherwise Overview. */
export function activeTab(
  visible: readonly LevelTab[],
  param: string | null,
): LevelTab {
  return visible.find((t) => t.id === param) ?? visible[0]!;
}

/** The strip and the active tab's panel. `overview` is the page's own content. */
export function LevelTabs({
  level,
  id,
  organizationId,
  overview,
}: {
  level: Level;
  id: string;
  /** The organization the site or group belongs to; an organization page can leave it out. */
  organizationId?: string;
  overview: ReactNode;
}) {
  const auth = useAuth();
  // Each tab's permission is checked where the page is, not in any scope.
  const can = (p: Permission) =>
    auth.canAt(p, {
      organizationId: organizationId ?? id,
      siteId: level === "site" ? id : undefined,
    });
  const url = useUrlState();
  // The same query the pages use for their Patch all button, so it is one request.
  const patching = useApi<PatchStatus>(
    can("patch.view") ? "/patching" : null,
    undefined,
    { staleTime: 60_000 },
  );
  const visible = visibleTabs({
    level,
    can,
    patchingConfigured: patching.data?.configured === true,
  });
  const active = activeTab(visible, url.get("tab"));
  const Component = active.component;
  return (
    <>
      {visible.some((t) => t.id !== "overview") && (
        <Tabs
          tabs={visible.map((t) => ({ id: t.id, label: t.label }))}
          active={active.id}
          onChange={(t) =>
            url.set({ tab: t === "overview" ? null : t, after: null })
          }
        />
      )}
      {Component ? (
        <div role="tabpanel" aria-labelledby={`tab-${active.id}`}>
          <Component level={level} id={id} />
        </div>
      ) : (
        overview
      )}
    </>
  );
}
