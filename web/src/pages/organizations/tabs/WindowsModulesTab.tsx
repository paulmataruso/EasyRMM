import { api } from "../../../api/client";
import { useApi, useApiMutation } from "../../../api/hooks";
import type { WindowsModuleSetting } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import {
  Button,
  Card,
  ErrorState,
  InlineError,
  Spinner,
} from "../../../components/ui";
import type { LevelTabProps } from "../levelTabs";

/** The path of a level's toggles (ADR-0073). */
export function modulesPath(
  level: "organization" | "site",
  id: string,
): string {
  return `/${level === "site" ? "sites" : "organizations"}/${id}/windows-modules`;
}

/**
 * The "Windows modules" card (ADR-0073, section 2): which Windows management modules are on for an organization, with an
 * optional override per site. A module that is off sends no job, schedules no read and evaluates no alert; its tab is
 * hidden. Turning it on again is immediate. Whether a device offers a module still depends on its detected roles.
 */
export function WindowsModulesTab({ level, id }: LevelTabProps) {
  return level === "group" ? null : <ModulesCard level={level} id={id} />;
}

function ModulesCard({
  level,
  id,
}: {
  level: "organization" | "site";
  id: string;
}) {
  const { can } = useAuth();
  const toast = useToast();
  const path = modulesPath(level, id);
  const canManage = can(level === "site" ? "site.manage" : "org.manage");
  const list = useApi<WindowsModuleSetting[]>(path);
  const set = useApiMutation(
    (v: { module: string; enabled: boolean }) =>
      api.put(`${path}/${v.module}`, { enabled: v.enabled }),
    { invalidate: [path, "/audit"], onSuccess: () => toast.success("Saved.") },
  );
  const clear = useApiMutation(
    (module: string) => api.del(`${path}/${module}`),
    {
      invalidate: [path, "/audit"],
      onSuccess: () =>
        toast.success("This site follows its organization again."),
    },
  );
  return (
    <Card title="Windows modules">
      <div className="flex max-w-2xl flex-col gap-3.5">
        <p className="text-sm text-muted">
          {level === "site"
            ? "A module set here overrides the organization's setting for this site."
            : "These apply to every site unless a site sets its own."}{" "}
          A module that is off sends no job, schedules no read and evaluates no
          alert, and its tab is hidden. A device offers a module only when its
          role was detected.
        </p>
        {list.isLoading ? (
          <Spinner />
        ) : list.error ? (
          <ErrorState
            error={list.error}
            onRetry={() => void list.refetch()}
            compact
          />
        ) : (
          <ul className="divide-y divide-border rounded border border-border">
            {(list.data ?? []).map((m) => (
              <li
                key={m.module}
                className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2"
              >
                <label className="flex min-w-0 flex-1 items-center gap-2.5 text-sm">
                  <input
                    type="checkbox"
                    className="size-4 accent-accent"
                    checked={m.enabled}
                    disabled={!canManage || set.isPending}
                    onChange={(e) =>
                      set.mutate({
                        module: m.module,
                        enabled: e.target.checked,
                      })
                    }
                  />
                  <span>{m.label}</span>
                </label>
                <span className="text-xs text-muted">{status(level, m)}</span>
                {level === "site" && m.override !== null && canManage && (
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => clear.mutate(m.module)}
                    loading={clear.isPending && clear.variables === m.module}
                  >
                    Use the organization's setting
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        <InlineError error={set.error ?? clear.error} />
      </div>
    </Card>
  );
}

function status(
  level: "organization" | "site",
  m: WindowsModuleSetting,
): string {
  if (m.override === null)
    return level === "site" ? "Follows the organization" : "Default";
  return level === "site" ? "Set for this site" : "Set";
}
