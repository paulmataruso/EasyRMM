import { useState } from "react";
import { BellRing, Plus } from "lucide-react";
import { useList } from "../../api/hooks";
import type { AlertPolicy } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Badge, Button, EmptyState, ErrorState, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatNumber, plural } from "../../lib/format";
import { conditionText, policyScope, SeverityBadge } from "./alertText";
import { PolicyDialog, useCanWritePolicies, type PolicyScopeFixed } from "./PolicyDialog";

/** Whose policies a table lists: the shared ones, or one organization's or one site's. */
export type PolicyScope =
  | { level: "shared" }
  | { level: "organization"; organizationId: string; name: string }
  | { level: "site"; organizationId: string; siteId: string; name: string };

const fixedOf = (s: PolicyScope): PolicyScopeFixed =>
  s.level === "shared"
    ? { level: "shared", organizationId: null, siteId: null, name: "Every device" }
    : { level: s.level, organizationId: s.organizationId, siteId: s.level === "site" ? s.siteId : null, name: s.name };

/**
 * The policies of one scope with their dialog (ADR-0072): Settings lists the shared ones, an organization's page its own,
 * a site's page its own. Changing needs monitoring.manage; the server decides per policy (`canEdit`).
 */
export function PolicyTable({ scope }: { scope: PolicyScope }) {
  const canWrite = useCanWritePolicies();
  const { session } = useAuth();
  const [editing, setEditing] = useState<AlertPolicy | "new" | null>(null);
  const onEdit = setEditing;
  const all = useList<AlertPolicy>("/alert-policies", scope.level === "shared" ? undefined : { organizationId: scope.organizationId }, { keepPrevious: true });
  const items = all.items.filter((p) => (scope.level === "shared" ? p.level === "shared" : scope.level === "site" ? p.siteId === scope.siteId : p.level === "organization" && p.organizationId === scope.organizationId));
  const list = { ...all, items };
  const canAdd = scope.level === "shared" ? session?.isSuperAdmin === true : canWrite;
  const anyEditable = list.items.some((p) => p.canEdit);

  return (
    <>
      {canAdd && list.items.length > 0 && (
        <Toolbar>
          <Button variant="primary" onClick={() => onEdit("new")}>
            <Plus className="size-4" aria-hidden />
            New policy
          </Button>
        </Toolbar>
      )}
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.items.length === 0 ? (
        <EmptyState
          title="No alert policies"
          icon={<BellRing className="size-8" aria-hidden />}
          action={
            canAdd ? (
              <Button variant="primary" onClick={() => onEdit("new")}>
                <Plus className="size-4" aria-hidden />
                New policy
              </Button>
            ) : undefined
          }
        >
          {canAdd
            ? "Add a policy to be alerted when devices go offline or run short of processor, memory or disk."
            : "Without policies, nothing raises an alert. An administrator adds them."}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Policy</th>
                  <th className="hidden md:table-cell">Condition</th>
                  <th className="hidden lg:table-cell">Applies to</th>
                  <th className="hidden sm:table-cell">Severity</th>
                  <th className="hidden text-right sm:table-cell">Active alerts</th>
                  <th>State</th>
                  {anyEditable && (
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {list.items.map((p) => (
                  <tr key={p.id}>
                    <td className="min-w-44">
                      <p className="font-medium">{p.name}</p>
                      <div className="my-1 sm:hidden">
                        <SeverityBadge severity={p.severity} />
                      </div>
                      <p className="text-xs text-muted md:hidden">{conditionText(p)}</p>
                      <p className="text-xs text-muted lg:hidden">{policyScope(p)}</p>
                      {p.description && <p className="max-w-md text-xs text-muted">{p.description}</p>}
                    </td>
                    <td className="hidden md:table-cell">{conditionText(p)}</td>
                    <td className="hidden max-w-60 break-words lg:table-cell">
                      {p.level === "shared" ? <span className="text-muted">Every device</span> : policyScope(p)}
                    </td>
                    <td className="hidden sm:table-cell">
                      <SeverityBadge severity={p.severity} />
                    </td>
                    <td className="hidden text-right tabular-nums sm:table-cell">
                      {p.activeAlerts > 0 ? formatNumber(p.activeAlerts) : <span className="text-subtle">0</span>}
                    </td>
                    <td>{p.enabled ? <Badge tone="ok">On</Badge> : <Badge>Off</Badge>}</td>
                    {anyEditable && (
                      <td className="w-px text-right">
                        {p.canEdit && (
                          <Button size="sm" variant="ghost" onClick={() => onEdit(p)} aria-label={`Edit ${p.name}`}>
                            Edit
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <p className="mt-2 text-xs text-muted">
            {plural(list.items.length, "policy", "policies")}, {plural(list.items.filter((p) => p.enabled).length, "turned on", "turned on")}.
          </p>
        </>
      )}
      <PolicyDialog
        open={editing !== null}
        onClose={() => setEditing(null)}
        policy={editing === "new" || editing === null ? undefined : editing}
        fixed={fixedOf(scope)}
      />
    </>
  );
}
