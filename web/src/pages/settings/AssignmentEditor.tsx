import { useId } from "react";
import { Plus, X } from "lucide-react";
import { fieldError } from "../../api/client";
import { useApi, useOrganizations, useSites } from "../../api/hooks";
import type { Assignment, List, Role, RoleView } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { roleName } from "../../components/StatusBadges";
import { Button, cx, Field, IconButton, Select } from "../../components/ui";

/** An assignment row as edited: empty strings mean "not chosen". */
export interface DraftAssignment {
  role: Role | "";
  organizationId: string;
  siteId: string;
}

export function toDraft(a: Assignment): DraftAssignment {
  return { role: a.role, organizationId: a.organizationId ?? "", siteId: a.siteId ?? "" };
}

export function fromDraft(d: DraftAssignment): Assignment {
  const a: Assignment = { role: d.role as Role };
  if (d.role !== "super_admin" && d.organizationId) a.organizationId = d.organizationId;
  if (d.role !== "super_admin" && d.role !== "org_admin" && d.organizationId && d.siteId) a.siteId = d.siteId;
  return a;
}

/** A draft is complete when it names a role and every scope that role needs. */
export function draftComplete(d: DraftAssignment): boolean {
  if (!d.role) return false;
  return d.role === "super_admin" || d.organizationId !== "";
}

export const blankDraft = (): DraftAssignment => ({ role: "", organizationId: "", siteId: "" });

/**
 * Edits a list of role assignments. Each row picks a role and the scope it applies to:
 * platform-wide (super administrators), a whole organization, or one site in it.
 */
export function AssignmentEditor({ value, onChange, error, hideLegend = false }: {
  value: DraftAssignment[];
  onChange: (next: DraftAssignment[]) => void;
  error?: unknown;
  /** Keep the legend for screen readers only, when a card title already names the group. */
  hideLegend?: boolean;
}) {
  const { isSuperAdmin } = useAuth();
  const roles = useApi<List<RoleView>>("/roles", undefined, { staleTime: 300_000 });
  const available = (roles.data?.items ?? []).filter((r) => r.role !== "super_admin" || isSuperAdmin);
  const update = (i: number, patch: Partial<DraftAssignment>) => onChange(value.map((d, j) => (j === i ? { ...d, ...patch } : d)));
  const listError = fieldError(error, "assignments");

  return (
    <fieldset className="flex flex-col gap-2">
      <legend className={hideLegend ? "sr-only" : "mb-1 text-xs font-medium text-muted"}>Roles</legend>
      {value.map((d, i) => (
        <AssignmentRow
          key={i}
          draft={d}
          roles={available}
          error={fieldError(error, `assignments.${i}`)}
          onChange={(patch) => update(i, patch)}
          onRemove={value.length > 1 ? () => onChange(value.filter((_, j) => j !== i)) : undefined}
        />
      ))}
      {listError && <p className="text-xs text-danger">{listError}</p>}
      <div>
        <Button size="sm" variant="ghost" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => onChange([...value, blankDraft()])}>
          Add another role
        </Button>
      </div>
      {roles.data && (
        <p className="text-xs text-subtle">
          {value
            .map((d) => roles.data.items.find((r) => r.role === d.role))
            .filter((r): r is RoleView => Boolean(r))
            .filter((r, i, all) => all.indexOf(r) === i)
            .map((r) => `${r.name}: ${r.description}`)
            .join(" ")}
        </p>
      )}
    </fieldset>
  );
}

function AssignmentRow({ draft, roles, error, onChange, onRemove }: {
  draft: DraftAssignment;
  roles: RoleView[];
  error: string | null;
  onChange: (patch: Partial<DraftAssignment>) => void;
  onRemove?: () => void;
}) {
  const orgs = useOrganizations();
  const sites = useSites(draft.organizationId || null);
  const id = useId();
  const def = roles.find((r) => r.role === draft.role);
  const needsOrg = draft.role !== "" && draft.role !== "super_admin";
  const allowsSite = def?.scopes.includes("site") ?? false;
  const orgSites = sites.items.filter((s) => s.organizationId === draft.organizationId);

  return (
    <div className={cx("rounded-md border border-line bg-raised p-2.5", error && "border-danger/60")}>
      <div className="grid grid-cols-1 items-end gap-2 sm:grid-cols-[1fr_1fr_1fr_auto]">
        <Field label="Role" htmlFor={`${id}-role`}>
          <Select
            id={`${id}-role`}
            value={draft.role}
            onChange={(e) => onChange({ role: e.target.value as Role | "", siteId: e.target.value === "org_admin" ? "" : draft.siteId })}
            required
          >
            <option value="">Choose a role…</option>
            {roles.map((r) => (
              <option key={r.role} value={r.role}>
                {r.name}
              </option>
            ))}
          </Select>
        </Field>
        {draft.role === "super_admin" ? (
          <p className="pb-2 text-xs text-muted sm:col-span-2">Applies to every organization and the platform settings.</p>
        ) : (
          <>
            <Field label="Organization" htmlFor={`${id}-org`}>
              <Select
                id={`${id}-org`}
                value={draft.organizationId}
                onChange={(e) => onChange({ organizationId: e.target.value, siteId: "" })}
                disabled={!needsOrg || orgs.isPending}
                required={needsOrg}
              >
                <option value="">{needsOrg ? "Choose an organization…" : "—"}</option>
                {orgs.items.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Site" htmlFor={`${id}-site`}>
              <Select
                id={`${id}-site`}
                value={draft.siteId}
                onChange={(e) => onChange({ siteId: e.target.value })}
                disabled={!allowsSite || !draft.organizationId}
              >
                <option value="">{allowsSite ? "Whole organization" : "—"}</option>
                {allowsSite &&
                  orgSites.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
              </Select>
            </Field>
          </>
        )}
        <div className="flex justify-end pb-0.5">
          {onRemove && (
            <IconButton label={draft.role ? `Remove ${roleName(draft.role)}` : "Remove role"} onClick={onRemove}>
              <X className="size-4" aria-hidden />
            </IconButton>
          )}
        </div>
      </div>
      {error && <p className="mt-1.5 text-xs text-danger">{error}</p>}
    </div>
  );
}
