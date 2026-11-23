import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { Building2, Plus } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation, useOrganizations, usePrefetch } from "../../api/hooks";
import type { Organization, OrganizationInput } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Dialog } from "../../components/Dialog";
import { SearchInput } from "../../components/Filters";
import { useToast } from "../../components/Toast";
import { Button, EmptyState, ErrorState, InlineError, PageHeader, Spinner, TableWrap, TextareaField, TextField, Toolbar } from "../../components/ui";
import { browserTimeZone, formatDateTime, formatRelative, plural } from "../../lib/format";
import { useRowKeys } from "../../lib/rowKeys";
import { useUrlState } from "../../lib/urlState";
import { TimeZoneField } from "./SiteFormDialog";

export function OrganizationsPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const url = useUrlState();
  const prefetch = usePrefetch();
  const list = useOrganizations();
  const tableRef = useRef<HTMLDivElement>(null);
  const search = url.get("q");
  const creating = url.get("new") === "1";
  const canCreate = can("org.create");

  // The list is small and returned in full, so filtering is immediate and local.
  const rows = useMemo(() => {
    const q = search.toLowerCase();
    return q ? list.items.filter((o) => o.name.toLowerCase().includes(q) || o.notes.toLowerCase().includes(q)) : list.items;
  }, [list.items, search]);

  // Shown only when it tells the reader something: when their access differs between organizations.
  const accessVaries = new Set(list.items.map((o) => o.canManage)).size > 1;

  const warm = (id: string) => {
    prefetch(`/organizations/${id}`);
    prefetch(`/organizations/${id}/sites`);
  };
  useRowKeys(tableRef, (link) => link.dataset.id && warm(link.dataset.id));

  return (
    <>
      <PageHeader
        title="Organizations"
        subtitle="Customers you manage. Each organization contains sites, and sites contain device groups."
        actions={
          canCreate && (
            <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => url.set({ new: "1" })}>
              New organization
            </Button>
          )
        }
      />
      <Toolbar>
        <SearchInput
          value={search}
          onChange={(v) => url.set({ q: v })}
          placeholder="Search organizations"
          className="max-w-sm"
          delay={0}
          readout={search && !list.isPending ? `${rows.length} of ${plural(list.items.length, "organization")}` : null}
        />
      </Toolbar>

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState
          title={search ? "No organizations match your search" : "No organizations yet"}
          icon={<Building2 className="size-8" aria-hidden />}
          action={
            canCreate && !search ? (
              <Button variant="primary" onClick={() => url.set({ new: "1" })}>
                Create your first organization
              </Button>
            ) : undefined
          }
        >
          {!search && (canCreate ? "Create an organization for each customer, then add its sites." : "You have not been given access to any organization yet. Ask an administrator.")}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <div ref={tableRef}>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th className="text-right">Sites</th>
                    {accessVaries && <th className="hidden sm:table-cell">Your access</th>}
                    <th className="hidden sm:table-cell">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((o) => (
                    <tr key={o.id} className="cursor-pointer" onClick={() => navigate(`/organizations/${o.id}`)} onMouseEnter={() => warm(o.id)}>
                      <td>
                        <Link
                          to={`/organizations/${o.id}`}
                          className="rounded-sm font-medium hover:text-accent"
                          data-row-link
                          data-id={o.id}
                          onClick={(e) => e.stopPropagation()}
                          onFocus={() => warm(o.id)}
                        >
                          {o.name}
                        </Link>
                        {o.notes && <p className="max-w-52 truncate text-xs text-muted sm:max-w-md">{o.notes}</p>}
                      </td>
                      <td className="text-right tabular-nums">{o.siteCount}</td>
                      {accessVaries && <td className="hidden text-muted sm:table-cell">{o.canManage ? "Can manage" : "View only"}</td>}
                      <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={formatDateTime(o.updatedAt)}>
                        {formatRelative(o.updatedAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </TableWrap>
          <p className="mt-2 text-xs text-muted">
            {plural(rows.length, "organization")}
            <span className="hidden sm:inline">
              . Press <kbd>j</kbd> and <kbd>k</kbd> to move between rows, <kbd>/</kbd> to search.
            </span>
          </p>
        </>
      )}

      <OrganizationFormDialog
        open={creating && canCreate}
        onClose={() => url.set({ new: null })}
        onSaved={(org) => navigate(`/organizations/${org.id}`)}
      />
    </>
  );
}

export function OrganizationFormDialog({ open, onClose, onSaved, organization }: {
  open: boolean;
  onClose: () => void;
  onSaved: (org: Organization) => void;
  organization?: Organization;
}) {
  const toast = useToast();
  const [form, setForm] = useState<OrganizationInput>({ name: "", timezone: "", notes: "" });
  useEffect(() => {
    if (open)
      setForm(
        organization
          ? { name: organization.name, timezone: organization.timezone, notes: organization.notes, autoRepair: organization.autoRepair }
          : { name: "", timezone: browserTimeZone(), notes: "" },
      );
  }, [open, organization]);

  const save = useApiMutation(
    (req: OrganizationInput) =>
      organization ? api.put<Organization>(`/organizations/${organization.id}`, req) : api.post<Organization>("/organizations", req),
    {
      invalidate: ["/organizations", "/sites", "/audit"],
      onSuccess: (org) => {
        toast.success(organization ? "Organization updated." : `Organization “${org.name}” created.`);
        onSaved(org);
      },
    },
  );
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ name: form.name.trim(), timezone: form.timezone.trim(), notes: form.notes.trim(), autoRepair: organization ? form.autoRepair : undefined });
  }
  // Organization names are unique on the server; only Super Administrators
  // rename, so an organization's own administrators cannot probe for others.
  const nameLocked = !!organization && !organization.canRename;

  return (
    <Dialog open={open} onClose={onClose} title={organization ? "Edit organization" : "New organization"}>
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField
          label="Name"
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          error={fieldError(save.error, "name")}
          hint={nameLocked ? "Only a Super Administrator can rename an organization." : undefined}
          required
          disabled={nameLocked}
          maxLength={200}
          autoFocus={!nameLocked}
        />
        <TimeZoneField
          value={form.timezone}
          onChange={(v) => setForm((f) => ({ ...f, timezone: v }))}
          error={fieldError(save.error, "timezone")}
          hint="Patching reports for this organization use it."
        />
        <TextareaField
          label="Notes"
          value={form.notes}
          onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
          error={fieldError(save.error, "notes")}
          hint="Contract details, contacts, anything technicians should know."
          maxLength={4000}
          autoFocus={nameLocked}
        />
        {organization && (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={form.autoRepair ?? true}
              onChange={(e) => setForm((f) => ({ ...f, autoRepair: e.target.checked }))}
            />
            <span>
              Repair agents automatically
              <span className="block text-muted">
                When MeshAgent or the EasyPatch agent stops working on a device, EasyRMM restarts it and, if that does not help, repairs it: at most once
                every 6 hours and 3 times a day for each. Repairs by hand stay available.
              </span>
            </span>
          </label>
        )}
        <InlineError error={save.error} fields={["name", "timezone", "notes"]} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim() || !form.timezone.trim()}>
            {organization ? "Save changes" : "Create organization"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
