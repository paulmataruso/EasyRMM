import { useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { MapPin, Pencil, Plus, Trash2 } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation, useList, usePrefetch } from "../../api/hooks";
import type { Organization, PatchStatus, Site } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, Card, EmptyState, ErrorState, KeyValueList, PageHeader, Spinner, TableWrap, Tabs } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useRowKeys } from "../../lib/rowKeys";
import { useUrlState } from "../../lib/urlState";
import { PolicyPanel } from "../patching/PolicyEditor";
import { TagsField } from "../patching/Tags";
import { ContactsPanel } from "./Contacts";
import { addressLines, confirmedCounts, OpenNowBadge, OrganizationDetailsDialog, OrganizationRecord } from "./CustomerRecord";
import { OrganizationFormDialog } from "./OrganizationsPage";
import { SiteFormDialog } from "./SiteFormDialog";

export function OrganizationDetailPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const url = useUrlState();
  const prefetch = usePrefetch();
  const tableRef = useRef<HTMLDivElement>(null);
  const org = useApi<Organization>(`/organizations/${id}`);
  const sites = useList<Site>(`/organizations/${id}/sites`);
  const [editing, setEditing] = useState(false);
  const [editingDetails, setEditingDetails] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const addingSite = url.get("newSite") === "1";
  // The Patch policy tab shows once EasyPatch is set up (ADR-0030).
  const patching = useApi<PatchStatus>(can("patch.view") ? "/patching" : null, undefined, { staleTime: 60_000 });
  const patched = patching.data?.configured === true;
  const documented = can("doc.view");
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "contacts", label: "Contacts", hidden: !documented },
    { id: "patch-policy", label: "Patch policy", hidden: !patched },
  ];
  const tab = tabs.find((t) => t.id === url.get("tab") && !t.hidden)?.id ?? "overview";

  const remove = useApiMutation((confirmed: Record<string, number> | undefined) => api.del(`/organizations/${id}`, confirmed), {
    invalidate: ["/organizations", "/sites", "/audit"],
    onSuccess: () => {
      toast.success(`Organization “${org.data?.name}” deleted.`);
      navigate("/organizations", { replace: true });
    },
  });

  const warm = (siteId: string) => {
    prefetch(`/sites/${siteId}`);
    prefetch(`/sites/${siteId}/device-groups`);
  };
  useRowKeys(tableRef, (link) => link.dataset.id && warm(link.dataset.id));

  if (org.isPending) return <Spinner />;
  if (org.isError) return <ErrorState error={org.error} onRetry={() => void org.refetch()} />;
  const o = org.data;

  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/organizations" className="hover:text-fg">
            Organizations
          </Link>
        }
        title={o.name}
        subtitle={plural(o.siteCount, "site")}
        actions={
          <>
            {o.canManage && (
              <Button icon={<Pencil className="size-4" aria-hidden />} onClick={() => setEditing(true)}>
                Edit
              </Button>
            )}
            {can("org.create") && (
              <Button variant="danger-ghost" icon={<Trash2 className="size-4" aria-hidden />} onClick={() => setDeleting(true)}>
                Delete
              </Button>
            )}
          </>
        }
      />

      {tabs.some((t) => t.id !== "overview" && !t.hidden) && (
        <Tabs tabs={tabs} active={tab} onChange={(t) => url.set({ tab: t === "overview" ? null : t, after: null })} />
      )}

      {tab === "patch-policy" && (
        <div role="tabpanel" aria-labelledby="tab-patch-policy">
          <PolicyPanel level="organization" id={o.id} intro={<TagsField level="organization" id={o.id} />} />
        </div>
      )}

      {tab === "contacts" && (
        <div role="tabpanel" aria-labelledby="tab-contacts">
          <ContactsPanel
            organizationId={o.id}
            levels={[
              ...(o.canManageDocumentation ? [{ id: null, name: "The organization" }] : []),
              ...sites.items.filter((s) => s.canManageDocumentation).map((s) => ({ id: s.id, name: s.name })),
            ]}
            after={url.get("after")}
            onPage={(after) => url.set({ after })}
          />
        </div>
      )}

      {tab === "overview" && (
        <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
          <Card
            title="Sites"
            className="xl:col-span-2"
            padded={false}
            actions={
              o.canManage && (
                <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => url.set({ newSite: "1" })}>
                  Add site
                </Button>
              )
            }
          >
            {sites.isPending ? (
              <Spinner />
            ) : sites.isError ? (
              <ErrorState error={sites.error} onRetry={() => void sites.refetch()} compact />
            ) : sites.items.length === 0 ? (
              <EmptyState
                title="No sites yet"
                icon={<MapPin className="size-8" aria-hidden />}
                action={
                  o.canManage ? (
                    <Button variant="primary" onClick={() => url.set({ newSite: "1" })}>
                      Add the first site
                    </Button>
                  ) : undefined
                }
              >
                A site is an office or location. Its time zone is used for schedules and reports.
              </EmptyState>
            ) : (
              <TableWrap className="rounded-none border-0">
                <div ref={tableRef}>
                  <table className="table-base">
                    <thead>
                      <tr>
                        <th>Site</th>
                        <th className="hidden sm:table-cell">Time zone</th>
                        <th className="text-right">Device groups</th>
                        <th className="hidden md:table-cell">Updated</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sites.items.map((s) => (
                        <tr key={s.id} className="cursor-pointer" onClick={() => navigate(`/sites/${s.id}`)} onMouseEnter={() => warm(s.id)}>
                          <td>
                            <Link
                              to={`/sites/${s.id}`}
                              className="font-medium hover:text-accent"
                              data-row-link
                              data-id={s.id}
                              onClick={(e) => e.stopPropagation()}
                              onFocus={() => warm(s.id)}
                            >
                              {s.name}
                            </Link>
                            {addressLines(s).length > 0 && <p className="max-w-52 truncate text-xs text-muted sm:max-w-md">{addressLines(s).join(", ")}</p>}
                          </td>
                          <td className="hidden whitespace-nowrap sm:table-cell">{s.timezone}</td>
                          <td className="text-right tabular-nums">{s.deviceGroupCount}</td>
                          <td className="hidden whitespace-nowrap text-muted md:table-cell" title={formatDateTime(s.updatedAt)}>
                            {formatRelative(s.updatedAt)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </TableWrap>
            )}
          </Card>

          <div className="flex flex-col gap-5">
          {documented && (
            <Card
              title={
                <span className="flex items-center gap-2">
                  Contact information <OpenNowBadge openNow={o.openNow} />
                </span>
              }
              actions={
                o.canManageDocumentation && (
                  <Button size="sm" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditingDetails(true)}>
                    Edit
                  </Button>
                )
              }
            >
              <OrganizationRecord organization={o} />
            </Card>
          )}
          <Card title="Details">
            <KeyValueList
              narrow
              items={[
                ["Time zone", o.timezone],
                ["Notes", o.notes ? <span className="whitespace-pre-wrap">{o.notes}</span> : <span className="text-muted">None</span>],
                ["Created", formatDateTime(o.createdAt)],
                ["Updated", formatDateTime(o.updatedAt)],
                ["Your access", o.canManage ? "Manage" : "View only"],
              ]}
            />
            {can("user.view") && (
              <Link to={`/settings?tab=users&organizationId=${o.id}`} className="mt-4 inline-block text-xs text-accent hover:underline">
                People with access to this organization
              </Link>
            )}
          </Card>
          </div>
        </div>
      )}

      <OrganizationFormDialog open={editing} organization={o} onClose={() => setEditing(false)} onSaved={() => setEditing(false)} />
      {o.canManageDocumentation && <OrganizationDetailsDialog open={editingDetails} organization={o} onClose={() => setEditingDetails(false)} />}
      <SiteFormDialog
        open={addingSite && o.canManage}
        organizationId={o.id}
        onClose={() => url.set({ newSite: null })}
        onSaved={(site) => navigate(`/sites/${site.id}`)}
      />
      <ConfirmDialog
        open={deleting}
        onClose={() => {
          setDeleting(false);
          remove.reset();
        }}
        onConfirm={() => remove.mutate(confirmedCounts(remove.error))}
        title="Delete organization"
        confirmLabel={confirmedCounts(remove.error) ? "Delete organization and contacts" : "Delete organization"}
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
        confirmText={o.name}
      >
        <p>
          This permanently deletes <strong>{o.name}</strong>. An organization must have no sites before it can be deleted. Its contacts
          are deleted with it once you confirm them. Its audit history is kept.
        </p>
      </ConfirmDialog>
    </>
  );
}
