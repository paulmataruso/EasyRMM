import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { FolderTree, MonitorDown, Pencil, Plus, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList } from "../../api/hooks";
import type { DeviceGroup, DeviceGroupInput, Organization, PatchStatus, Site } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import {
  Button,
  buttonClasses,
  Card,
  EmptyState,
  ErrorState,
  IconButton,
  InlineError,
  KeyValueList,
  PageHeader,
  Spinner,
  TableWrap,
  Tabs,
  TextareaField,
  TextField,
} from "../../components/ui";
import { formatDateTime } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { PatchAllButton } from "../patching/PatchAllButton";
import { PolicyPanel } from "../patching/PolicyEditor";
import { TagsField } from "../patching/Tags";
import { SiteFormDialog } from "./SiteFormDialog";

export function SiteDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const site = useApi<Site>(`/sites/${id}`);
  const org = useApi<Organization>(site.data ? `/organizations/${site.data.organizationId}` : null);
  const groups = useList<DeviceGroup>(`/sites/${id}/device-groups`);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [groupForm, setGroupForm] = useState<{ open: boolean; group?: DeviceGroup }>({ open: false });
  const [groupToDelete, setGroupToDelete] = useState<DeviceGroup | null>(null);
  const url = useUrlState();
  // The Patch policy tab shows once EasyPatch is set up (ADR-0030).
  const patching = useApi<PatchStatus>(can("patch.view") ? "/patching" : null, undefined, { staleTime: 60_000 });
  const patched = patching.data?.configured === true;
  const tab = patched && url.get("tab") === "patch-policy" ? "patch-policy" : "overview";

  const removeSite = useApiMutation(() => api.del(`/sites/${id}`), {
    invalidate: ["/organizations", "/sites", "/audit"],
    onSuccess: () => {
      toast.success(`Site “${site.data?.name}” deleted.`);
      navigate(`/organizations/${site.data?.organizationId ?? ""}`, { replace: true });
    },
  });
  const removeGroup = useApiMutation((g: DeviceGroup) => api.del(`/device-groups/${g.id}`), {
    invalidate: ["/sites", "/organizations", "/audit"],
    onSuccess: (_, g) => {
      toast.success(`Device group “${g.name}” deleted.`);
      setGroupToDelete(null);
    },
  });

  if (site.isPending) return <Spinner />;
  if (site.isError) return <ErrorState error={site.error} onRetry={() => void site.refetch()} />;
  const s = site.data;
  const canDeleteSite = org.data?.canManage ?? false;

  return (
    <>
      <PageHeader
        breadcrumb={
          <>
            <Link to="/organizations" className="hover:text-fg">
              Organizations
            </Link>
            <span className="mx-1.5" aria-hidden>
              /
            </span>
            <Link to={`/organizations/${s.organizationId}`} className="hover:text-fg">
              {s.organizationName}
            </Link>
          </>
        }
        title={s.name}
        subtitle={[s.timezone, s.address].filter(Boolean).join(" · ")}
        actions={
          <>
            {patched && <PatchAllButton organizationId={s.organizationId} siteId={s.id} preset="update-now" />}
            {can("enrollment.manage") && (
              <Link to={`/devices/add?siteId=${s.id}`} className={buttonClasses("secondary")}>
                <MonitorDown className="size-4" aria-hidden />
                Add devices
              </Link>
            )}
            {s.canManage && (
              <Button icon={<Pencil className="size-4" aria-hidden />} onClick={() => setEditing(true)}>
                Edit
              </Button>
            )}
            {canDeleteSite && (
              <Button variant="danger-ghost" icon={<Trash2 className="size-4" aria-hidden />} onClick={() => setDeleting(true)}>
                Delete
              </Button>
            )}
          </>
        }
      />

      {patched && (
        <Tabs
          tabs={[
            { id: "overview", label: "Overview" },
            { id: "patch-policy", label: "Patch policy" },
          ]}
          active={tab}
          onChange={(t) => url.set({ tab: t === "overview" ? null : t })}
        />
      )}

      {tab === "patch-policy" && (
        <div role="tabpanel" aria-labelledby="tab-patch-policy">
          <PolicyPanel level="site" id={s.id} intro={<TagsField level="site" id={s.id} />} />
        </div>
      )}

      {tab === "overview" && (
        <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
          <Card
            title="Device groups"
            className="xl:col-span-2"
            padded={false}
            actions={
              s.canManage && (
                <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setGroupForm({ open: true })}>
                  Add device group
                </Button>
              )
            }
          >
            {groups.isPending ? (
              <Spinner />
            ) : groups.isError ? (
              <ErrorState error={groups.error} onRetry={() => void groups.refetch()} compact />
            ) : groups.items.length === 0 ? (
              <EmptyState
                title="No device groups yet"
                icon={<FolderTree className="size-8" aria-hidden />}
                action={
                  s.canManage ? (
                    <Button variant="primary" onClick={() => setGroupForm({ open: true })}>
                      Add the first device group
                    </Button>
                  ) : undefined
                }
              >
                Device groups sort a site's devices, for example Servers, Workstations or Front desk.
              </EmptyState>
            ) : (
              <TableWrap className="rounded-none border-0">
                <table className="table-base">
                  <thead>
                    <tr>
                      <th>Device group</th>
                      <th>Description</th>
                      <th>Created</th>
                      {s.canManage && (
                        <th className="text-right">
                          <span className="sr-only">Actions</span>
                        </th>
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {groups.items.map((g) => (
                      <tr key={g.id}>
                        <td className="font-medium">{g.name}</td>
                        <td className="max-w-md truncate text-muted">{g.description || "—"}</td>
                        <td className="whitespace-nowrap text-muted">{formatDateTime(g.createdAt)}</td>
                        {s.canManage && (
                          <td className="text-right whitespace-nowrap">
                            <IconButton label={`Edit ${g.name}`} onClick={() => setGroupForm({ open: true, group: g })}>
                              <Pencil className="size-4" aria-hidden />
                            </IconButton>
                            <IconButton label={`Delete ${g.name}`} onClick={() => setGroupToDelete(g)} className="hover:text-danger">
                              <Trash2 className="size-4" aria-hidden />
                            </IconButton>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </Card>

          <Card title="Details">
            <KeyValueList
              narrow
              items={[
                ["Organization", <Link to={`/organizations/${s.organizationId}`} className="text-accent hover:underline">{s.organizationName}</Link>],
                ["Time zone", s.timezone],
                ["Address", s.address || <span className="text-muted">None</span>],
                ["Notes", s.notes ? <span className="whitespace-pre-wrap">{s.notes}</span> : <span className="text-muted">None</span>],
                ["Created", formatDateTime(s.createdAt)],
                ["Updated", formatDateTime(s.updatedAt)],
                ["Your access", s.canManage ? "Manage" : "View only"],
              ]}
            />
          </Card>
        </div>
      )}

      <SiteFormDialog open={editing} organizationId={s.organizationId} site={s} onClose={() => setEditing(false)} onSaved={() => setEditing(false)} />
      <DeviceGroupDialog
        open={groupForm.open}
        siteId={s.id}
        group={groupForm.group}
        onClose={() => setGroupForm({ open: false })}
      />
      <ConfirmDialog
        open={deleting}
        onClose={() => {
          setDeleting(false);
          removeSite.reset();
        }}
        onConfirm={() => removeSite.mutate(undefined)}
        title="Delete site"
        confirmLabel="Delete site"
        tone="danger"
        loading={removeSite.isPending}
        error={removeSite.error}
        confirmText={s.name}
      >
        <p>
          This permanently deletes <strong>{s.name}</strong> from {s.organizationName}. A site must have no device groups before it can be
          deleted.
        </p>
      </ConfirmDialog>
      <ConfirmDialog
        open={groupToDelete !== null}
        onClose={() => {
          setGroupToDelete(null);
          removeGroup.reset();
        }}
        onConfirm={() => groupToDelete && removeGroup.mutate(groupToDelete)}
        title="Delete device group"
        confirmLabel="Delete device group"
        tone="danger"
        loading={removeGroup.isPending}
        error={removeGroup.error}
      >
        <p>
          Delete <strong>{groupToDelete?.name}</strong> from {s.name}?
        </p>
      </ConfirmDialog>
    </>
  );
}

function DeviceGroupDialog({ open, onClose, siteId, group }: { open: boolean; onClose: () => void; siteId: string; group?: DeviceGroup }) {
  const toast = useToast();
  const [form, setForm] = useState<DeviceGroupInput>({ name: "", description: "" });
  useEffect(() => {
    if (open) setForm(group ? { name: group.name, description: group.description } : { name: "", description: "" });
  }, [open, group]);
  const save = useApiMutation(
    (req: DeviceGroupInput) => (group ? api.put<DeviceGroup>(`/device-groups/${group.id}`, req) : api.post<DeviceGroup>(`/sites/${siteId}/device-groups`, req)),
    {
      invalidate: ["/sites", "/organizations", "/audit"],
      onSuccess: (g) => {
        toast.success(group ? "Device group updated." : `Device group “${g.name}” created.`);
        onClose();
      },
    },
  );
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ name: form.name.trim(), description: form.description.trim() });
  }

  return (
    <Dialog open={open} onClose={onClose} title={group ? "Edit device group" : "New device group"} size="sm">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField
          label="Name"
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          error={fieldError(save.error, "name")}
          required
          maxLength={200}
          autoFocus
        />
        <TextareaField
          label="Description"
          value={form.description}
          onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
          error={fieldError(save.error, "description")}
          maxLength={2000}
        />
        <InlineError error={save.error} fields={["name", "description"]} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim()}>
            {group ? "Save changes" : "Create device group"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
