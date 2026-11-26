import { useEffect, useState, type FormEvent } from "react";
import { BackupCard } from "../devices/backup/BackupCard";
import { Link, useNavigate, useParams } from "react-router";
import { FolderTree, MonitorDown, Pencil, Plus, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList } from "../../api/hooks";
import type {
  DeviceGroup,
  DeviceGroupInput,
  Organization,
  PatchStatus,
  Site,
} from "../../api/types";
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
  TextareaField,
  TextField,
} from "../../components/ui";
import { formatDateTime } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { PatchAllButton } from "../patching/PatchAllButton";
import {
  addressLines,
  confirmedCounts,
  OpenNowBadge,
  SiteDetailsDialog,
  SiteRecord,
} from "./CustomerRecord";
import { ContactsPanel } from "./Contacts";
import { DeleteGroupDialog, DeviceGroupDialog } from "./GroupDialogs";
import { LevelTabs } from "./levelTabs";
import { PlacesCard } from "./Places";
import { SiteFormDialog } from "./SiteFormDialog";
import { SecurityCard } from "./tabs/SecurityTab";

export function SiteDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const site = useApi<Site>(`/sites/${id}`);
  const org = useApi<Organization>(
    site.data ? `/organizations/${site.data.organizationId}` : null,
  );
  const groups = useList<DeviceGroup>(`/sites/${id}/device-groups`);
  const [editing, setEditing] = useState(false);
  const [editingDetails, setEditingDetails] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const documented = can("doc.view");
  const [groupForm, setGroupForm] = useState<{
    open: boolean;
    group?: DeviceGroup;
  }>({ open: false });
  const [groupToDelete, setGroupToDelete] = useState<DeviceGroup | null>(null);
  const url = useUrlState();
  // The tab strip is the registry's (levelTabs.tsx); this gates the page's own button.
  const patching = useApi<PatchStatus>(
    can("patch.view") ? "/patching" : null,
    undefined,
    { staleTime: 60_000 },
  );
  const patched = patching.data?.configured === true;

  const removeSite = useApiMutation(
    (confirmed: Record<string, number> | undefined) =>
      api.del(`/sites/${id}`, confirmed),
    {
      invalidate: ["/organizations", "/sites", "/audit"],
      onSuccess: () => {
        toast.success(`Site “${site.data?.name}” deleted.`);
        navigate(`/organizations/${site.data?.organizationId ?? ""}`, {
          replace: true,
        });
      },
    },
  );

  if (site.isPending) return <Spinner />;
  if (site.isError)
    return (
      <ErrorState error={site.error} onRetry={() => void site.refetch()} />
    );
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
            <Link
              to={`/organizations/${s.organizationId}`}
              className="hover:text-fg"
            >
              {s.organizationName}
            </Link>
          </>
        }
        title={s.name}
        subtitle={[s.timezone, addressLines(s).join(", ")]
          .filter(Boolean)
          .join(" · ")}
        actions={
          <>
            {patched && (
              <PatchAllButton
                organizationId={s.organizationId}
                siteId={s.id}
                preset="update-now"
              />
            )}
            {can("enrollment.manage") && (
              <Link
                to="?tab=install"
                className={buttonClasses("secondary")}
              >
                <MonitorDown className="size-4" aria-hidden />
                Add devices
              </Link>
            )}
            {s.canManage && (
              <Button
                icon={<Pencil className="size-4" aria-hidden />}
                onClick={() => setEditing(true)}
              >
                Edit
              </Button>
            )}
            {canDeleteSite && (
              <Button
                variant="danger-ghost"
                icon={<Trash2 className="size-4" aria-hidden />}
                onClick={() => setDeleting(true)}
              >
                Delete
              </Button>
            )}
          </>
        }
      />

      <LevelTabs
        level="site"
        id={s.id}
        organizationId={s.organizationId}
        overview={
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
            <div className="flex flex-col gap-5 xl:col-span-2">
              <Card
                title="Device groups"
                padded={false}
                actions={
                  s.canManage && (
                    <Button
                      size="sm"
                      variant="primary"
                      icon={<Plus className="size-3.5" aria-hidden />}
                      onClick={() => setGroupForm({ open: true })}
                    >
                      Add device group
                    </Button>
                  )
                }
              >
                {groups.isPending ? (
                  <Spinner />
                ) : groups.isError ? (
                  <ErrorState
                    error={groups.error}
                    onRetry={() => void groups.refetch()}
                    compact
                  />
                ) : groups.items.length === 0 ? (
                  <EmptyState
                    title="No device groups yet"
                    icon={<FolderTree className="size-8" aria-hidden />}
                    action={
                      s.canManage ? (
                        <Button
                          variant="primary"
                          onClick={() => setGroupForm({ open: true })}
                        >
                          Add the first device group
                        </Button>
                      ) : undefined
                    }
                  >
                    Device groups sort a site's devices, for example Servers,
                    Workstations or Front desk.
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
                            <td className="font-medium">
                              <Link
                                to={`/groups/${g.id}`}
                                className="hover:text-accent hover:underline"
                              >
                                {g.name}
                              </Link>
                            </td>
                            <td className="max-w-md truncate text-muted">
                              {g.description || "—"}
                            </td>
                            <td className="whitespace-nowrap text-muted">
                              {formatDateTime(g.createdAt)}
                            </td>
                            {s.canManage && (
                              <td className="text-right whitespace-nowrap">
                                <IconButton
                                  label={`Edit ${g.name}`}
                                  onClick={() =>
                                    setGroupForm({ open: true, group: g })
                                  }
                                >
                                  <Pencil className="size-4" aria-hidden />
                                </IconButton>
                                <IconButton
                                  label={`Delete ${g.name}`}
                                  onClick={() => setGroupToDelete(g)}
                                  className="hover:text-danger"
                                >
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
              {documented && <PlacesCard site={s} />}
              {documented && (
                <ContactsPanel
                  organizationId={s.organizationId}
                  site={s}
                  levels={
                    s.canManageDocumentation ? [{ id: s.id, name: s.name }] : []
                  }
                />
              )}
            </div>

            <div className="flex flex-col gap-5">
              <BackupCard level="site" id={s.id} organizationId={s.organizationId} />
              {documented && (
                <Card
                  title={
                    <span className="flex items-center gap-2">
                      Address and hours <OpenNowBadge openNow={s.openNow} />
                    </span>
                  }
                  actions={
                    s.canManageDocumentation && (
                      <Button
                        size="sm"
                        icon={<Pencil className="size-3.5" aria-hidden />}
                        onClick={() => setEditingDetails(true)}
                      >
                        Edit
                      </Button>
                    )
                  }
                >
                  <SiteRecord
                    site={s}
                    organizationHours={org.data?.businessHours ?? null}
                  />
                </Card>
              )}
              <SecurityCard level="site" id={s.id} organizationId={s.organizationId} />
              <Card title="Details">
                <KeyValueList
                  narrow
                  items={[
                    [
                      "Organization",
                      <Link
                        to={`/organizations/${s.organizationId}`}
                        className="text-accent hover:underline"
                      >
                        {s.organizationName}
                      </Link>,
                    ],
                    ["Time zone", s.timezone],
                    [
                      "Notes",
                      s.notes ? (
                        <span className="whitespace-pre-wrap">{s.notes}</span>
                      ) : (
                        <span className="text-muted">None</span>
                      ),
                    ],
                    ["Created", formatDateTime(s.createdAt)],
                    ["Updated", formatDateTime(s.updatedAt)],
                    ["Your access", s.canManage ? "Manage" : "View only"],
                  ]}
                />
              </Card>
            </div>
          </div>
        }
      />

      <SiteFormDialog
        open={editing}
        organizationId={s.organizationId}
        site={s}
        onClose={() => setEditing(false)}
        onSaved={() => setEditing(false)}
      />
      {s.canManageDocumentation && (
        <SiteDetailsDialog
          open={editingDetails}
          site={s}
          onClose={() => setEditingDetails(false)}
        />
      )}
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
        onConfirm={() => removeSite.mutate(confirmedCounts(removeSite.error))}
        title="Delete site"
        confirmLabel={
          confirmedCounts(removeSite.error)
            ? "Delete site and its documentation"
            : "Delete site"
        }
        tone="danger"
        loading={removeSite.isPending}
        error={removeSite.error}
        confirmText={s.name}
      >
        <p>
          This permanently deletes <strong>{s.name}</strong> from{" "}
          {s.organizationName}. A site must have no devices before it can be
          deleted. Its contacts and places are deleted with it once you confirm
          them.
        </p>
      </ConfirmDialog>
      <DeleteGroupDialog
        group={groupToDelete}
        siteName={s.name}
        onClose={() => setGroupToDelete(null)}
      />
    </>
  );
}
