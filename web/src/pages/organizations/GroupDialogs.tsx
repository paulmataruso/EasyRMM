import { useEffect, useState, type FormEvent } from "react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { DeviceGroup, DeviceGroupInput } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, InlineError, TextareaField, TextField } from "../../components/ui";

/** What a change to a device group refreshes: the sites' pages, the tree and the devices' group names. */
const GROUP_CHANGED = ["/sites", "/organizations", "/device-tree", "/devices", "/audit"];

/** Creates a device group in a site, or edits one. Shared by the site's page and the sidebar tree's group menu (ADR-0069). */
export function DeviceGroupDialog({ open, onClose, siteId, group }: { open: boolean; onClose: () => void; siteId: string; group?: DeviceGroup }) {
  const toast = useToast();
  const [form, setForm] = useState<DeviceGroupInput>({ name: "", description: "" });
  useEffect(() => {
    if (open) setForm(group ? { name: group.name, description: group.description } : { name: "", description: "" });
  }, [open, group]);
  const save = useApiMutation(
    (req: DeviceGroupInput) => (group ? api.put<DeviceGroup>(`/device-groups/${group.id}`, req) : api.post<DeviceGroup>(`/sites/${siteId}/device-groups`, req)),
    {
      invalidate: GROUP_CHANGED,
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

/** Confirms deleting a device group; its devices stay in the site, in no group. */
export function DeleteGroupDialog({ group, siteName, onClose }: { group: DeviceGroup | null; siteName: string; onClose: () => void }) {
  const toast = useToast();
  const remove = useApiMutation((g: DeviceGroup) => api.del(`/device-groups/${g.id}`), {
    invalidate: GROUP_CHANGED,
    onSuccess: (_, g) => {
      toast.success(`Device group “${g.name}” deleted.`);
      onClose();
    },
  });
  return (
    <ConfirmDialog
      open={group !== null}
      onClose={() => {
        onClose();
        remove.reset();
      }}
      onConfirm={() => group && remove.mutate(group)}
      title="Delete device group"
      confirmLabel="Delete device group"
      tone="danger"
      loading={remove.isPending}
      error={remove.error}
    >
      <p>
        Delete <strong>{group?.name}</strong> from {siteName}? Its devices stay in the site, in no group.
      </p>
    </ConfirmDialog>
  );
}
