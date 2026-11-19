import { useEffect, useState, type FormEvent } from "react";
import { Pencil, Plus, Tag as TagIcon, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import { useAuth } from "../../auth/AuthContext";
import type { PatchAssignedTags, PatchTag, PatchTagList, PatchTagRef, PolicyLevel, TagColor } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import {
  Alert,
  Button,
  Card,
  cx,
  EmptyState,
  ErrorState,
  IconButton,
  InlineError,
  SelectField,
  Spinner,
  TableWrap,
  TextareaField,
  TextField,
} from "../../components/ui";
import { plural } from "../../lib/format";

// EasyPatch's tags (one-product plan, C4). A tag's policy applies to the devices that have the tag, directly or through
// their site or organization, over their site's policy. Tags are shared by every organization, so only someone who
// configures patching everywhere (a super administrator) manages or assigns them; the server says who may.

// As EasyPatch's console colours them (its components are upstream of EasyRMM's).
const COLOR_CLASSES: Record<TagColor, string> = {
  gray: "bg-neutral-soft text-muted",
  blue: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  green: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300",
  amber: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  red: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  purple: "bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300",
  teal: "bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300",
  pink: "bg-pink-100 text-pink-800 dark:bg-pink-950 dark:text-pink-300",
};

export const TAG_COLORS: { value: TagColor; label: string }[] = [
  { value: "gray", label: "Gray" },
  { value: "blue", label: "Blue" },
  { value: "green", label: "Green" },
  { value: "amber", label: "Amber" },
  { value: "red", label: "Red" },
  { value: "purple", label: "Purple" },
  { value: "teal", label: "Teal" },
  { value: "pink", label: "Pink" },
];

/** At most this many tags on an organization, site or device (EasyPatch's limit). */
const MAX_TAGS = 20;

/** "from its site" or "from its organization", for a device's tag it has through them. */
function inheritedLabel(tag: PatchTagRef): string | null {
  if (tag.inheritedFrom === "Site") return "from its site";
  if (tag.inheritedFrom === "Organization") return "from its organization";
  return null;
}

export function TagChip({ tag, className }: { tag: Pick<PatchTagRef, "name" | "color" | "inheritedFrom">; className?: string }) {
  const inherited = inheritedLabel(tag as PatchTagRef);
  return (
    <span
      className={cx(
        "inline-flex max-w-48 items-center gap-1 truncate rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap",
        COLOR_CLASSES[tag.color] ?? COLOR_CLASSES.gray,
        // An inherited tag is outlined with a dashed border: it is not set here.
        inherited && "outline-1 -outline-offset-1 outline-current/40 outline-dashed",
        className,
      )}
      title={inherited ? `${tag.name} (${inherited})` : tag.name}
    >
      {tag.name}
    </span>
  );
}

const LEVEL_NOUN: Record<string, string> = { organization: "organization", site: "site", device: "device" };

/**
 * An organization's, site's or device's tags, and for a super administrator a way to change them. A device's tags from its
 * site or organization are shown dashed; they are changed there.
 */
export function TagsField({ level, id }: { level: Extract<PolicyLevel, "organization" | "site" | "device">; id: string }) {
  const assigned = useApi<PatchAssignedTags>(`/patching/tags/of/${level}/${id}`);
  const [editing, setEditing] = useState(false);
  if (assigned.isPending) return <Spinner label="Loading tags…" />;
  if (assigned.isError) return <ErrorState error={assigned.error} onRetry={() => void assigned.refetch()} compact />;
  const tags = assigned.data.tags;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <span className="text-xs font-medium text-muted">Tags</span>
      {tags.length === 0 ? (
        <span className="text-sm text-muted">None</span>
      ) : (
        <span className="inline-flex flex-wrap items-center gap-1">
          {tags.map((t) => (
            <TagChip key={t.id} tag={t} />
          ))}
        </span>
      )}
      {assigned.data.canAssign && (
        <Button size="sm" variant="ghost" icon={<TagIcon className="size-3.5" aria-hidden />} onClick={() => setEditing(true)}>
          Change tags
        </Button>
      )}
      {/* Remounted on each opening, so it starts from the tags as they are then. */}
      <AssignDialog key={editing ? "open" : "closed"} open={editing} onClose={() => setEditing(false)} level={level} id={id} current={tags} />
    </div>
  );
}

function AssignDialog({ open, onClose, level, id, current }: {
  open: boolean;
  onClose: () => void;
  level: "organization" | "site" | "device";
  id: string;
  current: PatchTagRef[];
}) {
  const toast = useToast();
  const all = useApi<PatchTagList>(open ? "/patching/tags" : null);
  const own = current.filter((t) => !t.inheritedFrom);
  const locked = new Map(current.filter((t) => t.inheritedFrom).map((t) => [t.id, inheritedLabel(t) ?? ""]));
  const [selected, setSelected] = useState<Set<string>>(() => new Set(own.map((t) => t.id)));
  const save = useApiMutation((tagIds: string[]) => api.put<PatchAssignedTags>(`/patching/tags/of/${level}/${id}`, { tagIds }), {
    invalidate: ["/patching"],
    onSuccess: () => {
      toast.success("Tags saved.");
      onClose();
    },
  });
  const tooMany = selected.size > MAX_TAGS;
  return (
    <Dialog
      open={open}
      onClose={() => {
        onClose();
        save.reset();
      }}
      title={`This ${LEVEL_NOUN[level]}'s tags`}
      description={
        level === "device"
          ? "A tag's policy applies over the site's policy. Tags the device has through its site or organization are changed there."
          : `Every device in this ${LEVEL_NOUN[level]} has its tags, and a tag's policy applies to them over the site's policy.`
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} disabled={tooMany || !all.data} onClick={() => save.mutate([...selected])}>
            Save tags
          </Button>
        </>
      }
    >
      {all.isPending ? (
        <Spinner />
      ) : all.isError ? (
        <ErrorState error={all.error} onRetry={() => void all.refetch()} compact />
      ) : all.data.items.length === 0 ? (
        <EmptyState title="No tags yet" compact icon={<TagIcon className="size-8" aria-hidden />}>
          Super administrators add tags under Settings → Patching.
        </EmptyState>
      ) : (
        <fieldset className="flex flex-col gap-0.5">
          <legend className="sr-only">Tags</legend>
          {all.data.items.map((t) => {
            const from = locked.get(t.id);
            return (
              <label key={t.id} className="flex items-start gap-2.5 rounded-md px-2 py-1.5 hover:bg-hover">
                <input
                  type="checkbox"
                  className="mt-0.5 size-4 accent-accent"
                  checked={selected.has(t.id) || from !== undefined}
                  disabled={from !== undefined && !selected.has(t.id)}
                  onChange={(e) => {
                    const next = new Set(selected);
                    if (e.target.checked) next.add(t.id);
                    else next.delete(t.id);
                    setSelected(next);
                  }}
                />
                <span className="flex min-w-0 flex-col gap-0.5">
                  <span className="flex flex-wrap items-center gap-2">
                    <TagChip tag={t} />
                    {t.hasPolicy && <span className="text-xs text-muted">Has a policy, priority {t.priority}</span>}
                    {from && <span className="text-xs text-muted">({from})</span>}
                  </span>
                  {t.description && <span className="text-xs text-subtle">{t.description}</span>}
                </span>
              </label>
            );
          })}
        </fieldset>
      )}
      {tooMany && (
        <Alert tone="warn" className="mt-3">
          Choose at most {MAX_TAGS} tags.
        </Alert>
      )}
      <InlineError error={save.error} />
    </Dialog>
  );
}

/** Settings → Patching → Tags: every tag, with its priority, policy and where it is used. */
export function TagsManager({ onPolicy }: { onPolicy: (tag: PatchTag) => void }) {
  const toast = useToast();
  const { canGlobal } = useAuth();
  // A tag's policy is EasyPatch's server-wide, so reading it needs patching everywhere.
  const seePolicies = canGlobal("patch.view");
  const list = useApi<PatchTagList>("/patching/tags");
  const [form, setForm] = useState<{ open: boolean; tag?: PatchTag }>({ open: false });
  const [deleting, setDeleting] = useState<PatchTag | null>(null);
  const remove = useApiMutation((t: PatchTag) => api.del(`/patching/tags/${t.id}`), {
    invalidate: ["/patching"],
    onSuccess: (_, t) => {
      toast.success(`Tag “${t.name}” deleted.`);
      setDeleting(null);
    },
  });
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  const { items, canManage } = list.data;
  return (
    <Card
      title="Tags"
      padded={false}
      actions={
        canManage && (
          <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setForm({ open: true })}>
            Add tag
          </Button>
        )
      }
    >
      <p className="border-b border-line px-4 py-3 text-sm text-muted">
        A tag's policy applies to the devices that have the tag, directly or through their site or organization. It overrides
        their site's and organization's policy and is overridden by a device's own. When tags disagree, the higher priority wins.
      </p>
      {items.length === 0 ? (
        <EmptyState
          title="No tags yet"
          icon={<TagIcon className="size-8" aria-hidden />}
          action={
            canManage ? (
              <Button variant="primary" onClick={() => setForm({ open: true })}>
                Add the first tag
              </Button>
            ) : undefined
          }
        >
          Tags group devices across organizations, for example Pilot ring or Servers, so one policy can apply to all of them.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Tag</th>
                <th className="text-right">Priority</th>
                <th>Policy</th>
                <th className="hidden md:table-cell">Used by</th>
                {canManage && <th className="w-0" aria-label="Actions" />}
              </tr>
            </thead>
            <tbody>
              {items.map((t) => (
                <tr key={t.id}>
                  <td>
                    <TagChip tag={t} />
                    {t.description && <p className="mt-1 max-w-md text-xs text-muted">{t.description}</p>}
                  </td>
                  <td className="text-right tabular-nums">{t.priority}</td>
                  <td>
                    {seePolicies && (canManage || t.hasPolicy) ? (
                      <button type="button" className="text-left text-accent hover:underline" onClick={() => onPolicy(t)}>
                        {!canManage ? "View policy" : t.hasPolicy ? "Edit policy" : "Add a policy"}
                      </button>
                    ) : (
                      <span className="text-muted">{t.hasPolicy ? "Has a policy" : "None"}</span>
                    )}
                  </td>
                  <td className="hidden text-muted md:table-cell">
                    {[plural(t.endpointCount, "device"), plural(t.siteCount, "site"), plural(t.organizationCount, "organization")].join(", ")}
                  </td>
                  {canManage && (
                    <td className="whitespace-nowrap">
                      <span className="flex justify-end gap-1">
                        <IconButton label={`Edit ${t.name}`} onClick={() => setForm({ open: true, tag: t })}>
                          <Pencil className="size-4" aria-hidden />
                        </IconButton>
                        <IconButton label={`Delete ${t.name}`} onClick={() => setDeleting(t)}>
                          <Trash2 className="size-4" aria-hidden />
                        </IconButton>
                      </span>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <TagFormDialog open={form.open} tag={form.tag} onClose={() => setForm({ open: false })} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => {
          setDeleting(null);
          remove.reset();
        }}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title="Delete tag"
        confirmLabel="Delete tag"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
        confirmText={deleting?.name}
      >
        {deleting && (
          <p>
            This deletes <strong>{deleting.name}</strong>
            {deleting.hasPolicy ? " and its policy" : ""}, and takes it off {plural(deleting.endpointCount, "device")},{" "}
            {plural(deleting.siteCount, "site")} and {plural(deleting.organizationCount, "organization")}. Their own, site and
            organization policies apply again.
          </p>
        )}
      </ConfirmDialog>
    </Card>
  );
}

function TagFormDialog({ open, tag, onClose }: { open: boolean; tag?: PatchTag; onClose: () => void }) {
  const toast = useToast();
  const [name, setName] = useState("");
  const [color, setColor] = useState<TagColor>("blue");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("0");
  useEffect(() => {
    if (!open) return;
    setName(tag?.name ?? "");
    setColor(tag?.color ?? "blue");
    setDescription(tag?.description ?? "");
    setPriority(String(tag?.priority ?? 0));
  }, [open, tag]);
  const save = useApiMutation(
    (body: { name: string; color: TagColor; description: string | null; priority: number }) =>
      tag ? api.put<PatchTag>(`/patching/tags/${tag.id}`, body) : api.post<PatchTag>("/patching/tags", body),
    {
      invalidate: ["/patching"],
      onSuccess: (t) => {
        toast.success(tag ? `Tag “${t.name}” saved.` : `Tag “${t.name}” added.`);
        onClose();
      },
    },
  );
  const n = Number(priority);
  const priorityError = priority.trim() === "" || !Number.isInteger(n) || n < 0 || n > 1000 ? "Choose a priority from 0 to 1000." : null;
  const nameError = name.trim() === "" ? "Give the tag a name." : null;
  function submit(e: FormEvent) {
    e.preventDefault();
    if (priorityError || nameError) return;
    save.mutate({ name: name.trim(), color, description: description.trim() || null, priority: n });
  }
  return (
    <Dialog
      open={open}
      onClose={() => {
        onClose();
        save.reset();
      }}
      title={tag ? "Edit tag" : "Add tag"}
      size="sm"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="tag-form" loading={save.isPending}>
            {tag ? "Save tag" : "Add tag"}
          </Button>
        </>
      }
    >
      <form id="tag-form" onSubmit={submit} className="flex flex-col gap-3.5" noValidate>
        <TextField
          label="Name"
          value={name}
          maxLength={40}
          onChange={(e) => setName(e.target.value)}
          error={fieldError(save.error, "name") ?? (save.isError ? nameError : null)}
          required
          autoFocus
        />
        <SelectField label="Colour" value={color} onChange={(e) => setColor(e.target.value as TagColor)} error={fieldError(save.error, "color")}>
          {TAG_COLORS.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Priority"
          type="number"
          inputMode="numeric"
          min={0}
          max={1000}
          value={priority}
          onChange={(e) => setPriority(e.target.value)}
          hint="When devices have several tags with policies, the highest priority wins."
          error={fieldError(save.error, "priority") ?? priorityError}
        />
        <TextareaField
          label="Description"
          value={description}
          maxLength={500}
          onChange={(e) => setDescription(e.target.value)}
          error={fieldError(save.error, "description")}
        />
        <p className="flex items-center gap-2 text-xs text-muted">
          Shown as <TagChip tag={{ name: name.trim() || "Tag", color }} />
        </p>
        <InlineError error={save.error} fields={["name", "color", "priority", "description"]} />
      </form>
    </Dialog>
  );
}
