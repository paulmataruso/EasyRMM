// Places within a site (ADR-0066): buildings, floors, rooms and racks, each inside another place of the site or at
// its top, at most four deep.

import { useEffect, useState, type FormEvent } from "react";
import { Building2, Pencil, Plus, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation, useList } from "../../api/hooks";
import type { Place, PlaceInput, PlaceKind, Site } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Badge, Button, Card, EmptyState, ErrorState, IconButton, InlineError, SelectField, Spinner, TextField } from "../../components/ui";

const PLACE_KINDS: [PlaceKind, string][] = [
  ["building", "Building"],
  ["floor", "Floor"],
  ["room", "Room"],
  ["rack", "Rack"],
  ["other", "Other"],
];

/** The most places one inside another. */
const MAX_DEPTH = 4;

function placeKindLabel(kind: string): string {
  return PLACE_KINDS.find(([k]) => k === kind)?.[1] ?? kind;
}

/** The place and every place inside it; the list is in tree order, so they follow it. */
function withInside(places: Place[], place: Place): Set<string> {
  const out = new Set([place.id]);
  for (const p of places) if (p.parentId && out.has(p.parentId)) out.add(p.id);
  return out;
}

/** How many levels a place and the places inside it take. */
function height(places: Place[], place: Place): number {
  const inside = withInside(places, place);
  return Math.max(...places.filter((p) => inside.has(p.id)).map((p) => p.depth)) - place.depth + 1;
}

/** Where a place is, from the top of the site: "Main › Floor 1". */
function placePath(byId: Map<string, Place>, place: Place): string {
  const names = [place.name];
  for (let p = place.parentId ? byId.get(place.parentId) : undefined; p; p = p.parentId ? byId.get(p.parentId) : undefined) names.unshift(p.name);
  return names.join(" › ");
}

/** The places inside each place, by its ID, and those at the top under "". The list is in tree order, so each stays in it. */
function childrenOf(places: Place[]): Map<string, Place[]> {
  const out = new Map<string, Place[]>();
  for (const p of places) {
    const key = p.parentId ?? "";
    out.set(key, [...(out.get(key) ?? []), p]);
  }
  return out;
}

export function PlacesCard({ site, className }: { site: Site; className?: string }) {
  const toast = useToast();
  const list = useList<Place>(`/sites/${site.id}/places`);
  const [form, setForm] = useState<{ open: boolean; place?: Place; parentId?: string | null }>({ open: false });
  const [deleting, setDeleting] = useState<Place | null>(null);
  const remove = useApiMutation((p: Place) => api.del(`/places/${p.id}`), {
    invalidate: [`/sites/${site.id}/places`, "/audit"],
    onSuccess: (_, p) => {
      toast.success(`${placeKindLabel(p.kind)} “${p.name}” deleted.`);
      setDeleting(null);
    },
  });
  const manage = site.canManageDocumentation;
  const children = childrenOf(list.items);

  // A list within a list for the places inside a place, so that a screen reader says how deep each is.
  const tree = (parentId: string, label?: string) => (
    <ul className={label ? "divide-y divide-line" : "divide-y divide-line border-t border-line"} aria-label={label}>
      {(children.get(parentId) ?? []).map((p) => (
        <li key={p.id}>
          <div className="flex items-center gap-2 py-1.5 pr-4" style={{ paddingLeft: `${p.depth}rem` }}>
            <Badge>{placeKindLabel(p.kind)}</Badge>
            <span className="min-w-0 flex-1 truncate font-medium">{p.name}</span>
            {manage && (
              <span className="whitespace-nowrap">
                {p.depth < MAX_DEPTH && (
                  <IconButton label={`Add a place inside ${p.name}`} onClick={() => setForm({ open: true, parentId: p.id })}>
                    <Plus className="size-4" aria-hidden />
                  </IconButton>
                )}
                <IconButton label={`Edit ${p.name}`} onClick={() => setForm({ open: true, place: p })}>
                  <Pencil className="size-4" aria-hidden />
                </IconButton>
                <IconButton label={`Delete ${p.name}`} onClick={() => setDeleting(p)} className="hover:text-danger">
                  <Trash2 className="size-4" aria-hidden />
                </IconButton>
              </span>
            )}
          </div>
          {children.has(p.id) && tree(p.id)}
        </li>
      ))}
    </ul>
  );

  return (
    <Card
      title="Places"
      className={className}
      padded={false}
      actions={
        manage && (
          <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setForm({ open: true, parentId: null })}>
            Add place
          </Button>
        )
      }
    >
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : list.items.length === 0 ? (
        <EmptyState title="No places yet" icon={<Building2 className="size-8" aria-hidden />} compact>
          Where things are within the site: buildings, floors, rooms and racks.
        </EmptyState>
      ) : (
        tree("", `Places at ${site.name}`)
      )}
      <PlaceDialog
        open={form.open}
        onClose={() => setForm({ open: false })}
        site={site}
        places={list.items}
        place={form.place}
        parentId={form.parentId ?? null}
      />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => {
          setDeleting(null);
          remove.reset();
        }}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title="Delete place"
        confirmLabel="Delete place"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        <p>
          Delete <strong>{deleting?.name}</strong> from {site.name}? A place with places inside it cannot be deleted until they are moved or deleted.
        </p>
      </ConfirmDialog>
    </Card>
  );
}

/**
 * What an edit changed, and nothing else, so that a stale form cannot move a place back to where it was when the
 * form opened.
 */
function placeChanges(before: Place, form: PlaceInput): Partial<PlaceInput> {
  const out: Partial<PlaceInput> = {};
  if (form.kind !== before.kind) out.kind = form.kind;
  if (form.name !== before.name) out.name = form.name;
  if (form.parentId !== before.parentId) out.parentId = form.parentId;
  return out;
}

function PlaceDialog({ open, onClose, site, places, place, parentId }: {
  open: boolean;
  onClose: () => void;
  site: Site;
  places: Place[];
  place?: Place;
  parentId: string | null;
}) {
  const toast = useToast();
  const [form, setForm] = useState<PlaceInput>({ parentId: null, kind: "building", name: "" });
  useEffect(() => {
    if (open) setForm(place ? { parentId: place.parentId, kind: place.kind, name: place.name } : { parentId, kind: parentId ? "room" : "building", name: "" });
  }, [open, place, parentId]);
  const save = useApiMutation(
    (req: PlaceInput) => (place ? api.patch<Place>(`/places/${place.id}`, placeChanges(place, req)) : api.post<Place>(`/sites/${site.id}/places`, req)),
    {
      invalidate: [`/sites/${site.id}/places`, "/audit"],
      onSuccess: (p) => {
        toast.success(place ? "Place updated." : `${placeKindLabel(p.kind)} “${p.name}” added.`);
        onClose();
      },
    },
  );
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  const set = <K extends keyof PlaceInput>(k: K, v: PlaceInput[K]) => setForm((f) => ({ ...f, [k]: v }));

  // A place may go inside any place but itself and those inside it, as long as it and they stay within four levels.
  const moving = place ? withInside(places, place) : new Set<string>();
  const levels = place ? height(places, place) : 1;
  const parents = places.filter((p) => !moving.has(p.id) && p.depth + levels <= MAX_DEPTH);
  const byId = new Map(places.map((p) => [p.id, p]));

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ ...form, name: form.name.trim() });
  }

  return (
    <Dialog open={open} onClose={onClose} title={place ? "Edit place" : "New place"} description={site.name} size="sm">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <SelectField label="Kind" value={form.kind} onChange={(e) => set("kind", e.target.value as PlaceKind)} error={fieldError(save.error, "kind")}>
          {PLACE_KINDS.map(([k, label]) => (
            <option key={k} value={k}>
              {label}
            </option>
          ))}
        </SelectField>
        <TextField label="Name" value={form.name} onChange={(e) => set("name", e.target.value)} error={fieldError(save.error, "name")} required maxLength={200} autoFocus />
        <SelectField label="Inside" value={form.parentId ?? ""} onChange={(e) => set("parentId", e.target.value || null)} error={fieldError(save.error, "parentId")}>
          <option value="">The site itself</option>
          {parents.map((p) => (
            <option key={p.id} value={p.id}>
              {`${placePath(byId, p)} (${placeKindLabel(p.kind)})`}
            </option>
          ))}
        </SelectField>
        <InlineError error={save.error} fields={["kind", "name", "parentId"]} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim()}>
            {place ? "Save changes" : "Add place"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
