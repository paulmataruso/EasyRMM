import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useSites } from "../../api/hooks";
import type { MaintenanceWindow, MaintenanceWindowInput } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Badge, Button, Card, EmptyState, ErrorState, InlineError, SelectField, Spinner, TableWrap, TextField } from "../../components/ui";

const WINDOWS = "/maintenance-windows";
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function when(w: MaintenanceWindow): string {
  const length = w.lengthMinutes % 60 === 0 ? `${w.lengthMinutes / 60} h` : `${w.lengthMinutes} min`;
  if (w.kind === "once") return `${(w.startsAt ?? "").replace("T", " ")} for ${length}`;
  return `${w.days.map((d) => DAYS[d]).join(", ")} at ${w.start} for ${length}`;
}

/**
 * Maintenance windows, by site (ADR-0053): during one, a site's devices still raise alerts in the console, but an
 * organization's rules send nothing new about them; what is still open when it ends is sent in one message.
 * With no organization it is the read-only list Settings shows.
 */
export function WindowsPanel({ organizationId }: { organizationId: string | null }) {
  const q = useApi<{ windows: MaintenanceWindow[] }>(WINDOWS, { organizationId }, { refetchInterval: 30_000 });
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<MaintenanceWindow | null>(null);
  const toast = useToast();
  const remove = useApiMutation((w: MaintenanceWindow) => api.del(`${WINDOWS}/${w.id}`), {
    invalidate: [WINDOWS, "/audit"],
    onSuccess: () => {
      setDeleting(null);
      toast.success("Window deleted.");
    },
  });
  const rows = q.data?.windows ?? [];
  const editable = organizationId !== null;
  return (
    <>
      <Card
        title="Maintenance windows"
        actions={
          editable && (
            <Button variant="primary" size="sm" icon={<Plus className="size-4" aria-hidden />} onClick={() => setAdding(true)}>
              Add window
            </Button>
          )
        }
        padded={false}
      >
        {q.isPending ? (
          <div className="p-4">
            <Spinner />
          </div>
        ) : q.isError ? (
          <div className="p-4">
            <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState title="No maintenance windows" compact>
            {editable ? "Add one to hold notifications while a site is worked on." : "Site administrators manage them on the organization's Notifications tab."}
          </EmptyState>
        ) : (
          <TableWrap className="rounded-none border-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-muted">
                  <th className="px-4 py-2 font-medium">Site</th>
                  <th className="px-4 py-2 font-medium">Window</th>
                  <th className="px-4 py-2 font-medium">When (site time)</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {rows.map((w) => (
                  <tr key={w.id} className="border-b border-line last:border-0">
                    <td className="px-4 py-2 align-top">{w.siteName}</td>
                    <td className="px-4 py-2 align-top">
                      {w.name} {w.active && <Badge tone="warn">Holding now</Badge>} {!w.enabled && <Badge tone="neutral">Off</Badge>}
                    </td>
                    <td className="px-4 py-2 align-top text-xs">{when(w)}</td>
                    <td className="px-4 py-2 text-right align-top">
                      {editable && w.canEdit && (
                        <Button size="sm" variant="danger-ghost" icon={<Trash2 className="size-4" aria-hidden />} onClick={() => setDeleting(w)}>
                          Delete
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
      {adding && organizationId && <WindowDialog organizationId={organizationId} onClose={() => setAdding(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title={`Delete ${deleting?.name ?? "window"}?`}
        confirmLabel="Delete window"
        onConfirm={() => deleting && remove.mutate(deleting)}
        loading={remove.isPending} tone="danger"
      >
        Notifications about the site&apos;s devices are no longer held by it.
      </ConfirmDialog>
    </>
  );
}

function WindowDialog({ organizationId, onClose }: { organizationId: string; onClose: () => void }) {
  const toast = useToast();
  const sites = useSites(organizationId);
  const [siteId, setSiteId] = useState("");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"weekly" | "once">("weekly");
  const [days, setDays] = useState<number[]>([6]);
  const [start, setStart] = useState("22:00");
  const [startsAt, setStartsAt] = useState("");
  const [hours, setHours] = useState(4);
  const site = siteId || sites.data?.items[0]?.id || "";
  const create = useApiMutation((input: MaintenanceWindowInput) => api.post<MaintenanceWindow>(`/sites/${site}/maintenance-windows`, input), {
    invalidate: [WINDOWS, "/audit"],
    onSuccess: () => {
      toast.success("Window added.");
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title="Add a maintenance window" description="Times are the site's own clock. A window across midnight belongs to the day it starts.">
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate(kind === "weekly" ? { name, kind, days, start, lengthMinutes: Math.round(hours * 60), enabled: true } : { name, kind, days: [], startsAt, lengthMinutes: Math.round(hours * 60), enabled: true });
        }}
      >
        <SelectField label="Site" value={site} onChange={(e) => setSiteId(e.target.value)}>
          {(sites.data?.items ?? []).map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </SelectField>
        <TextField label="Name" required value={name} maxLength={100} onChange={(e) => setName(e.target.value)} error={fieldError(create.error, "name")} />
        <SelectField label="Repeats" value={kind} onChange={(e) => setKind(e.target.value as "weekly" | "once")}>
          <option value="weekly">Every week</option>
          <option value="once">Once</option>
        </SelectField>
        {kind === "weekly" ? (
          <>
            <fieldset className="flex flex-wrap gap-3">
              <legend className="mb-1 text-sm font-medium">Days</legend>
              {DAYS.map((d, i) => (
                <label key={d} className="flex items-center gap-1.5 text-sm">
                  <input type="checkbox" className="size-4 accent-accent" checked={days.includes(i)} onChange={(e) => setDays(e.target.checked ? [...days, i] : days.filter((x) => x !== i))} />
                  {d}
                </label>
              ))}
            </fieldset>
            <TextField label="Starts at" type="time" required value={start} onChange={(e) => setStart(e.target.value)} error={fieldError(create.error, "start")} />
          </>
        ) : (
          <TextField label="Starts" type="datetime-local" required value={startsAt} onChange={(e) => setStartsAt(e.target.value)} hint="Within 90 days; at most 7 days long." error={fieldError(create.error, "startsAt")} />
        )}
        <TextField label="Lasts (hours)" type="number" min={0.5} max={kind === "weekly" ? 24 : 168} step={0.5} value={hours} onChange={(e) => setHours(Number(e.target.value))} error={fieldError(create.error, "lengthMinutes")} />
        <InlineError error={create.error} fields={["name", "start", "startsAt", "lengthMinutes"]} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={!site}>
            Add window
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
