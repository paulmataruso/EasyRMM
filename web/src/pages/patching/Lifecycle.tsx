import { useState, type FormEvent } from "react";
import { CalendarX2, Pencil, Plus, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchLifecycleEntry, PatchLifecycleInput, PatchLifecycleList } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Badge, Button, Card, EmptyState, ErrorState, Field, IconButton, InlineError, Select, SelectField, Spinner, TableWrap, TextareaField, TextField } from "../../components/ui";

// Settings → Patching → OS lifecycle (one-product plan, C6): when each operating system build stops getting security
// updates. EasyPatch matches a device's product, edition group and build to an entry to say whether its operating system
// is still supported; super administrators keep the dates.

/** The products EasyPatch matches devices to: an entry for any other never matches. */
const WINDOWS = ["Windows 10", "Windows 11", "Windows Server"];
const LINUX = ["Debian", "Ubuntu", "Red Hat Enterprise Linux", "Rocky Linux", "AlmaLinux", "Oracle Linux", "CentOS Stream", "Fedora"];

/** Windows editions, as EasyPatch groups them. Linux releases match on product and release only. */
const EDITIONS: Record<string, string> = {
  HomePro: "Home and Pro",
  EnterpriseEducation: "Enterprise and Education",
  LTSC: "Enterprise LTSC",
  IoTLTSC: "IoT Enterprise LTSC",
  Server: "Server",
  LTS: "LTS",
  Any: "Any edition",
};

function editionsFor(product: string): string[] {
  if (product === "Windows Server") return ["Server", "Any"];
  if (WINDOWS.includes(product)) return ["HomePro", "EnterpriseEducation", "LTSC", "IoTLTSC", "Any"];
  return [];
}

/** The edition group a Linux entry is saved with: EasyPatch's own Ubuntu entries say LTS. */
function linuxEdition(product: string): string {
  return product === "Ubuntu" ? "LTS" : "Any";
}

function buildHint(product: string): string {
  if (WINDOWS.includes(product)) return "Windows' build number, as 26100 for 24H2.";
  if (product === "Ubuntu") return "The release's year and month, as 2404 for 24.04.";
  return "The major version, as 12 for Debian 12.";
}

/** "13 Oct 2026", from 2006-01-02, the same day wherever the browser is. */
function day(date: string): string {
  const [y, m, d] = date.split("-").map(Number);
  return new Date(y ?? 1970, (m ?? 1) - 1, d ?? 1).toLocaleDateString(undefined, { dateStyle: "medium" });
}

function today(): string {
  const n = new Date();
  return `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, "0")}-${String(n.getDate()).padStart(2, "0")}`;
}

/** Six months from today, as 2006-01-02. */
function soon(): string {
  const n = new Date();
  n.setMonth(n.getMonth() + 6);
  return `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, "0")}-${String(n.getDate()).padStart(2, "0")}`;
}

function Support({ entry }: { entry: PatchLifecycleEntry }) {
  const now = today();
  if (entry.endOfServicing >= now) {
    return entry.endOfServicing <= soon() ? <Badge tone="warn">Ends soon</Badge> : <Badge tone="ok">Supported</Badge>;
  }
  if (entry.esuEndDate && entry.esuEndDate >= now) return <Badge tone="warn">Extended updates only</Badge>;
  return <Badge tone="danger">Ended</Badge>;
}

export function LifecyclePanel() {
  const toast = useToast();
  const list = useApi<PatchLifecycleList>("/patching/lifecycle");
  const [product, setProduct] = useState("");
  const [form, setForm] = useState<{ open: boolean; entry?: PatchLifecycleEntry }>({ open: false });
  const [deleting, setDeleting] = useState<PatchLifecycleEntry | null>(null);
  const remove = useApiMutation((e: PatchLifecycleEntry) => api.del(`/patching/lifecycle/${e.id}`), {
    invalidate: ["/patching"],
    onSuccess: (_, e) => {
      toast.success(`${e.product} ${e.versionLabel} deleted.`);
      setDeleting(null);
    },
  });
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  const { items, canEdit } = list.data;
  const products = [...new Set(items.map((e) => e.product))];
  const shown = product ? items.filter((e) => e.product === product) : items;
  return (
    <Card
      title="Operating system lifecycle"
      padded={false}
      actions={
        canEdit && (
          <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setForm({ open: true })}>
            Add entry
          </Button>
        )
      }
    >
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-line px-4 py-3">
        <p className="max-w-2xl text-sm text-muted">
          When each operating system build stops getting security updates. A device whose build has no entry shows its support as
          unknown; one past its date shows as unsupported, or on extended security updates where it has them.
        </p>
        {products.length > 1 && (
          <Field label="Product" htmlFor="lifecycle-product" className="min-w-48">
            <Select id="lifecycle-product" value={product} onChange={(e) => setProduct(e.target.value)}>
              <option value="">All products</option>
              {products.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </Select>
          </Field>
        )}
      </div>
      {!canEdit && <p className="border-b border-line px-4 py-3 text-sm text-muted">Only super administrators change these dates.</p>}
      {shown.length === 0 ? (
        <EmptyState title="No entries" icon={<CalendarX2 className="size-8" aria-hidden />}>
          Without entries, every device&apos;s operating system support is unknown.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <caption className="sr-only">Operating system lifecycle</caption>
            <thead>
              <tr>
                <th scope="col">Operating system</th>
                <th scope="col" className="hidden sm:table-cell">
                  Edition
                </th>
                <th scope="col" className="hidden text-right md:table-cell">
                  Build
                </th>
                <th scope="col">Security updates end</th>
                <th scope="col" className="hidden lg:table-cell">
                  Extended updates end
                </th>
                <th scope="col" className="hidden sm:table-cell">
                  Support
                </th>
                {canEdit && (
                  <th scope="col" className="w-0">
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {shown.map((e) => (
                <tr key={e.id} className="align-top">
                  <td>
                    <span className="font-medium">
                      {e.product} {e.versionLabel}
                    </span>
                    {e.notes && <p className="mt-0.5 max-w-md text-xs text-muted">{e.notes}</p>}
                  </td>
                  <td className="hidden whitespace-nowrap sm:table-cell">{EDITIONS[e.editionGroup] ?? e.editionGroup}</td>
                  <td className="hidden text-right tabular-nums md:table-cell">{e.buildNumber}</td>
                  <td className="whitespace-nowrap">
                    {day(e.endOfServicing)}
                    {/* On a phone, the support state goes under the date. */}
                    <span className="mt-1 block sm:hidden">
                      <Support entry={e} />
                    </span>
                  </td>
                  <td className="hidden whitespace-nowrap lg:table-cell">{e.esuEndDate ? day(e.esuEndDate) : <span className="text-subtle">—</span>}</td>
                  <td className="hidden sm:table-cell">
                    <Support entry={e} />
                  </td>
                  {canEdit && (
                    <td className="whitespace-nowrap">
                      <span className="flex justify-end gap-1">
                        <IconButton label={`Edit ${e.product} ${e.versionLabel}`} onClick={() => setForm({ open: true, entry: e })}>
                          <Pencil className="size-4" aria-hidden />
                        </IconButton>
                        <IconButton label={`Delete ${e.product} ${e.versionLabel}`} onClick={() => setDeleting(e)}>
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
      {/* Remounted on each opening, so it starts from the entry as it is then. */}
      <EntryDialog key={form.open ? (form.entry?.id ?? "new") : "closed"} open={form.open} entry={form.entry} onClose={() => setForm({ open: false })} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => {
          setDeleting(null);
          remove.reset();
        }}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title="Delete entry"
        confirmLabel="Delete entry"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        {deleting && (
          <p>
            Devices on {deleting.product} {deleting.versionLabel} ({EDITIONS[deleting.editionGroup] ?? deleting.editionGroup}, build{" "}
            {deleting.buildNumber}) will show their support as unknown.
          </p>
        )}
      </ConfirmDialog>
    </Card>
  );
}

function EntryDialog({ open, entry, onClose }: { open: boolean; entry?: PatchLifecycleEntry; onClose: () => void }) {
  const toast = useToast();
  const [product, setProduct] = useState(entry?.product ?? "Windows 11");
  const [edition, setEdition] = useState(entry?.editionGroup ?? "HomePro");
  const [build, setBuild] = useState(entry ? String(entry.buildNumber) : "");
  const [version, setVersion] = useState(entry?.versionLabel ?? "");
  const [end, setEnd] = useState(entry?.endOfServicing ?? "");
  const [esu, setEsu] = useState(entry?.esuEndDate ?? "");
  const [notes, setNotes] = useState(entry?.notes ?? "");
  const [tried, setTried] = useState(false);
  const save = useApiMutation(
    (body: PatchLifecycleInput) =>
      entry ? api.put<PatchLifecycleEntry>(`/patching/lifecycle/${entry.id}`, body) : api.post<PatchLifecycleEntry>("/patching/lifecycle", body),
    {
      invalidate: ["/patching"],
      onSuccess: (e) => {
        toast.success(entry ? `${e.product} ${e.versionLabel} saved.` : `${e.product} ${e.versionLabel} added.`);
        onClose();
      },
    },
  );
  const editions = editionsFor(product);
  // Keep a product or Windows edition EasyPatch's console saved that EasyRMM does not offer.
  const other = entry && !WINDOWS.includes(entry.product) && !LINUX.includes(entry.product) ? entry.product : null;
  const unchanged = entry !== undefined && entry.product === product;
  const editionOptions = unchanged && editions.length > 0 && !editions.includes(entry.editionGroup) ? [...editions, entry.editionGroup] : editions;
  const n = Number(build);
  const errors = {
    buildNumber: build.trim() === "" || !Number.isInteger(n) || n < 1 || n > 1_000_000 ? "Enter a build from 1 to 1,000,000." : null,
    versionLabel: version.trim() === "" ? "Name the version, as 24H2 or 24.04 LTS." : null,
    endOfServicing: end === "" ? "Choose the date security updates end." : null,
    esuEndDate: esu !== "" && end !== "" && esu < end ? "Extended updates end on or after the end of security updates." : null,
  };
  const blocked = Object.values(errors).some(Boolean);
  const show = (k: keyof typeof errors) => fieldError(save.error, k) ?? (tried ? errors[k] : null);

  function submit(e: FormEvent) {
    e.preventDefault();
    setTried(true);
    if (blocked) return;
    save.mutate({
      product,
      editionGroup: editions.length > 0 ? edition : unchanged ? entry.editionGroup : linuxEdition(product),
      buildNumber: n,
      versionLabel: version.trim(),
      endOfServicing: end,
      esuEndDate: esu === "" ? null : esu,
      notes: notes.trim() === "" ? null : notes.trim(),
    });
  }

  return (
    <Dialog
      open={open}
      onClose={() => {
        onClose();
        save.reset();
      }}
      title={entry ? "Edit lifecycle entry" : "Add lifecycle entry"}
      description="Check the dates against the vendor's lifecycle page: Microsoft's, or the distribution's release schedule."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="lifecycle-form" loading={save.isPending}>
            {entry ? "Save entry" : "Add entry"}
          </Button>
        </>
      }
    >
      <form id="lifecycle-form" onSubmit={submit} className="grid gap-3.5 sm:grid-cols-2" noValidate>
        <SelectField
          label="Product"
          value={product}
          onChange={(e) => {
            const next = e.target.value;
            setProduct(next);
            const options = editionsFor(next);
            setEdition(options.includes(edition) ? edition : (options[0] ?? linuxEdition(next)));
          }}
          error={fieldError(save.error, "product")}
          className={editionOptions.length === 0 ? "sm:col-span-2" : undefined}
        >
          <optgroup label="Windows">
            {WINDOWS.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </optgroup>
          <optgroup label="Linux">
            {LINUX.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </optgroup>
          {other && (
            <optgroup label="Other">
              <option>{other}</option>
            </optgroup>
          )}
        </SelectField>
        {editionOptions.length > 0 && (
          <SelectField label="Edition" value={edition} onChange={(e) => setEdition(e.target.value)} error={fieldError(save.error, "editionGroup")}>
            {editionOptions.map((g) => (
              <option key={g} value={g}>
                {EDITIONS[g] ?? g}
              </option>
            ))}
          </SelectField>
        )}
        <TextField
          label="Build"
          type="number"
          inputMode="numeric"
          min={1}
          max={1_000_000}
          value={build}
          onChange={(e) => setBuild(e.target.value)}
          hint={buildHint(product)}
          error={show("buildNumber")}
          required
        />
        <TextField label="Version" value={version} maxLength={50} onChange={(e) => setVersion(e.target.value)} hint="As people know it: 24H2, 2025 or 24.04 LTS." error={show("versionLabel")} required />
        <TextField label="Security updates end" type="date" value={end} onChange={(e) => setEnd(e.target.value)} error={show("endOfServicing")} required />
        <TextField
          label="Extended updates end"
          type="date"
          value={esu}
          onChange={(e) => setEsu(e.target.value)}
          hint="Optional: paid extended security updates, for devices enrolled in them."
          error={show("esuEndDate")}
        />
        <TextareaField label="Notes" value={notes} maxLength={1000} rows={2} onChange={(e) => setNotes(e.target.value)} error={fieldError(save.error, "notes")} className="sm:col-span-2" />
      </form>
      <InlineError error={save.error} fields={["product", "editionGroup", "buildNumber", "versionLabel", "endOfServicing", "esuEndDate", "notes"]} />
    </Dialog>
  );
}
