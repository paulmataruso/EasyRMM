import { useEffect, useId, useState, type FormEvent } from "react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { Site, SiteInput } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, Field, InlineError, Input, TextareaField, TextField } from "../../components/ui";
import { browserTimeZone, timeZones } from "../../lib/format";

function blankSite(): SiteInput {
  return { name: "", timezone: browserTimeZone(), address: "", notes: "" };
}

/** Creates a site in an organization, or edits an existing site. */
export function SiteFormDialog({ open, onClose, onSaved, organizationId, site }: {
  open: boolean;
  onClose: () => void;
  onSaved: (site: Site) => void;
  organizationId: string;
  site?: Site;
}) {
  const toast = useToast();
  const [form, setForm] = useState<SiteInput>(blankSite);
  useEffect(() => {
    if (open) setForm(site ? { name: site.name, timezone: site.timezone, address: site.address, notes: site.notes } : blankSite());
  }, [open, site]);

  const save = useApiMutation(
    (req: SiteInput) => (site ? api.put<Site>(`/sites/${site.id}`, req) : api.post<Site>(`/organizations/${organizationId}/sites`, req)),
    {
      invalidate: ["/organizations", "/sites", "/audit"],
      onSuccess: (s) => {
        toast.success(site ? "Site updated." : `Site “${s.name}” created.`);
        onSaved(s);
      },
    },
  );
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const set = <K extends keyof SiteInput>(k: K, v: SiteInput[K]) => setForm((f) => ({ ...f, [k]: v }));

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ name: form.name.trim(), timezone: form.timezone.trim(), address: form.address.trim(), notes: form.notes.trim() });
  }

  return (
    <Dialog open={open} onClose={onClose} title={site ? "Edit site" : "New site"}>
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField label="Name" value={form.name} onChange={(e) => set("name", e.target.value)} error={fieldError(save.error, "name")} required maxLength={200} autoFocus />
        <TimeZoneField value={form.timezone} onChange={(v) => set("timezone", v)} error={fieldError(save.error, "timezone")} />
        <TextField label="Address" value={form.address} onChange={(e) => set("address", e.target.value)} error={fieldError(save.error, "address")} maxLength={500} />
        <TextareaField label="Notes" value={form.notes} onChange={(e) => set("notes", e.target.value)} error={fieldError(save.error, "notes")} maxLength={4000} />
        <InlineError error={save.error} fields={["name", "timezone", "address", "notes"]} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim() || !form.timezone.trim()}>
            {site ? "Save changes" : "Create site"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export function TimeZoneField({ value, onChange, error }: { value: string; onChange: (v: string) => void; error?: string | null }) {
  const zones = timeZones();
  const id = useId();
  return (
    <Field label="Time zone" htmlFor={`${id}-input`} error={error} hint="IANA time zone, e.g. America/New_York. Used for schedules and reports." required>
      <Input
        id={`${id}-input`}
        list={`${id}-options`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required
        autoComplete="off"
        aria-invalid={error ? true : undefined}
      />
      <datalist id={`${id}-options`}>
        {zones.map((z) => (
          <option key={z} value={z} />
        ))}
      </datalist>
    </Field>
  );
}
