// The customer record (ADR-0066): an organization's contact information, a site's address, and the business hours of
// both. Contacts and places have their own files.

import { useEffect, useId, useState, type FormEvent } from "react";
import { Copy, Plus, X } from "lucide-react";
import { api, ApiError, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { BusinessHours, Organization, OrganizationDetails, Site, SiteDetails } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Badge, Button, Field, IconButton, InlineError, Input, KeyValueList, SelectField, TextareaField, TextField } from "../../components/ui";
import { countryName, countryOptions } from "../../lib/countries";
import { copyHours, hoursOrNull, MAX_PERIODS_PER_DAY, summarizeHours, WEEKDAYS } from "../../lib/hours";

/** Open or closed now, by the business hours; nothing when none are kept. */
export function OpenNowBadge({ openNow }: { openNow: boolean | null }) {
  if (openNow === null) return null;
  return openNow ? <Badge tone="ok">Open now</Badge> : <Badge tone="neutral">Closed now</Badge>;
}

/** A schedule as a short table of days and periods. */
export function HoursList({ hours }: { hours: BusinessHours }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
      {summarizeHours(hours).map(([days, periods]) => (
        <div key={days} className="contents">
          <dt className="text-muted">{days}</dt>
          <dd className="tabular-nums">{periods}</dd>
        </div>
      ))}
    </dl>
  );
}

const none = <span className="text-muted">None</span>;

function link(href: string, text: string) {
  return (
    <a href={href} className="break-all text-accent hover:underline" rel="noreferrer noopener">
      {text}
    </a>
  );
}

/** The organization's contact information and hours. */
export function OrganizationRecord({ organization: o }: { organization: Organization }) {
  return (
    <KeyValueList
      narrow
      items={[
        ["Main phone", o.mainPhone ? link(`tel:${o.mainPhone.replace(/[^\d+]/g, "")}`, o.mainPhone) : none],
        ["Main email", o.mainEmail ? link(`mailto:${o.mainEmail}`, o.mainEmail) : none],
        ["Website", o.website ? <a href={o.website} target="_blank" rel="noreferrer noopener" className="break-all text-accent hover:underline">{o.website}</a> : none],
        ["Business hours", o.businessHours ? <HoursList hours={o.businessHours} /> : none],
        ["After hours", o.afterHoursNote ? <span className="whitespace-pre-wrap">{o.afterHoursNote}</span> : none],
      ]}
    />
  );
}

/** The address as lines: the fields when any is set, else the free text (ADR-0066). */
export function addressLines(s: SiteDetails): string[] {
  const place = [s.city, s.region, s.postalCode].filter(Boolean).join(", ");
  const fields = [s.addressLine1, s.addressLine2, place, s.countryCode ? countryName(s.countryCode) : ""].filter(Boolean);
  if (fields.length > 0) return fields;
  return s.address ? s.address.split("\n") : [];
}

/** The site's address and hours. */
export function SiteRecord({ site: s, organizationHours }: { site: Site; organizationHours: BusinessHours | null }) {
  const lines = addressLines(s);
  const hours = s.businessHours ?? (s.hoursFromOrganization ? organizationHours : null);
  return (
    <KeyValueList
      narrow
      items={[
        ["Address", lines.length > 0 ? <address className="not-italic">{lines.map((l, i) => <span key={i} className="block">{l}</span>)}</address> : none],
        [
          "Business hours",
          hours ? (
            <>
              <HoursList hours={hours} />
              {!s.businessHours && <p className="mt-1 text-xs text-muted">The organization's hours, in the site's time zone.</p>}
            </>
          ) : (
            none
          ),
        ],
        ["After hours", s.afterHoursNote ? <span className="whitespace-pre-wrap">{s.afterHoursNote}</span> : none],
      ]}
    />
  );
}

/** Edits a weekly schedule: up to four periods a day; a day without any is closed. */
export function HoursEditor({ value, onChange, error }: { value: BusinessHours; onChange: (h: BusinessHours) => void; error?: string | null }) {
  const id = useId();
  const change = (fn: (h: BusinessHours) => void) => {
    const next = copyHours(value);
    fn(next);
    onChange(next);
  };
  return (
    <fieldset className="flex flex-col gap-2" aria-describedby={`${id}-hint`}>
      <legend className="mb-1 text-xs font-medium text-muted">Business hours</legend>
      {WEEKDAYS.map(({ day, long }) => (
        <div key={day} className="flex flex-wrap items-center gap-x-3 gap-y-1.5" role="group" aria-label={long}>
          <span className="w-24 text-sm">{long}</span>
          {value[day].length === 0 && <span className="text-sm text-muted">Closed</span>}
          {value[day].map((p, i) => (
            <span key={i} className="flex items-center gap-1">
              <Input
                type="time"
                aria-label={`${long} period ${i + 1} opens`}
                value={p.start}
                required
                onChange={(e) => change((h) => void (h[day][i]!.start = e.target.value))}
                className="w-28"
              />
              <span className="text-muted" aria-hidden>
                –
              </span>
              <Input
                type="time"
                aria-label={`${long} period ${i + 1} closes`}
                value={p.end}
                required
                onChange={(e) => change((h) => void (h[day][i]!.end = e.target.value))}
                className="w-28"
              />
              <IconButton label={`Remove ${long} period ${i + 1}`} onClick={() => change((h) => void h[day].splice(i, 1))}>
                <X className="size-4" aria-hidden />
              </IconButton>
            </span>
          ))}
          {value[day].length < MAX_PERIODS_PER_DAY && (
            <Button
              size="sm"
              variant="ghost"
              icon={<Plus className="size-3.5" aria-hidden />}
              aria-label={`Add a period on ${long}`}
              onClick={() => change((h) => void h[day].push({ start: "09:00", end: "17:00" }))}
            >
              Add
            </Button>
          )}
        </div>
      ))}
      <div>
        <Button
          size="sm"
          variant="ghost"
          icon={<Copy className="size-3.5" aria-hidden />}
          onClick={() => change((h) => {
            for (const day of ["tuesday", "wednesday", "thursday", "friday"] as const) h[day] = h.monday.map((p) => ({ ...p }));
          })}
        >
          Copy Monday to Tuesday–Friday
        </Button>
      </div>
      {error ? (
        <p className="text-xs text-danger">{error}</p>
      ) : (
        <p id={`${id}-hint`} className="text-xs text-subtle">
          Up to four periods a day. A period that ends at or before it starts runs past midnight.
        </p>
      )}
    </fieldset>
  );
}

const ORGANIZATION_FIELDS = ["mainPhone", "mainEmail", "website", "businessHours", "afterHoursNote"];

/** Edits an organization's contact information and hours (doc.manage). */
export function OrganizationDetailsDialog({ open, onClose, organization: o }: { open: boolean; onClose: () => void; organization: Organization }) {
  const toast = useToast();
  const [form, setForm] = useState<OrganizationDetails>(() => detailsOf(o));
  useEffect(() => {
    if (open) setForm(detailsOf(o));
  }, [open, o]);
  const save = useApiMutation((req: OrganizationDetails) => api.put<Organization>(`/organizations/${o.id}/details`, req), {
    invalidate: ["/organizations", "/sites", "/audit"],
    onSuccess: () => {
      toast.success("Contact information saved.");
      onClose();
    },
  });
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  const set = <K extends keyof OrganizationDetails>(k: K, v: OrganizationDetails[K]) => setForm((f) => ({ ...f, [k]: v }));

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ ...form, businessHours: form.businessHours && hoursOrNull(form.businessHours) });
  }

  return (
    <Dialog open={open} onClose={onClose} title="Edit contact information" description={o.name} size="lg">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <TextField label="Main phone" type="tel" value={form.mainPhone} onChange={(e) => set("mainPhone", e.target.value)} error={fieldError(save.error, "mainPhone")} maxLength={50} autoFocus />
          <TextField label="Main email" type="email" value={form.mainEmail} onChange={(e) => set("mainEmail", e.target.value)} error={fieldError(save.error, "mainEmail")} maxLength={254} />
        </div>
        <TextField
          label="Website"
          value={form.website}
          onChange={(e) => set("website", e.target.value)}
          error={fieldError(save.error, "website")}
          hint="https:// is added when no scheme is given."
          maxLength={2000}
        />
        <HoursEditor value={form.businessHours ?? copyHours(null)} onChange={(h) => set("businessHours", h)} error={fieldError(save.error, "businessHours")} />
        <p className="-mt-1.5 text-xs text-subtle">In the organization's time zone, {o.timezone}. Sites without hours of their own use these.</p>
        <TextareaField
          label="After-hours instructions"
          value={form.afterHoursNote}
          onChange={(e) => set("afterHoursNote", e.target.value)}
          error={fieldError(save.error, "afterHoursNote")}
          maxLength={2000}
        />
        <InlineError error={save.error} fields={ORGANIZATION_FIELDS} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function detailsOf(o: Organization): OrganizationDetails {
  return { mainPhone: o.mainPhone, mainEmail: o.mainEmail, website: o.website, businessHours: copyHours(o.businessHours), afterHoursNote: o.afterHoursNote };
}

const SITE_FIELDS = ["address", "addressLine1", "addressLine2", "city", "region", "postalCode", "countryCode", "businessHours", "afterHoursNote"];

function siteDetailsOf(s: Site): SiteDetails {
  return {
    address: s.address,
    addressLine1: s.addressLine1,
    addressLine2: s.addressLine2,
    city: s.city,
    region: s.region,
    postalCode: s.postalCode,
    countryCode: s.countryCode,
    businessHours: s.businessHours && copyHours(s.businessHours),
    afterHoursNote: s.afterHoursNote,
  };
}

/** Edits a site's address and hours (doc.manage at the site). */
export function SiteDetailsDialog({ open, onClose, site: s }: { open: boolean; onClose: () => void; site: Site }) {
  const toast = useToast();
  const [form, setForm] = useState<SiteDetails>(() => siteDetailsOf(s));
  const [ownHours, setOwnHours] = useState(s.businessHours !== null);
  useEffect(() => {
    if (open) {
      setForm(siteDetailsOf(s));
      setOwnHours(s.businessHours !== null);
    }
  }, [open, s]);
  const save = useApiMutation((req: SiteDetails) => api.put<Site>(`/sites/${s.id}/details`, req), {
    invalidate: ["/sites", "/organizations", "/audit"],
    onSuccess: () => {
      toast.success("Address and hours saved.");
      onClose();
    },
  });
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  const set = <K extends keyof SiteDetails>(k: K, v: SiteDetails[K]) => setForm((f) => ({ ...f, [k]: v }));
  const text = (k: "addressLine1" | "addressLine2" | "city" | "region" | "postalCode", label: string, max: number) => (
    <TextField label={label} value={form[k]} onChange={(e) => set(k, e.target.value)} error={fieldError(save.error, k)} maxLength={max} />
  );
  const ownHoursId = useId();

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ ...form, businessHours: ownHours && form.businessHours ? hoursOrNull(form.businessHours) : null });
  }

  return (
    <Dialog open={open} onClose={onClose} title="Edit address and hours" description={s.name} size="lg">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        {text("addressLine1", "Address line 1", 200)}
        {text("addressLine2", "Address line 2", 200)}
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-3">
          {text("city", "City or town", 100)}
          {text("region", "State, county or province", 100)}
          {text("postalCode", "Postal code", 20)}
        </div>
        <SelectField label="Country" value={form.countryCode} onChange={(e) => set("countryCode", e.target.value)} error={fieldError(save.error, "countryCode")}>
          <option value="">None</option>
          {countryOptions().map((c) => (
            <option key={c.code} value={c.code}>
              {c.name}
            </option>
          ))}
        </SelectField>
        <TextareaField
          label="Address as free text"
          value={form.address}
          onChange={(e) => set("address", e.target.value)}
          error={fieldError(save.error, "address")}
          hint="For an address the fields above do not fit. The site shows the fields when any is filled in."
          maxLength={1000}
        />
        <label htmlFor={ownHoursId} className="flex items-center gap-2 text-sm">
          <input
            id={ownHoursId}
            type="checkbox"
            className="size-4 accent-accent"
            checked={ownHours}
            onChange={(e) => {
              setOwnHours(e.target.checked);
              if (e.target.checked && !form.businessHours) set("businessHours", copyHours(null));
            }}
          />
          This site keeps hours of its own
        </label>
        {ownHours ? (
          <>
            <HoursEditor value={form.businessHours ?? copyHours(null)} onChange={(h) => set("businessHours", h)} error={fieldError(save.error, "businessHours")} />
            <p className="-mt-1.5 text-xs text-subtle">In the site's time zone, {s.timezone}.</p>
          </>
        ) : (
          <Field label="Business hours">
            <p className="text-sm text-muted">The organization's hours, in the site's time zone ({s.timezone}).</p>
          </Field>
        )}
        <TextareaField
          label="After-hours instructions"
          value={form.afterHoursNote}
          onChange={(e) => set("afterHoursNote", e.target.value)}
          error={fieldError(save.error, "afterHoursNote")}
          maxLength={2000}
        />
        <InlineError error={save.error} fields={SITE_FIELDS} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/**
 * What a refused deletion asks to confirm (ADR-0066): the counts of the documentation that would go with it. Sent
 * back with the next try, so a deletion only removes what its confirmation named.
 */
export function confirmedCounts(error: unknown): Record<string, number> | undefined {
  if (error instanceof ApiError && (error.code === "documentation_exists" || error.code === "documentation_changed") && error.counts) return error.counts;
  return undefined;
}
