// Contacts (ADR-0066): the customer's staff to call, at the organization or one of its sites. They are personal data,
// not EasyRMM accounts.

import { useEffect, useId, useState, type FormEvent } from "react";
import { ChevronRight, Pencil, Plus, Trash2, Users } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation, useList } from "../../api/hooks";
import type { Contact, ContactInput, ContactPriority, Site } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Badge, Button, Card, EmptyState, ErrorState, IconButton, InlineError, SelectField, Spinner, TableWrap, TextareaField, TextField } from "../../components/ui";

const PRIORITY_LABELS: Record<ContactPriority, string> = { primary: "Primary", secondary: "Secondary", none: "None" };

/** A contact's place in the organization: the site's name, or the organization. */
function levelName(c: Contact): string {
  return c.siteId ? c.siteName : "Organization";
}

function ContactBadges({ contact: c }: { contact: Contact }) {
  return (
    <span className="flex flex-wrap gap-1">
      {c.priority !== "none" && <Badge tone={c.priority === "primary" ? "accent" : "info"}>{PRIORITY_LABELS[c.priority]}</Badge>}
      {c.emergency && <Badge tone="danger">Emergency</Badge>}
    </span>
  );
}

/** A list of contacts, with editing for those the caller may manage. */
export function ContactsTable({ items, showLevel, onEdit, onDelete }: {
  items: Contact[];
  showLevel: boolean;
  onEdit: (c: Contact) => void;
  onDelete: (c: Contact) => void;
}) {
  const managing = items.some((c) => c.canManage);
  return (
    <TableWrap className="rounded-none border-0">
      <table className="table-base">
        <thead>
          <tr>
            <th>Name</th>
            {showLevel && <th className="hidden sm:table-cell">Where</th>}
            <th>Reach</th>
            <th className="hidden md:table-cell">Note</th>
            {managing && (
              <th className="text-right">
                <span className="sr-only">Actions</span>
              </th>
            )}
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.id}>
              <td>
                <p className="font-medium">{c.name}</p>
                {c.jobTitle && <p className="text-xs text-muted">{c.jobTitle}</p>}
                <ContactBadges contact={c} />
              </td>
              {showLevel && <td className="hidden whitespace-nowrap sm:table-cell">{levelName(c)}</td>}
              <td className="text-sm">
                {c.email && (
                  <a href={`mailto:${c.email}`} className="block break-all text-accent hover:underline">
                    {c.email}
                  </a>
                )}
                {c.officePhone && <span className="block whitespace-nowrap">Office: {c.officePhone}</span>}
                {c.mobilePhone && <span className="block whitespace-nowrap">Mobile: {c.mobilePhone}</span>}
                {!c.email && !c.officePhone && !c.mobilePhone && <span className="text-muted">—</span>}
              </td>
              <td className="hidden max-w-xs md:table-cell">
                <span className="line-clamp-3 whitespace-pre-wrap text-muted">{c.note || "—"}</span>
              </td>
              {managing && (
                <td className="text-right whitespace-nowrap">
                  {c.canManage && (
                    <>
                      <IconButton label={`Edit ${c.name}`} onClick={() => onEdit(c)}>
                        <Pencil className="size-4" aria-hidden />
                      </IconButton>
                      <IconButton label={`Delete ${c.name}`} onClick={() => onDelete(c)} className="hover:text-danger">
                        <Trash2 className="size-4" aria-hidden />
                      </IconButton>
                    </>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

/**
 * An organization's contacts, or one site's: a page at a time when `paged` (the organization's Contacts tab keeps
 * the cursor in the URL), else the whole level, which the server holds to 1,000.
 */
export function ContactsPanel({ organizationId, site, levels, after, onPage, className }: {
  organizationId: string;
  className?: string;
  /** One site's contacts; absent for the whole organization's. */
  site?: Site;
  /** Where the caller may add contacts: null for the organization, or sites. */
  levels: { id: string | null; name: string }[];
  /** The organization's list pages through with these. */
  after?: string | null;
  onPage?: (after: string | null) => void;
}) {
  const toast = useToast();
  const paged = onPage !== undefined;
  const list = useList<Contact>(
    `/organizations/${organizationId}/contacts`,
    { siteId: site?.id, after: paged ? after : undefined, limit: paged ? 100 : 1000 },
    { keepPrevious: true },
  );
  const [form, setForm] = useState<{ open: boolean; contact?: Contact }>({ open: false });
  const [deleting, setDeleting] = useState<Contact | null>(null);
  const remove = useApiMutation((c: Contact) => api.del(`/contacts/${c.id}`), {
    invalidate: [`/organizations/${organizationId}/contacts`, "/audit"],
    onSuccess: (_, c) => {
      toast.success(`Contact “${c.name}” deleted.`);
      setDeleting(null);
    },
  });

  const add = levels.length > 0 && (
    <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setForm({ open: true })}>
      Add contact
    </Button>
  );

  return (
    <Card title="Contacts" padded={false} actions={add} className={className}>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : list.items.length === 0 && !after ? (
        <EmptyState title="No contacts yet" icon={<Users className="size-8" aria-hidden />} compact>
          The people to call at {site ? "this site" : "the customer"}: who decides, who to reach out of hours.
        </EmptyState>
      ) : (
        <>
          <ContactsTable items={list.items} showLevel={!site} onEdit={(c) => setForm({ open: true, contact: c })} onDelete={setDeleting} />
          {paged && (after || list.next) && (
            <nav className="flex items-center justify-end gap-1 border-t border-line px-4 py-2" aria-label="Pagination">
              {after && (
                <Button size="sm" variant="ghost" onClick={() => onPage(null)}>
                  First page
                </Button>
              )}
              {list.next && (
                <Button size="sm" variant="ghost" onClick={() => onPage(list.next)}>
                  Next page
                  <ChevronRight className="size-4" aria-hidden />
                </Button>
              )}
            </nav>
          )}
        </>
      )}
      <ContactDialog
        open={form.open}
        onClose={() => setForm({ open: false })}
        organizationId={organizationId}
        contact={form.contact}
        levels={levels}
      />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => {
          setDeleting(null);
          remove.reset();
        }}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title="Delete contact"
        confirmLabel="Delete contact"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        <p>
          Delete <strong>{deleting?.name}</strong>, a contact of {deleting?.siteId ? deleting.siteName : "the organization"}?
        </p>
      </ConfirmDialog>
    </Card>
  );
}

const FIELDS = ["siteId", "name", "jobTitle", "email", "officePhone", "mobilePhone", "note", "priority", "emergency"];

function blank(siteId: string | null): ContactInput {
  return { siteId, name: "", jobTitle: "", email: "", officePhone: "", mobilePhone: "", note: "", priority: "none", emergency: false };
}

function ContactDialog({ open, onClose, organizationId, contact, levels }: {
  open: boolean;
  onClose: () => void;
  organizationId: string;
  contact?: Contact;
  levels: { id: string | null; name: string }[];
}) {
  const toast = useToast();
  const emergencyId = useId();
  const [form, setForm] = useState<ContactInput>(() => blank(null));
  const firstLevel = levels[0]?.id ?? null;
  useEffect(() => {
    if (!open) return;
    if (contact) {
      const { name, jobTitle, email, officePhone, mobilePhone, note, priority, emergency } = contact;
      setForm({ name, jobTitle, email, officePhone, mobilePhone, note, priority, emergency });
    } else setForm(blank(firstLevel));
  }, [open, contact, firstLevel]);
  const save = useApiMutation(
    (req: ContactInput) => (contact ? api.patch<Contact>(`/contacts/${contact.id}`, req) : api.post<Contact>(`/organizations/${organizationId}/contacts`, req)),
    {
      invalidate: [`/organizations/${organizationId}/contacts`, "/audit"],
      onSuccess: (c) => {
        toast.success(contact ? "Contact updated." : `Contact “${c.name}” added.`);
        onClose();
      },
    },
  );
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  const set = <K extends keyof ContactInput>(k: K, v: ContactInput[K]) => setForm((f) => ({ ...f, [k]: v }));

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate(form);
  }

  return (
    <Dialog open={open} onClose={onClose} title={contact ? "Edit contact" : "New contact"} description={contact ? levelName(contact) : undefined}>
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        {!contact && levels.length > 1 && (
          <SelectField label="Contact of" value={form.siteId ?? ""} onChange={(e) => set("siteId", e.target.value || null)} error={fieldError(save.error, "siteId")}>
            {levels.map((l) => (
              <option key={l.id ?? ""} value={l.id ?? ""}>
                {l.name}
              </option>
            ))}
          </SelectField>
        )}
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <TextField label="Name" value={form.name} onChange={(e) => set("name", e.target.value)} error={fieldError(save.error, "name")} required maxLength={200} autoFocus />
          <TextField label="Job title" value={form.jobTitle} onChange={(e) => set("jobTitle", e.target.value)} error={fieldError(save.error, "jobTitle")} maxLength={200} />
        </div>
        <TextField label="Email" type="email" value={form.email} onChange={(e) => set("email", e.target.value)} error={fieldError(save.error, "email")} maxLength={254} />
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <TextField label="Office phone" type="tel" value={form.officePhone} onChange={(e) => set("officePhone", e.target.value)} error={fieldError(save.error, "officePhone")} maxLength={50} />
          <TextField label="Mobile phone" type="tel" value={form.mobilePhone} onChange={(e) => set("mobilePhone", e.target.value)} error={fieldError(save.error, "mobilePhone")} maxLength={50} />
        </div>
        <SelectField
          label="Priority"
          value={form.priority}
          onChange={(e) => set("priority", e.target.value as ContactPriority)}
          error={fieldError(save.error, "priority")}
          hint="One primary contact for the organization and one for each site: choosing another makes the current one secondary."
        >
          <option value="none">None</option>
          <option value="primary">Primary</option>
          <option value="secondary">Secondary</option>
        </SelectField>
        <label htmlFor={emergencyId} className="flex items-center gap-2 text-sm">
          <input id={emergencyId} type="checkbox" className="size-4 accent-accent" checked={form.emergency} onChange={(e) => set("emergency", e.target.checked)} />
          Emergency contact
        </label>
        <TextareaField label="Note" value={form.note} onChange={(e) => set("note", e.target.value)} error={fieldError(save.error, "note")} maxLength={2000} />
        <InlineError error={save.error} fields={FIELDS} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim()}>
            {contact ? "Save changes" : "Add contact"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
