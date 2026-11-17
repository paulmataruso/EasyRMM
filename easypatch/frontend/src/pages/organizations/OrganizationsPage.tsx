import { useEffect, useId, useMemo, useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router';
import { Building2, Plus } from 'lucide-react';
import { api } from '../../api/client';
import { useApiMutation, useList } from '../../api/hooks';
import type { OrganizationDto, OrganizationRequest, OrganizationSummaryDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { Dialog } from '../../components/Dialog';
import { SearchInput } from '../../components/Filters';
import { useToast } from '../../components/Toast';
import {
  Badge,
  Button,
  Checkbox,
  EmptyState,
  ErrorState,
  Field,
  InlineError,
  Input,
  PageHeader,
  ProgressBar,
  SortHeader,
  type SortState,
  Spinner,
  TableWrap,
  Textarea,
  TextField,
  Toolbar,
} from '../../components/ui';
import { formatNumber, formatPercent, formatRelative } from '../../lib/format';
import { browserTimeZone, timeZones } from '../../lib/timezones';
import { useUrlState } from '../../lib/urlState';

const SORT_KEYS: Record<string, (o: OrganizationSummaryDto) => string | number> = {
  name: (o) => o.name.toLowerCase(),
  endpoints: (o) => o.endpointCount,
  compliance: (o) => (o.endpointCount === 0 ? Number.POSITIVE_INFINITY : o.compliancePercent),
  missing: (o) => o.missingRequiredUpdates,
  lastActivity: (o) => (o.lastActivityAt ? Date.parse(o.lastActivityAt) : 0),
};

/** The organization list is small and returned in full (sorted by name), so other sort orders are applied here. */
function sortOrganizations(items: OrganizationSummaryDto[], sort: SortState): OrganizationSummaryDto[] {
  const key = sort.sort ? SORT_KEYS[sort.sort] : undefined;
  if (!key) return items;
  const factor = sort.dir === 'desc' ? -1 : 1;
  return [...items].sort((a, b) => {
    const x = key(a);
    const y = key(b);
    return (x < y ? -1 : x > y ? 1 : 0) * factor || a.name.localeCompare(b.name);
  });
}

export function OrganizationsPage() {
  const { canOperate } = useAuth();
  const navigate = useNavigate();
  const url = useUrlState();
  const [creating, setCreating] = useState(false);
  const search = url.get('search');
  const includeArchived = url.get('archived') === 'true';
  const list = useList<OrganizationSummaryDto>(
    '/organizations',
    { search, includeArchived: includeArchived || undefined },
    { keepPrevious: true, refetchInterval: 60_000 },
  );
  const sortField = url.sort.sort;
  const sortDir = url.sort.dir;
  const rows = useMemo(() => sortOrganizations(list.page.items, { sort: sortField, dir: sortDir }), [list.page.items, sortField, sortDir]);

  return (
    <>
      <PageHeader
        title="Organizations"
        subtitle="Customers you manage. Each organization contains sites and endpoints."
        actions={
          canOperate && (
            <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setCreating(true)}>
              New organization
            </Button>
          )
        }
      />
      <Toolbar>
        <SearchInput value={search} onChange={(v) => url.set({ search: v })} placeholder="Search organizations" className="max-w-sm" />
        <Checkbox label="Show archived" checked={includeArchived} onChange={(e) => url.set({ archived: e.target.checked })} className="pb-2" />
      </Toolbar>

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState
          title={search ? 'No organizations match your search' : 'No organizations yet'}
          icon={<Building2 className="size-8" aria-hidden />}
          action={canOperate && !search ? <Button variant="primary" onClick={() => setCreating(true)}>Create your first organization</Button> : undefined}
        >
          {!search && 'Create an organization, then generate an enrollment token or deployment code to add endpoints.'}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <SortHeader field="name" label="Name" state={url.sort} onSort={url.toggleSort} />
                  <SortHeader field="endpoints" label="Endpoints" state={url.sort} onSort={url.toggleSort} className="text-right" />
                  <th>Online / offline</th>
                  <SortHeader field="compliance" label="Compliance" state={url.sort} onSort={url.toggleSort} className="w-48" />
                  <SortHeader field="missing" label="Missing" state={url.sort} onSort={url.toggleSort} className="text-right" />
                  <th className="text-right">Failed</th>
                  <th className="text-right">Restart</th>
                  <SortHeader field="lastActivity" label="Last activity" state={url.sort} onSort={url.toggleSort} />
                </tr>
              </thead>
              <tbody>
                {rows.map((o) => (
                  <tr key={o.id} className="cursor-pointer" onClick={() => navigate(`/organizations/${o.id}`)}>
                    <td>
                      <Link to={`/organizations/${o.id}`} className="font-medium hover:text-accent" onClick={(e) => e.stopPropagation()}>
                        {o.name}
                      </Link>
                      {!o.isActive && <Badge className="ml-2">Archived</Badge>}
                      {o.description && <p className="max-w-md truncate text-xs text-muted">{o.description}</p>}
                    </td>
                    <td className="text-right tabular-nums">{formatNumber(o.endpointCount)}</td>
                    <td className="whitespace-nowrap tabular-nums">
                      <span className="text-ok">{o.onlineCount}</span> / <span className={o.offlineCount ? 'text-warn' : 'text-muted'}>{o.offlineCount}</span>
                    </td>
                    <td>
                      {o.endpointCount === 0 ? (
                        <span className="text-xs text-subtle">No endpoints</span>
                      ) : (
                        <div className="flex items-center gap-2">
                          <ProgressBar value={o.compliancePercent} tone={o.compliancePercent >= 90 ? 'ok' : o.compliancePercent >= 70 ? 'warn' : 'danger'} label={`${o.name} compliance`} />
                          <span className="w-11 text-right text-xs tabular-nums">{formatPercent(o.compliancePercent)}</span>
                        </div>
                      )}
                    </td>
                    <td className="text-right tabular-nums">{o.missingRequiredUpdates > 0 ? <span className="text-warn">{formatNumber(o.missingRequiredUpdates)}</span> : '0'}</td>
                    <td className="text-right tabular-nums">{o.failedCount > 0 ? <span className="text-danger">{o.failedCount}</span> : '0'}</td>
                    <td className="text-right tabular-nums">{o.rebootRequiredCount > 0 ? <span className="text-info">{o.rebootRequiredCount}</span> : '0'}</td>
                    <td className="whitespace-nowrap text-muted">{formatRelative(o.lastActivityAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <p className="mt-2 text-xs text-muted">
            {rows.length} organization{rows.length === 1 ? '' : 's'}
          </p>
        </>
      )}

      <OrganizationFormDialog
        open={creating}
        onClose={() => setCreating(false)}
        onSaved={(org) => {
          setCreating(false);
          navigate(`/organizations/${org.id}`);
        }}
      />
    </>
  );
}

export function OrganizationFormDialog({ open, onClose, onSaved, organization }: {
  open: boolean;
  onClose: () => void;
  onSaved: (org: OrganizationDto) => void;
  organization?: OrganizationDto;
}) {
  const toast = useToast();
  const [form, setForm] = useState<OrganizationRequest>(blankOrganization);
  useEffect(() => {
    if (!open) return;
    setForm(
      organization
        ? {
            name: organization.name,
            description: organization.description,
            contactName: organization.contactName,
            contactEmail: organization.contactEmail,
            notes: organization.notes,
            timeZone: organization.timeZone,
          }
        : blankOrganization(),
    );
  }, [open, organization]);

  const save = useApiMutation(
    (req: OrganizationRequest) => (organization ? api.put<OrganizationDto>(`/organizations/${organization.id}`, req) : api.post<OrganizationDto>('/organizations', req)),
    {
      invalidate: ['/organizations', '/dashboard'],
      onSuccess: (org) => {
        toast.success(organization ? 'Organization updated.' : `Organization “${org.name}” created.`);
        onSaved(org);
      },
    },
  );

  const set = <K extends keyof OrganizationRequest>(k: K, v: OrganizationRequest[K]) => setForm((f) => ({ ...f, [k]: v }));
  const empty = (v: string) => (v.trim() === '' ? null : v);

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ ...form, name: form.name.trim() });
  }

  return (
    <Dialog open={open} onClose={onClose} title={organization ? 'Edit organization' : 'New organization'}>
      <form onSubmit={submit} className="flex flex-col gap-3.5" id="org-form">
        <TextField label="Name" value={form.name} onChange={(e) => set('name', e.target.value)} required maxLength={200} autoFocus />
        <TextField label="Description" value={form.description ?? ''} onChange={(e) => set('description', empty(e.target.value))} maxLength={500} />
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <TextField label="Contact name" value={form.contactName ?? ''} onChange={(e) => set('contactName', empty(e.target.value))} maxLength={200} />
          <TextField label="Contact email" type="email" value={form.contactEmail ?? ''} onChange={(e) => set('contactEmail', empty(e.target.value))} maxLength={320} />
        </div>
        <TimeZoneField value={form.timeZone ?? 'UTC'} onChange={(v) => set('timeZone', v)} hint="Default time zone for maintenance windows. Sites can override it." />
        <Field label="Notes" htmlFor="org-notes">
          <Textarea id="org-notes" value={form.notes ?? ''} onChange={(e) => set('notes', empty(e.target.value))} maxLength={4000} />
        </Field>
        <InlineError error={save.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim()}>
            {organization ? 'Save changes' : 'Create organization'}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function blankOrganization(): OrganizationRequest {
  return { name: '', description: null, contactName: null, contactEmail: null, notes: null, timeZone: browserTimeZone() };
}

export function TimeZoneField({ value, onChange, hint, label = 'Time zone' }: { value: string; onChange: (v: string) => void; hint?: string; label?: string }) {
  const zones = timeZones();
  const id = useId();
  return (
    <Field label={label} htmlFor={`${id}-input`} hint={hint ?? 'IANA time zone, e.g. America/New_York.'}>
      <Input id={`${id}-input`} list={`${id}-options`} value={value} onChange={(e) => onChange(e.target.value)} required autoComplete="off" />
      <datalist id={`${id}-options`}>
        {zones.map((z) => (
          <option key={z} value={z} />
        ))}
      </datalist>
    </Field>
  );
}
