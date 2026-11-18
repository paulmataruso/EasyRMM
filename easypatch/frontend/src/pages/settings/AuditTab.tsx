import { Link } from 'react-router';
import { ScrollText } from 'lucide-react';
import { useList, useOrganizations } from '../../api/hooks';
import type { AuditLogDto, UserDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { OrganizationSelect } from '../../components/Filters';
import { Button, EmptyState, ErrorState, Field, Input, Mono, Pagination, Select, Spinner, TableWrap, Toolbar } from '../../components/ui';
import { dayBoundary, formatDateTime, formatRelative } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';

/** Action prefixes; the API filters with "starts with", so a prefix selects a whole area. */
const ACTION_GROUPS: [string, string][] = [
  ['auth.', 'Sign-in and account security'],
  ['user.', 'User administration'],
  ['organization.', 'Organizations'],
  ['site.', 'Sites'],
  ['policy.', 'Policies'],
  ['endpoint.', 'Endpoints'],
  ['job.', 'Jobs'],
  ['enrollment_token.', 'Enrollment tokens'],
  ['deployment_code.', 'Deployment codes'],
  ['enrollment_request.', 'Approvals'],
  ['settings.', 'Server settings'],
  ['lifecycle.', 'OS lifecycle'],
];

function prettyDetails(details: string): string {
  try {
    return JSON.stringify(JSON.parse(details), null, 2);
  } catch {
    return details;
  }
}

export function AuditTab() {
  const url = useUrlState();
  const { isSuperAdmin } = useAuth();
  const orgs = useOrganizations(true);
  const users = useList<UserDto>(isSuperAdmin ? '/users' : null);
  const from = url.get('from');
  const to = url.get('to');
  const list = useList<AuditLogDto>(
    '/audit-logs',
    {
      userId: url.get('userId') || undefined,
      organizationId: url.get('organizationId') || undefined,
      action: url.get('action') || undefined,
      from: dayBoundary(from, false),
      to: dayBoundary(to, true),
      page: url.page,
      pageSize: 50,
    },
    { keepPrevious: true },
  );
  const orgName = (id: string | null) => (id ? (orgs.page.items.find((o) => o.id === id)?.name ?? null) : null);
  const filtered = ['userId', 'organizationId', 'action', 'from', 'to'].some((k) => url.get(k));

  return (
    <>
      <Toolbar>
        {isSuperAdmin && (
          <Field label="User" htmlFor="audit-user">
            <Select id="audit-user" value={url.get('userId')} onChange={(e) => url.set({ userId: e.target.value })}>
              <option value="">All users</option>
              {users.page.items.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.username}
                </option>
              ))}
            </Select>
          </Field>
        )}
        <OrganizationSelect value={url.get('organizationId')} onChange={(v) => url.set({ organizationId: v })} />
        <Field label="Area" htmlFor="audit-action">
          <Select id="audit-action" value={url.get('action')} onChange={(e) => url.set({ action: e.target.value })}>
            <option value="">All actions</option>
            {ACTION_GROUPS.map(([prefix, label]) => (
              <option key={prefix} value={prefix}>
                {label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="From" htmlFor="audit-from">
          <Input id="audit-from" type="date" value={from} max={to || undefined} onChange={(e) => url.set({ from: e.target.value })} />
        </Field>
        <Field label="To" htmlFor="audit-to">
          <Input id="audit-to" type="date" value={to} min={from || undefined} onChange={(e) => url.set({ to: e.target.value })} />
        </Field>
        {filtered && (
          <Button variant="ghost" className="mb-0.5" onClick={() => url.set({ userId: null, organizationId: null, action: null, from: null, to: null })}>
            Clear filters
          </Button>
        )}
      </Toolbar>
      {!isSuperAdmin && <p className="mb-3 text-xs text-muted">You see entries for the organizations you can access.</p>}
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title={filtered ? 'No audit entries match these filters' : 'No audit entries yet'} icon={<ScrollText className="size-8" aria-hidden />} />
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>When</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Organization</th>
                  <th>Source IP</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {list.page.items.map((a) => (
                  <tr key={a.id} className="align-top">
                    <td className="whitespace-nowrap" title={formatRelative(a.createdAt)}>
                      {formatDateTime(a.createdAt)}
                    </td>
                    <td className="whitespace-nowrap">{a.username ?? <span className="text-muted">system</span>}</td>
                    <td>
                      <Mono>{a.action}</Mono>
                    </td>
                    <td className="text-sm">
                      {a.endpointId ? (
                        <Link to={`/endpoints/${a.endpointId}`} className="text-accent hover:underline">
                          {a.targetType ?? 'Endpoint'}
                        </Link>
                      ) : (
                        (a.targetType ?? '—')
                      )}
                      {a.targetId && <div className="max-w-48 truncate font-mono text-xs text-muted" title={a.targetId}>{a.targetId}</div>}
                    </td>
                    <td className="text-sm">
                      {a.organizationId ? (
                        <Link to={`/organizations/${a.organizationId}`} className="text-accent hover:underline">
                          {orgName(a.organizationId) ?? 'Organization'}
                        </Link>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="font-mono text-xs whitespace-nowrap">{a.ipAddress ?? '—'}</td>
                    <td className="max-w-md">
                      {a.details ? (
                        <details>
                          <summary className="cursor-pointer text-xs text-accent">Show</summary>
                          <pre className="mt-1 max-h-64 overflow-auto rounded-md bg-raised p-2 font-mono text-xs whitespace-pre-wrap">{prettyDetails(a.details)}</pre>
                        </details>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                      {a.correlationId && <div className="mt-1 font-mono text-[11px] text-subtle" title="Correlation ID">{a.correlationId}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}
    </>
  );
}
