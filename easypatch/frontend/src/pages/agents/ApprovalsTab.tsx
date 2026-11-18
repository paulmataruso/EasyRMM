import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Check, Fingerprint, UserCheck, X } from 'lucide-react';
import { api } from '../../api/client';
import { useApiMutation, useList } from '../../api/hooks';
import { ENROLLMENT_REQUEST_STATUSES, type EnrollmentRequestDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { CodeBlock } from '../../components/Copy';
import { Dialog } from '../../components/Dialog';
import { EnumSelect, OrganizationSelect, SiteSelect } from '../../components/Filters';
import { RequestStatusBadge } from '../../components/StatusBadges';
import { useToast } from '../../components/Toast';
import { Alert, Badge, Button, EmptyState, ErrorState, InlineError, Mono, Pagination, Spinner, TableWrap, TextField, Toolbar } from '../../components/ui';
import { formatDateTime, formatRelative } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';

const STATUS_COMMAND = '& "$env:ProgramFiles\\EasyPatch\\Agent\\EasyPatch.Agent.exe" status';

export function ApprovalsTab() {
  const { canOperate } = useAuth();
  const toast = useToast();
  const url = useUrlState();
  const rawStatus = url.get('status', 'Pending');
  const status = rawStatus === 'all' ? '' : rawStatus;
  const list = useList<EnrollmentRequestDto>('/enrollment-requests', { status: status || undefined, page: url.page, pageSize: 100 }, { keepPrevious: true, refetchInterval: 15_000 });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [approving, setApproving] = useState<EnrollmentRequestDto | null>(null);
  const [rejecting, setRejecting] = useState<EnrollmentRequestDto | null>(null);
  const items = list.page.items;
  const pending = items.filter((r) => r.status === 'Pending');
  const allSelected = pending.length > 0 && pending.every((r) => selected.has(r.id));

  useEffect(() => setSelected(new Set()), [status]);

  const bulk = useApiMutation((ids: string[]) => api.post<unknown>('/enrollment-requests/bulk-approve', { ids }), {
    invalidate: ['/enrollment-requests', '/endpoints', '/dashboard', '/deployment-codes'],
    onSuccess: (_, ids) => {
      toast.success(`${ids.length} endpoint${ids.length === 1 ? '' : 's'} approved.`);
      setSelected(new Set());
    },
  });

  return (
    <>
      <Alert tone="info" className="mb-4" title="Verify before approving">
        <p>
          Endpoints installed with a deployment code wait here. Approving issues the agent its credential and makes the endpoint manageable. To verify a device,
          compare its key fingerprint with the output of this command on the device (as administrator):
        </p>
        <CodeBlock code={STATUS_COMMAND} className="mt-2 max-w-xl" />
      </Alert>
      <Toolbar>
        <EnumSelect label="Status" value={status} onChange={(v) => url.set({ status: v || 'all' })} options={ENROLLMENT_REQUEST_STATUSES} allLabel="All" />
        <span className="flex-1" />
        {canOperate && selected.size > 0 && (
          <Button variant="primary" className="mb-0.5" loading={bulk.isPending} icon={<Check className="size-4" aria-hidden />} onClick={() => bulk.mutate([...selected])}>
            Approve {selected.size} selected
          </Button>
        )}
      </Toolbar>
      <InlineError error={bulk.error} />
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState title={status === 'Pending' ? 'No endpoints waiting for approval' : 'No enrollment requests'} icon={<UserCheck className="size-8" aria-hidden />} />
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  {canOperate && (
                    <th className="w-8">
                      <input
                        type="checkbox"
                        className="size-4"
                        aria-label="Select all pending requests"
                        checked={allSelected}
                        disabled={pending.length === 0}
                        onChange={() => setSelected(allSelected ? new Set() : new Set(pending.map((r) => r.id)))}
                      />
                    </th>
                  )}
                  <th>Device</th>
                  <th>Key fingerprint</th>
                  <th>Hardware / OS</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Requested</th>
                  <th>Status</th>
                  {canOperate && <th className="text-right">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.id}>
                    {canOperate && (
                      <td>
                        <input
                          type="checkbox"
                          className="size-4"
                          aria-label={`Select ${r.hostname}`}
                          disabled={r.status !== 'Pending'}
                          checked={selected.has(r.id)}
                          onChange={() =>
                            setSelected((s) => {
                              const next = new Set(s);
                              if (next.has(r.id)) next.delete(r.id);
                              else next.add(r.id);
                              return next;
                            })
                          }
                        />
                      </td>
                    )}
                    <td className="whitespace-nowrap">
                      <div className="font-medium">{r.hostname}</div>
                      <div className="text-xs text-muted">agent {r.agentVersion}</div>
                      {r.existingEndpointId && (
                        <Link to={`/endpoints/${r.existingEndpointId}`} className="mt-0.5 inline-block">
                          <Badge tone="warn" title="An endpoint with the same hardware ID and hostname exists. Approving re-associates it.">
                            Re-enrollment of existing endpoint
                          </Badge>
                        </Link>
                      )}
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-1.5">
                        <Fingerprint className="size-3.5 text-subtle" aria-hidden />
                        <Mono className="text-sm">{r.keyFingerprint}</Mono>
                      </span>
                    </td>
                    <td className="text-sm">
                      <div>{[r.manufacturer, r.model].filter(Boolean).join(' ') || '—'}</div>
                      <div className="text-xs text-muted">
                        {r.serialNumber && <>S/N {r.serialNumber} · </>}
                        {r.osCaption ?? 'Unknown OS'}
                      </div>
                    </td>
                    <td className="font-mono text-xs whitespace-nowrap">{r.sourceIp ?? '—'}</td>
                    <td className="text-sm">
                      <div className="whitespace-nowrap">
                        {r.organizationName}
                        {r.siteName && <span className="text-muted"> · {r.siteName}</span>}
                      </div>
                      <div className="text-xs text-muted">via {r.deploymentCodeName}</div>
                    </td>
                    <td className="whitespace-nowrap text-muted" title={formatDateTime(r.createdAt)}>
                      {formatRelative(r.createdAt)}
                      <div className="text-xs">last seen {formatRelative(r.lastSeenAt)}</div>
                    </td>
                    <td>
                      <RequestStatusBadge status={r.status} />
                      {r.status === 'Pending' && <div className="mt-0.5 text-xs text-muted">expires {formatRelative(r.expiresAt)}</div>}
                      {r.rejectReason && <div className="mt-0.5 text-xs text-muted">{r.rejectReason}</div>}
                      {r.endpointId && (
                        <Link to={`/endpoints/${r.endpointId}`} className="text-xs text-accent hover:underline">
                          View endpoint
                        </Link>
                      )}
                    </td>
                    {canOperate && (
                      <td>
                        {r.status === 'Pending' && (
                          <div className="flex justify-end gap-1">
                            <Button size="sm" variant="primary" icon={<Check className="size-3.5" aria-hidden />} onClick={() => setApproving(r)}>
                              Approve
                            </Button>
                            <Button size="sm" variant="danger-ghost" icon={<X className="size-3.5" aria-hidden />} onClick={() => setRejecting(r)}>
                              Reject
                            </Button>
                          </div>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}
      <ApproveDialog request={approving} onClose={() => setApproving(null)} />
      <RejectDialog request={rejecting} onClose={() => setRejecting(null)} />
    </>
  );
}

function ApproveDialog({ request, onClose }: { request: EnrollmentRequestDto | null; onClose: () => void }) {
  const toast = useToast();
  const [org, setOrg] = useState('');
  const [site, setSite] = useState('');
  useEffect(() => {
    if (request) {
      setOrg(request.organizationId);
      setSite(request.siteId ?? '');
    }
  }, [request]);
  const approve = useApiMutation(
    (r: EnrollmentRequestDto) =>
      api.post(`/enrollment-requests/${r.id}/approve`, { organizationId: org || null, siteId: site || null }),
    {
      invalidate: ['/enrollment-requests', '/endpoints', '/dashboard', '/deployment-codes'],
      onSuccess: (_, r) => {
        toast.success(`${r.hostname} approved. It becomes active at its next poll.`);
        onClose();
      },
    },
  );
  return (
    <Dialog
      open={request !== null}
      onClose={onClose}
      title={request ? `Approve ${request.hostname}?` : ''}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={approve.isPending} disabled={!org} onClick={() => request && approve.mutate(request)} icon={<Check className="size-4" aria-hidden />}>
            Approve endpoint
          </Button>
        </>
      }
    >
      {request && (
        <div className="flex flex-col gap-4 text-sm">
          <div className="rounded-md border border-line bg-raised p-3">
            <p className="text-xs text-muted">Key fingerprint reported by the device</p>
            <p className="mt-1 font-mono text-lg tracking-wider">{request.keyFingerprint}</p>
            <p className="mt-2 text-xs text-muted">
              Confirm it matches the output of <span className="font-mono">EasyPatch.Agent.exe status</span> on {request.hostname}
              {request.serialNumber && ` (serial ${request.serialNumber})`}. A mismatch means the request did not come from that device.
            </p>
          </div>
          {request.existingEndpointId && (
            <Alert tone="warn">
              An endpoint with the same hardware ID and hostname already exists. Approving re-associates its history with this new agent key and revokes the old key.
            </Alert>
          )}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <OrganizationSelect value={org} onChange={(v) => { setOrg(v); setSite(''); }} label="Organization" required />
            <SiteSelect organizationId={org} value={site} onChange={setSite} allLabel="No site" />
          </div>
          <InlineError error={approve.error} />
        </div>
      )}
    </Dialog>
  );
}

function RejectDialog({ request, onClose }: { request: EnrollmentRequestDto | null; onClose: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState('');
  useEffect(() => {
    if (request) setReason('');
  }, [request]);
  const reject = useApiMutation((r: EnrollmentRequestDto) => api.post(`/enrollment-requests/${r.id}/reject`, { reason: reason.trim() || null }), {
    invalidate: ['/enrollment-requests', '/dashboard', '/deployment-codes'],
    onSuccess: (_, r) => {
      toast.success(`${r.hostname} rejected.`);
      onClose();
    },
  });
  return (
    <Dialog
      open={request !== null}
      onClose={onClose}
      size="sm"
      title={request ? `Reject ${request.hostname}?` : ''}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="danger" loading={reject.isPending} onClick={() => request && reject.mutate(request)}>
            Reject
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <p>The agent is told its request was rejected and stops polling. It is not removed from the device.</p>
        <TextField label="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} />
        <InlineError error={reject.error} />
      </div>
    </Dialog>
  );
}
