import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { FileDown, Mail, Trash2 } from 'lucide-react';
import { api, apiUrl } from '../../api/client';
import { useApi, useApiMutation, useList } from '../../api/hooks';
import type { MonthlyReportDto, ReportScheduleDto, ReportScheduleRequest, SendReportRequest } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { OrganizationSelect } from '../../components/Filters';
import { useToast } from '../../components/Toast';
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  EmptyState,
  ErrorState,
  IconButton,
  InlineError,
  Pagination,
  SelectField,
  Spinner,
  TableWrap,
  Textarea,
  Toolbar,
} from '../../components/ui';
import { formatBytes, formatDate, formatDateTime } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';

const MAX_RECIPIENTS = 20;

export function parseRecipients(text: string): string[] {
  const seen = new Set<string>();
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !seen.has(s.toLowerCase()) && seen.add(s.toLowerCase()));
}

/** "October 2026" for a yyyy-MM-dd date (no time-zone shift). */
export function monthLabel(date: string): string {
  const [y, m] = date.split('-').map(Number);
  return new Date(y, m - 1, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
}

function reportLabel(r: MonthlyReportDto): string {
  return r.monthToDate ? `${monthLabel(r.periodStart)} (to ${formatDate(r.periodEnd)})` : monthLabel(r.periodStart);
}

/** The current month (month to date) and the 12 months before it, newest first. */
function recentMonths(now = new Date()): { year: number; month: number; label: string }[] {
  return Array.from({ length: 13 }, (_, i) => {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
    const label = d.toLocaleDateString(undefined, { month: 'long', year: 'numeric', timeZone: 'UTC' });
    return { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1, label: i === 0 ? `${label} (month to date)` : label };
  });
}

export function MonthlyReportsTab() {
  const url = useUrlState();
  const organizationId = url.get('organizationId');
  const page = Number(url.get('page', '1')) || 1;
  return (
    <>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, page: null })} />
      </Toolbar>
      <p className="mb-4 max-w-3xl text-sm text-muted">
        A PDF per organization and month: compliance at the start and end of the month, updates installed, failed installations, the most widely missing
        updates (known-exploited first), operating systems and, optionally, every endpoint. Scheduled reports are emailed to the organization's recipients;
        any report can also be downloaded or sent on demand. Email needs SMTP with STARTTLS or TLS (Settings → Notifications).
      </p>
      {organizationId ? (
        <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
          <ScheduleCard organizationId={organizationId} />
          <GenerateCard organizationId={organizationId} />
        </div>
      ) : (
        <Alert tone="info" className="mb-4">
          Choose an organization to set up its monthly email or to generate a report.
        </Alert>
      )}
      <ReportList organizationId={organizationId} page={page} onPage={(p) => url.set({ page: p === 1 ? null : String(p) })} />
    </>
  );
}

function ScheduleCard({ organizationId }: { organizationId: string }) {
  const { canOperate } = useAuth();
  const toast = useToast();
  const schedule = useApi<ReportScheduleDto>(`/organizations/${organizationId}/report-schedule`);
  const [enabled, setEnabled] = useState(false);
  const [recipients, setRecipients] = useState('');
  const [day, setDay] = useState(1);
  const [includeEndpoints, setIncludeEndpoints] = useState(true);
  useEffect(() => {
    if (!schedule.data) return;
    setEnabled(schedule.data.enabled);
    setRecipients(schedule.data.recipients.join('\n'));
    setDay(schedule.data.dayOfMonth);
    setIncludeEndpoints(schedule.data.includeEndpointList);
  }, [schedule.data]);
  const save = useApiMutation((req: ReportScheduleRequest) => api.put<ReportScheduleDto>(`/organizations/${organizationId}/report-schedule`, req), {
    invalidate: [`/organizations/${organizationId}/report-schedule`],
    onSuccess: () => toast.success('Report schedule saved.'),
  });
  const parsed = useMemo(() => parseRecipients(recipients), [recipients]);

  if (schedule.isPending) return <Card title="Monthly email"><Spinner /></Card>;
  if (schedule.isError) return <Card title="Monthly email"><ErrorState error={schedule.error} onRetry={() => void schedule.refetch()} compact /></Card>;
  const s = schedule.data;
  const tooMany = parsed.length > MAX_RECIPIENTS;
  const valid = !tooMany && (!enabled || parsed.length > 0);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (valid) save.mutate({ enabled, recipients: parsed, dayOfMonth: day, includeEndpointList: includeEndpoints });
  }

  return (
    <Card title="Monthly email">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Checkbox
          label="Email last month's report automatically"
          hint="Months that ended before you switch this on are not sent; generate and send those below."
          checked={enabled}
          disabled={!canOperate}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        <div className="flex flex-col gap-1">
          <label htmlFor="report-recipients" className="text-sm font-medium">
            Recipients
          </label>
          <Textarea
            id="report-recipients"
            rows={3}
            value={recipients}
            disabled={!canOperate}
            placeholder={'it-manager@customer.example\nowner@customer.example'}
            onChange={(e) => setRecipients(e.target.value)}
          />
          <p className={tooMany ? 'text-xs text-danger' : 'text-xs text-muted'}>
            One address per line (up to {MAX_RECIPIENTS}). Reports describe this customer's exposure: send them only to people who should see it.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <SelectField
            label="Send on day"
            value={String(day)}
            disabled={!canOperate}
            onChange={(e) => setDay(Number(e.target.value))}
            hint={`Of each month, in the organization's time zone (${s.timeZone}).`}
          >
            {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </SelectField>
          <Checkbox
            className="sm:pt-6"
            label="Include the endpoint list"
            hint="Adds a table of every endpoint."
            checked={includeEndpoints}
            disabled={!canOperate}
            onChange={(e) => setIncludeEndpoints(e.target.checked)}
          />
        </div>
        {s.nextReportDate && s.nextReportPeriod ? (
          <p className="text-sm">
            Next: the {monthLabel(s.nextReportPeriod)} report, sent on {formatDate(s.nextReportDate)}.
          </p>
        ) : (
          s.enabled && <p className="text-sm text-muted">No report is scheduled.</p>
        )}
        <InlineError error={save.error} />
        {canOperate && (
          <div>
            <Button type="submit" variant="primary" disabled={!valid} loading={save.isPending}>
              Save schedule
            </Button>
          </div>
        )}
      </form>
    </Card>
  );
}

function GenerateCard({ organizationId }: { organizationId: string }) {
  const { canOperate } = useAuth();
  const toast = useToast();
  const months = useMemo(() => recentMonths(), []);
  const [choice, setChoice] = useState(1); // last month
  const [includeEndpoints, setIncludeEndpoints] = useState(true);
  const generate = useApiMutation(
    (req: { year: number; month: number }) =>
      api.post<MonthlyReportDto>('/monthly-reports', { organizationId, year: req.year, month: req.month, includeEndpointList: includeEndpoints }),
    {
      invalidate: ['/monthly-reports'],
      onSuccess: (r) => toast.success(`${r.fileName} generated.`),
    },
  );
  if (!canOperate) {
    return (
      <Card title="Generate a report">
        <p className="text-sm text-muted">Administrators can generate reports. You can download the existing ones below.</p>
      </Card>
    );
  }

  return (
    <Card title="Generate a report">
      <div className="flex flex-col gap-3">
        <SelectField label="Month" value={String(choice)} onChange={(e) => setChoice(Number(e.target.value))}>
          {months.map((m, i) => (
            <option key={`${m.year}-${m.month}`} value={i}>
              {m.label}
            </option>
          ))}
        </SelectField>
        <Checkbox label="Include the endpoint list" checked={includeEndpoints} onChange={(e) => setIncludeEndpoints(e.target.checked)} />
        <p className="text-xs text-muted">
          Month values (installations, failures, the trend) use UTC dates. Current values (compliance, missing updates, operating systems) are taken when
          the report is generated, so a report for an earlier month shows today's state for those.
        </p>
        <InlineError error={generate.error} />
        <div>
          <Button variant="primary" loading={generate.isPending} onClick={() => generate.mutate(months[choice])}>
            Generate PDF
          </Button>
        </div>
      </div>
    </Card>
  );
}

function DeliveryBadge({ report }: { report: MonthlyReportDto }) {
  switch (report.deliveryStatus) {
    case 'Sent':
      return (
        <Badge tone="ok" title={report.recipients.join(', ')}>
          Sent to {report.recipients.length}
        </Badge>
      );
    case 'Pending':
      return (
        <Badge tone={report.attempts > 0 ? 'warn' : 'info'} title={report.lastError ?? report.recipients.join(', ')}>
          {report.attempts > 0 ? `Retrying (${report.attempts})` : 'Queued'}
        </Badge>
      );
    case 'Failed':
      return (
        <Badge tone="danger" title={report.lastError ?? undefined}>
          Not sent
        </Badge>
      );
    default:
      return <span className="text-muted">—</span>;
  }
}

function ReportList({ organizationId, page, onPage }: { organizationId: string; page: number; onPage: (page: number) => void }) {
  const { canOperate } = useAuth();
  const toast = useToast();
  const list = useList<MonthlyReportDto>(
    '/monthly-reports',
    { organizationId: organizationId || undefined, page, pageSize: 25 },
    { keepPrevious: true, refetchInterval: (data) => (data && 'items' in data && data.items.some((r) => r.deliveryStatus === 'Pending') ? 15_000 : false) },
  );
  const [sending, setSending] = useState<MonthlyReportDto | null>(null);
  const [deleting, setDeleting] = useState<MonthlyReportDto | null>(null);
  const remove = useApiMutation((r: MonthlyReportDto) => api.del(`/monthly-reports/${r.id}`), {
    invalidate: ['/monthly-reports'],
    onSuccess: (_, r) => {
      toast.success(`${r.fileName} deleted.`);
      setDeleting(null);
    },
  });

  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  if (list.page.items.length === 0) {
    return <EmptyState title="No reports yet">Generated and scheduled reports appear here.</EmptyState>;
  }

  return (
    <>
      <TableWrap>
        <table className="table-base">
          <thead>
            <tr>
              <th>Month</th>
              <th>Organization</th>
              <th>Generated</th>
              <th className="text-right">Size</th>
              <th>Email</th>
              <th className="w-0" aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {list.page.items.map((r) => (
              <tr key={r.id}>
                <td className="whitespace-nowrap font-medium">{reportLabel(r)}</td>
                <td>{r.organizationName}</td>
                <td className="whitespace-nowrap">
                  {formatDateTime(r.generatedAt)}
                  <div className="text-xs text-muted">{r.scheduled ? 'Scheduled' : `By ${r.generatedBy ?? 'unknown'}`}</div>
                </td>
                <td className="whitespace-nowrap text-right">{formatBytes(r.sizeBytes)}</td>
                <td className="whitespace-nowrap">
                  <DeliveryBadge report={r} />
                  {r.deliveryStatus === 'Sent' && r.sentAt && <div className="text-xs text-muted">{formatDateTime(r.sentAt)}</div>}
                  {r.deliveryStatus === 'Failed' && r.lastError && <div className="max-w-64 truncate text-xs text-danger" title={r.lastError}>{r.lastError}</div>}
                </td>
                <td className="whitespace-nowrap">
                  <div className="flex items-center gap-1">
                    <a
                      href={apiUrl(`/monthly-reports/${r.id}/pdf`)}
                      download={r.fileName}
                      className="inline-flex size-8 items-center justify-center rounded-md text-muted hover:bg-hover hover:text-fg"
                      title={`Download ${r.fileName}`}
                      aria-label={`Download ${r.fileName}`}
                    >
                      <FileDown className="size-4" aria-hidden />
                    </a>
                    {canOperate && (
                      <>
                        <IconButton label="Email this report" onClick={() => setSending(r)}>
                          <Mail className="size-4" aria-hidden />
                        </IconButton>
                        <IconButton label="Delete" onClick={() => setDeleting(r)}>
                          <Trash2 className="size-4" aria-hidden />
                        </IconButton>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={onPage} />
      <SendDialog report={sending} onClose={() => setSending(null)} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title="Delete report"
        confirmLabel="Delete"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        Delete {deleting?.fileName}? A deleted scheduled report is not generated or sent again automatically.
      </ConfirmDialog>
    </>
  );
}

function SendDialog({ report, onClose }: { report: MonthlyReportDto | null; onClose: () => void }) {
  const toast = useToast();
  const schedule = useApi<ReportScheduleDto>(report ? `/organizations/${report.organizationId}/report-schedule` : null);
  const [recipients, setRecipients] = useState('');
  useEffect(() => {
    if (report) setRecipients(schedule.data?.recipients.join('\n') ?? '');
  }, [report, schedule.data]);
  const send = useApiMutation((req: SendReportRequest) => api.post<MonthlyReportDto>(`/monthly-reports/${report?.id}/send`, req), {
    invalidate: ['/monthly-reports'],
    onSuccess: () => {
      toast.success('Report queued. It is emailed within a minute.');
      onClose();
    },
  });
  const parsed = useMemo(() => parseRecipients(recipients), [recipients]);
  const valid = parsed.length > 0 && parsed.length <= MAX_RECIPIENTS;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (valid) send.mutate({ recipients: parsed });
  }

  return (
    <Dialog open={report !== null} onClose={onClose} title={`Email ${report ? reportLabel(report) : ''} report`} size="md">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <p className="text-sm">
          {report?.organizationName}: <span className="font-mono text-xs">{report?.fileName}</span>
        </p>
        <div className="flex flex-col gap-1">
          <label htmlFor="send-recipients" className="text-sm font-medium">
            Recipients
          </label>
          <Textarea id="send-recipients" rows={4} value={recipients} onChange={(e) => setRecipients(e.target.value)} autoFocus />
          <p className="text-xs text-muted">One address per line (up to {MAX_RECIPIENTS}). Defaults to the organization's report recipients.</p>
        </div>
        <InlineError error={send.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!valid} loading={send.isPending}>
            Send
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
