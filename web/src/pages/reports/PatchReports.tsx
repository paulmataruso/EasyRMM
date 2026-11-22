import { useId, useMemo, useState } from "react";
import { Download, FileText, Mail, Plus, Trash2 } from "lucide-react";
import { api, API_BASE } from "../../api/client";
import { useApi, useApiMutation, useOrganizations } from "../../api/hooks";
import type { PatchMonthlyReport, PatchMonthlyReportList, PatchTrend, PatchTrendPoint } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { OrganizationSelect } from "../../components/Filters";
import { TimeChart, type TimeSeries } from "../../components/TimeChart";
import { useToast } from "../../components/Toast";
import { Badge, Button, buttonClasses, Card, EmptyState, ErrorState, InlineError, SelectField, Segmented, Spinner, TableWrap, TextareaField, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, formatSize } from "../../lib/format";
import { ReportMailAlert } from "./ReportMailAlert";
import { useUrlState } from "../../lib/urlState";

// The patch reports EasyRMM takes from EasyPatch: the compliance trend above the compliance
// report, and monthly PDF reports. The compliance and installations tables themselves are ordinary reports.

const PERIODS = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
] as const;
type Period = (typeof PERIODS)[number]["value"];

/** A day (2006-01-02) at local midnight, so the chart labels it as that day wherever the browser is. */
function localDay(date: string): Date {
  const [y, m, d] = date.split("-").map(Number);
  return new Date(y ?? 1970, (m ?? 1) - 1, d ?? 1);
}

type TrendRow = PatchTrendPoint & { at: string };

const SERIES: TimeSeries<TrendRow>[] = [{ key: "compliant", label: "Up to date", color: "var(--series-1)", value: (p) => p.compliancePercent }];

const percent = (v: number) => `${v.toLocaleString(undefined, { maximumFractionDigits: 1 })}%`;

/** The share of machines up to date, day by day, over the organizations the caller sees whole. */
export function PatchTrendCard({ organizationId, siteChosen }: { organizationId: string; siteChosen: boolean }) {
  const url = useUrlState();
  const period: Period = PERIODS.find((p) => p.value === url.get("trend"))?.value ?? "30";
  const trend = useApi<PatchTrend>("/patching/reports/trend", { organizationId, days: period }, { keepPrevious: true, staleTime: 60_000 });
  const rows = useMemo(() => (trend.data?.points ?? []).map((p) => ({ ...p, at: localDay(p.date).toISOString() })), [trend.data]);
  // Nobody sees an organization whole: the trend adds up organizations, so there is nothing to draw.
  if (trend.isSuccess && trend.data.organizations === 0) return null;
  const today = new Date();
  const to = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const from = new Date(to.getFullYear(), to.getMonth(), to.getDate() - (Number(period) - 1));
  const latest = trend.data?.points.at(-1);
  const long = PERIODS.find((p) => p.value === period)?.label ?? period;
  return (
    <Card
      title="Compliance trend"
      className="mb-4"
      actions={<Segmented label="Period" options={[...PERIODS]} value={period} onChange={(v) => url.set({ trend: v === "30" ? null : v })} />}
    >
      {trend.isPending ? (
        <Spinner />
      ) : trend.isError ? (
        <ErrorState error={trend.error} onRetry={() => void trend.refetch()} compact />
      ) : (
        <>
          <TimeChart
            data={rows}
            series={SERIES}
            from={from.toISOString()}
            to={to.toISOString()}
            stepSeconds={86_400}
            label={`Machines up to date, last ${long}`}
            format={percent}
            stale={trend.isPlaceholderData}
            daily
          />
          <p className="mt-2 text-xs text-muted">
            {latest ? `${latest.compliant.toLocaleString()} of ${latest.totalEndpoints.toLocaleString()} machines were up to date on the last day. ` : ""}
            The patching engine keeps a record of each organization a day, updated every 30 minutes
            {trend.data.organizations > 1 ? `; this adds up ${trend.data.organizations} organizations` : ""}.
            {siteChosen ? " The trend covers whole organizations, not only the chosen site." : ""}
          </p>
        </>
      )}
    </Card>
  );
}

const MONTHS = Array.from({ length: 12 }, (_, i) => new Date(2000, i, 1).toLocaleDateString(undefined, { month: "long" }));

/** "October 2026", or "November 2026 so far". */
export function reportMonth(r: Pick<PatchMonthlyReport, "periodStart" | "monthToDate">): string {
  const month = localDay(r.periodStart).toLocaleDateString(undefined, { month: "long", year: "numeric" });
  return r.monthToDate ? `${month} so far` : month;
}

/** Splits addresses typed one per line, or separated by commas or spaces. */
export function addresses(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((a) => a.trim())
    .filter(Boolean);
}

function Delivery({ report }: { report: PatchMonthlyReport }) {
  const to = report.recipients.join(", ");
  switch (report.deliveryStatus) {
    case "Sent":
      return (
        <Badge tone="ok" title={to}>
          Emailed {report.sentAt ? formatRelative(report.sentAt) : ""}
        </Badge>
      );
    case "Failed":
      return (
        <span className="flex flex-col items-start gap-1">
          <Badge tone="danger" title={to}>
            Email failed
          </Badge>
          {report.lastError && <span className="max-w-sm text-xs text-muted">{report.lastError}</span>}
        </span>
      );
    case "Pending":
    case "Sending":
      return (
        <Badge tone="info" title={to}>
          Sending
        </Badge>
      );
    default:
      return <span className="text-subtle">Not emailed</span>;
  }
}

/** Reports → Monthly patch reports: each organization's PDF of a month, made on request or on its schedule. */
export function MonthlyReports() {
  const url = useUrlState();
  const toast = useToast();
  const organizationId = url.get("organizationId");
  const list = useApi<PatchMonthlyReportList>("/patching/reports/monthly", { organizationId }, { keepPrevious: true });
  const [generating, setGenerating] = useState(false);
  const [emailing, setEmailing] = useState<PatchMonthlyReport | null>(null);
  const [deleting, setDeleting] = useState<PatchMonthlyReport | null>(null);
  const remove = useApiMutation((r: PatchMonthlyReport) => api.del(`/patching/reports/monthly/${r.id}`), {
    invalidate: ["/patching/reports", "/audit"],
    onSuccess: () => {
      toast.success("Report deleted.");
      setDeleting(null);
    },
  });
  const canGenerate = list.data?.canGenerate ?? [];
  return (
    <>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} className="max-w-64" />
        {canGenerate.length > 0 && (
          <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setGenerating(true)} className="self-end">
            Make a report
          </Button>
        )}
      </Toolbar>
      <ReportMailAlert className="mb-4" />
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.data.items.length === 0 ? (
        <div className="rounded-lg border border-line bg-surface">
          <EmptyState title="No monthly reports yet" compact icon={<FileText className="size-8" aria-hidden />}>
            {canGenerate.length > 0
              ? "Make one for a month, or schedule them under Settings → Patching to have one made and emailed each month."
              : "Reports appear here once someone who manages an organization's patching makes one, or its schedule does."}
          </EmptyState>
        </div>
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <caption className="sr-only">Monthly patch reports</caption>
              <thead>
                <tr>
                  <th scope="col">Organization</th>
                  <th scope="col">Month</th>
                  <th scope="col">Made</th>
                  <th scope="col" className="text-right">
                    Size
                  </th>
                  <th scope="col">Email</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((r) => (
                  <tr key={r.id}>
                    <td className="font-medium">{r.organizationName}</td>
                    <td className="whitespace-nowrap">
                      {reportMonth(r)}
                      {r.scheduled && (
                        <Badge tone="neutral" className="ml-2">
                          Scheduled
                        </Badge>
                      )}
                    </td>
                    <td className="whitespace-nowrap">
                      <span title={formatDateTime(r.generatedAt)}>{formatRelative(r.generatedAt)}</span>
                      {r.generatedBy && <span className="text-muted"> by {r.generatedBy}</span>}
                    </td>
                    <td className="text-right tabular-nums">{formatSize(r.sizeBytes)}</td>
                    <td>
                      <Delivery report={r} />
                    </td>
                    <td>
                      <div className="flex justify-end gap-1">
                        <a
                          href={`${API_BASE}/patching/reports/monthly/${r.id}/pdf`}
                          download={r.fileName}
                          className={buttonClasses("ghost", "sm")}
                          aria-label={`Download the ${reportMonth(r)} report of ${r.organizationName}`}
                        >
                          <Download className="size-3.5" aria-hidden />
                          PDF
                        </a>
                        {r.canManage && (
                          <>
                            <Button size="sm" variant="ghost" icon={<Mail className="size-3.5" aria-hidden />} onClick={() => setEmailing(r)}>
                              Email
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              icon={<Trash2 className="size-3.5" aria-hidden />}
                              aria-label={`Delete the ${reportMonth(r)} report of ${r.organizationName}`}
                              onClick={() => setDeleting(r)}
                            />
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          {list.data.capped && <p className="mt-2 text-xs text-muted">Only the newest reports are listed; choose an organization to see its own.</p>}
        </>
      )}
      <GenerateDialog key={generating ? "open" : "closed"} open={generating} onClose={() => setGenerating(false)} organizations={canGenerate} />
      <EmailDialog key={emailing?.id ?? "closed"} report={emailing} onClose={() => setEmailing(null)} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => {
          setDeleting(null);
          remove.reset();
        }}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title="Delete this report?"
        confirmLabel="Delete report"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        {deleting && `The ${reportMonth(deleting)} report of ${deleting.organizationName} is deleted for everyone. A new one can be made at any time.`}
      </ConfirmDialog>
    </>
  );
}

function GenerateDialog({ open, onClose, organizations }: { open: boolean; onClose: () => void; organizations: string[] }) {
  const toast = useToast();
  const orgs = useOrganizations();
  const choices = (orgs.data?.items ?? []).filter((o) => organizations.includes(o.id));
  const last = new Date();
  last.setDate(1);
  last.setMonth(last.getMonth() - 1);
  const [org, setOrg] = useState(organizations.length === 1 ? (organizations[0] ?? "") : "");
  const [year, setYear] = useState(String(last.getFullYear()));
  const [month, setMonth] = useState(String(last.getMonth() + 1));
  const [devices, setDevices] = useState(true);
  const devicesId = useId();
  const thisYear = new Date().getFullYear();
  const generate = useApiMutation(
    () => api.post<PatchMonthlyReport>("/patching/reports/monthly", { organizationId: org, year: Number(year), month: Number(month), includeEndpointList: devices }),
    {
      invalidate: ["/patching/reports", "/audit"],
      onSuccess: (r) => {
        toast.success(`The ${reportMonth(r)} report of ${r.organizationName} is ready.`);
        onClose();
      },
    },
  );
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Make a monthly report"
      description="A PDF of the organization's patching over the month: compliance, what was installed and what failed. The current month makes a report of the month so far."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={generate.isPending} disabled={!org} onClick={() => generate.mutate()}>
            Make report
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <SelectField label="Organization" value={org} onChange={(e) => setOrg(e.target.value)}>
          <option value="">Choose an organization</option>
          {choices.map((o) => (
            <option key={o.id} value={o.id}>
              {o.name}
            </option>
          ))}
        </SelectField>
        <div className="flex gap-3">
          <SelectField label="Month" value={month} onChange={(e) => setMonth(e.target.value)} className="flex-1">
            {MONTHS.map((name, i) => (
              <option key={name} value={String(i + 1)}>
                {name}
              </option>
            ))}
          </SelectField>
          <SelectField label="Year" value={year} onChange={(e) => setYear(e.target.value)} className="w-32">
            {Array.from({ length: 10 }, (_, i) => String(thisYear - i)).map((y) => (
              <option key={y} value={y}>
                {y}
              </option>
            ))}
          </SelectField>
        </div>
        <label htmlFor={devicesId} className="flex items-start gap-2.5 text-sm">
          <input id={devicesId} type="checkbox" className="mt-0.5 size-4 accent-accent" checked={devices} onChange={(e) => setDevices(e.target.checked)} />
          <span>
            List each device
            <span className="block text-xs text-muted">Adds a page per device. Leave it out for a short summary.</span>
          </span>
        </label>
        <InlineError error={generate.error} />
      </div>
    </Dialog>
  );
}

function EmailDialog({ report, onClose }: { report: PatchMonthlyReport | null; onClose: () => void }) {
  const toast = useToast();
  const [to, setTo] = useState("");
  const send = useApiMutation(
    (r: PatchMonthlyReport) => api.post<PatchMonthlyReport>(`/patching/reports/monthly/${r.id}/send`, { recipients: addresses(to) }),
    {
      invalidate: ["/patching/reports", "/audit"],
      onSuccess: (r) => {
        toast.success(`Sending the report to ${r.recipients.join(", ")}.`);
        onClose();
      },
    },
  );
  return (
    <Dialog
      open={report !== null}
      onClose={onClose}
      title="Email this report"
      description={report ? `The ${reportMonth(report)} report of ${report.organizationName}, as a PDF attachment.` : undefined}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={send.isPending} onClick={() => report && send.mutate(report)}>
            Send
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <ReportMailAlert />
        <TextareaField
          label="Recipients"
          hint="One address per line, up to 20. Leave it empty to send to the organization's report schedule's recipients."
          value={to}
          onChange={(e) => setTo(e.target.value)}
          rows={3}
          placeholder="it@example.com"
        />
        <InlineError error={send.error} />
      </div>
    </Dialog>
  );
}
