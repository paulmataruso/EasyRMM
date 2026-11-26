import { useId, type ReactNode } from "react";
import { Download } from "lucide-react";
import { API_BASE } from "../../api/client";
import { useApi } from "../../api/hooks";
import type { PatchStatus, Permission, Report, ReportColumn, ReportName, ReportValue } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { OrganizationSelect, SearchInput, SiteSelect } from "../../components/Filters";
import { buttonClasses, cx, EmptyState, ErrorState, Field, PageHeader, Select, Spinner, TableWrap, Tabs, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { categoryLabel, COMPLIANCE } from "../patching/patchText";
import { UPDATE_CATEGORIES } from "../patching/PatchUpdates";
import { MonthlyReports, PatchTrendCard } from "./PatchReports";
import { POSTURE_FILTERS } from "../devices/postureText";

interface ReportInfo {
  name: ReportName;
  label: string;
  description: string;
  /** What the rows show; report.view is needed as well. */
  permission: Permission;
  filters: ("platform" | "search" | "health" | "alerts" | "compliance" | "installations" | "posture")[];
  search?: { label: string; placeholder: string };
  /** The report comes from EasyPatch, so it is offered once EasyPatch is set up. */
  patching?: true;
}

/** The monthly PDF reports: a tab of their own, not a table report. */
const MONTHLY = "patch-monthly";

export const REPORTS: ReportInfo[] = [
  {
    name: "devices",
    label: "Device inventory",
    description: "Every device with its hardware, operating system, agent and addresses, as its agent last reported them.",
    permission: "device.view",
    filters: ["platform", "search"],
    search: { label: "Device", placeholder: "Name or host name" },
  },
  {
    name: "software",
    label: "Installed software",
    description: "Each package or program installed on each device. Search for a name to see which devices have it, and which versions.",
    permission: "software.view",
    filters: ["platform", "search"],
    search: { label: "Package", placeholder: "Package or program name" },
  },
  {
    name: "health",
    label: "Device health",
    description: "Each device's latest measurements and fullest filesystem. Find devices that have not checked in for a while, or are running out of space.",
    permission: "device.view",
    filters: ["platform", "health"],
  },
  {
    name: "alerts",
    label: "Alert history",
    description: "Alerts raised over a period, newest first: how long each stayed open, and how it ended.",
    permission: "alert.view",
    filters: ["alerts"],
  },
  {
    name: "security",
    label: "Security",
    description:
      "Whether each Windows and Linux device meets its security policy, with a score and the reasons: hardening and patching judged as one, where a result that is unknown or too old never counts as passing.",
    permission: "device.view",
    filters: ["platform", "posture", "search"],
    search: { label: "Device", placeholder: "Name or host name" },
  },
  {
    name: "contacts",
    label: "Contacts",
    description: "The customers' contacts, organization by organization: who to call, how, and who is primary or for emergencies.",
    permission: "doc.view",
    filters: ["search"],
    search: { label: "Contact", placeholder: "Name or email" },
  },
  {
    name: "patch-compliance",
    label: "Patch compliance",
    description:
      "Each device's patching as the patching engine last saw it: updates missing and failed, restarts pending and operating system support. Devices it does not patch say why.",
    permission: "patch.view",
    filters: ["platform", "compliance", "search"],
    search: { label: "Device", placeholder: "Name or host name" },
    patching: true,
  },
  {
    name: "patch-installations",
    label: "Patch installations",
    description: "Each update the patching engine's jobs finished with over a period, newest first: installed, failed, skipped or cancelled, and why.",
    permission: "patch.view",
    filters: ["installations", "search"],
    search: { label: "Device or update", placeholder: "Device, update or KB" },
    patching: true,
  },
];

/** The URL parameters that narrow reports; each report reads its own. */
const PARAMS = ["organizationId", "siteId", "platform", "q", "offlineDays", "diskPercent", "days", "severity", "compliance", "category", "result", "posture"] as const;

export function ReportsPage() {
  const { can } = useAuth();
  const url = useUrlState();
  const seesPatching = can("report.view") && can("patch.view");
  const patching = useApi<PatchStatus>(seesPatching ? "/patching" : null, undefined, { staleTime: 60_000 });
  const patched = patching.data?.configured === true;
  const available = REPORTS.filter((r) => can("report.view") && can(r.permission) && (!r.patching || patched));
  const tabs = [...available.map((r) => ({ id: r.name as string, label: r.label })), ...(patched ? [{ id: MONTHLY, label: "Monthly patch reports" }] : [])];
  const requested = url.get("report");
  const info = available.find((r) => r.name === requested) ?? (requested === MONTHLY && patched ? undefined : available[0]);

  // A patch report asked for by the URL waits for patching's status rather than show another report first.
  if (seesPatching && patching.isPending && (requested.startsWith("patch-") || requested === MONTHLY)) return <Spinner />;

  if (requested === MONTHLY && patched) {
    return (
      <>
        <PageHeader title="Reports" subtitle="Monthly patch reports: a PDF of each organization's patching over a month, to keep or email." />
        <Tabs tabs={tabs} active={MONTHLY} onChange={(id) => url.set({ report: id === tabs[0]?.id ? null : id, q: null })} />
        <div role="tabpanel" aria-labelledby={`tab-${MONTHLY}`}>
          <MonthlyReports />
        </div>
      </>
    );
  }

  if (!info) {
    return (
      <>
        <PageHeader title="Reports" />
        <EmptyState title="No reports for your role">Reports need the report.view permission and the permission to see what they list.</EmptyState>
      </>
    );
  }

  const params: Record<string, string> = {};
  for (const key of PARAMS) {
    const v = url.get(key);
    if (v && applies(info, key)) params[key] = v;
  }
  const query = new URLSearchParams(params).toString();
  const csv = `${API_BASE}/reports/${info.name}/csv${query ? `?${query}` : ""}`;

  return (
    <>
      <PageHeader
        title="Reports"
        subtitle="What EasyRMM knows about your devices, to read here or download as CSV for a spreadsheet."
        actions={
          <a href={csv} download className={buttonClasses("secondary")}>
            <Download className="size-4" aria-hidden />
            Download CSV
          </a>
        }
      />
      <Tabs tabs={tabs} active={info.name} onChange={(id) => url.set({ report: id === tabs[0]?.id ? null : id, q: null })} />
      <div role="tabpanel" aria-labelledby={`tab-${info.name}`}>
        <p className="mb-3 max-w-3xl text-sm text-muted">{info.description}</p>
        <Filters info={info} />
        {info.name === "patch-compliance" && <PatchTrendCard organizationId={url.get("organizationId")} siteChosen={url.get("siteId") !== ""} />}
        <ReportTable name={info.name} params={params} />
      </div>
    </>
  );
}

function applies(info: ReportInfo, key: (typeof PARAMS)[number]): boolean {
  switch (key) {
    case "organizationId":
    case "siteId":
      return true;
    case "platform":
      return info.filters.includes("platform");
    case "q":
      return info.filters.includes("search");
    case "offlineDays":
    case "diskPercent":
      return info.filters.includes("health");
    case "days":
      return info.filters.includes("alerts") || info.filters.includes("installations");
    case "severity":
      return info.filters.includes("alerts");
    case "compliance":
      return info.filters.includes("compliance");
    case "posture":
      return info.filters.includes("posture");
    case "category":
    case "result":
      return info.filters.includes("installations");
  }
}

function Filters({ info }: { info: ReportInfo }) {
  const url = useUrlState();
  const organizationId = url.get("organizationId");
  return (
    <Toolbar>
      <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} className="max-w-64" />
      <SiteSelect organizationId={organizationId} value={url.get("siteId")} onChange={(v) => url.set({ siteId: v })} className="max-w-64" />
      {info.filters.includes("platform") && (
        <Choice
          label="Platform"
          value={url.get("platform")}
          onChange={(v) => url.set({ platform: v })}
          options={[
            ["", "All platforms"],
            ["windows", "Windows"],
            ["linux", "Linux"],
          ]}
        />
      )}
      {info.filters.includes("health") && (
        <>
          <Choice
            label="Not seen for"
            value={url.get("offlineDays")}
            onChange={(v) => url.set({ offlineDays: v })}
            options={[
              ["", "Any time"],
              ["1", "A day or more"],
              ["7", "A week or more"],
              ["30", "30 days or more"],
              ["90", "90 days or more"],
            ]}
          />
          <Choice
            label="Fullest disk"
            value={url.get("diskPercent")}
            onChange={(v) => url.set({ diskPercent: v })}
            options={[
              ["", "Any"],
              ["80", "80% full or more"],
              ["90", "90% full or more"],
              ["95", "95% full or more"],
            ]}
          />
        </>
      )}
      {info.filters.includes("alerts") && (
        <>
          <Choice
            label="Opened in"
            value={url.get("days")}
            onChange={(v) => url.set({ days: v })}
            options={[
              ["7", "The last 7 days"],
              ["", "The last 30 days"],
              ["90", "The last 90 days"],
              ["365", "The last year"],
            ]}
          />
          <Choice
            label="Severity"
            value={url.get("severity")}
            onChange={(v) => url.set({ severity: v })}
            options={[
              ["", "Any severity"],
              ["critical", "Critical"],
              ["warning", "Warning"],
            ]}
          />
        </>
      )}
      {info.filters.includes("compliance") && (
        <Choice
          label="Compliance"
          value={url.get("compliance")}
          onChange={(v) => url.set({ compliance: v })}
          options={[
            ["", "Any compliance"],
            ...Object.entries(COMPLIANCE).map(([status, c]): [string, string] => [status, c.label]),
            ["unlinked", "Not patched"],
          ]}
        />
      )}
      {info.filters.includes("posture") && (
        <Choice
          label="Security"
          value={url.get("posture")}
          onChange={(v) => url.set({ posture: v })}
          options={[["", "Any security"], ...POSTURE_FILTERS.map((f): [string, string] => [f.value, f.label])]}
        />
      )}
      {info.filters.includes("installations") && (
        <>
          <Choice
            label="Finished in"
            value={url.get("days")}
            onChange={(v) => url.set({ days: v })}
            options={[
              ["7", "The last 7 days"],
              ["", "The last 30 days"],
              ["90", "The last 90 days"],
              ["365", "The last year"],
            ]}
          />
          <Choice
            label="Category"
            value={url.get("category")}
            onChange={(v) => url.set({ category: v })}
            options={[["", "Any category"], ...UPDATE_CATEGORIES.map((c): [string, string] => [c, categoryLabel(c)])]}
          />
          <Choice
            label="Result"
            value={url.get("result")}
            onChange={(v) => url.set({ result: v })}
            options={[
              ["", "Any result"],
              ["Succeeded", "Installed"],
              ["Failed", "Failed"],
              ["Skipped", "Skipped"],
              ["Cancelled", "Cancelled"],
            ]}
          />
        </>
      )}
      {info.search && (
        <SearchInput
          key={info.name}
          value={url.get("q")}
          onChange={(v) => url.set({ q: v })}
          label={info.search.label}
          placeholder={info.search.placeholder}
          className="max-w-xs"
        />
      )}
    </Toolbar>
  );
}

function Choice({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  const id = useId();
  return (
    <Field label={label} htmlFor={id} className="min-w-40">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map(([v, text]) => (
          <option key={v} value={v}>
            {text}
          </option>
        ))}
      </Select>
    </Field>
  );
}

function ReportTable({ name, params }: { name: ReportName; params: Record<string, string> }) {
  const report = useApi<Report>(`/reports/${name}`, params, { keepPrevious: true, staleTime: 30_000 });
  if (report.isPending) return <Spinner />;
  if (report.isError) return <ErrorState error={report.error} onRetry={() => void report.refetch()} />;
  const r = report.data;
  // A previous report's data shows while the next loads; never with another report's columns.
  if (r.name !== name) return <Spinner />;
  if (r.total === 0) {
    return (
      <div className="rounded-lg border border-line bg-surface">
        <EmptyState title="Nothing to report" compact>
          No rows match these filters.
        </EmptyState>
      </div>
    );
  }
  return (
    <>
      <TableWrap>
        <table className="table-base">
          <caption className="sr-only">{r.title}</caption>
          <thead>
            <tr>
              {r.columns.map((c) => (
                <th key={c.key} scope="col" className={cx(numeric(c) && "text-right", "whitespace-nowrap")}>
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {r.rows.map((row, i) => (
              <tr key={i}>
                {r.columns.map((c, j) => (
                  <td key={c.key} className={cx(numeric(c) && "text-right tabular-nums", j === 2 && "font-medium", "whitespace-nowrap")}>
                    {cell(c, row[j] ?? null)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <p className="mt-2 text-xs text-muted">
        {r.truncated
          ? `The report stops at ${r.total.toLocaleString()} rows; narrow it with the filters. `
          : r.rows.length < r.total
            ? `Showing the first ${r.rows.length.toLocaleString()} of ${plural(r.total, "row")}; the CSV has them all. `
            : `${plural(r.total, "row")}. `}
        Generated <span title={formatDateTime(r.generatedAt)}>{formatRelative(r.generatedAt)}</span>
        {report.isFetching ? ", updating…" : "."}
      </p>
    </>
  );
}

function numeric(c: ReportColumn): boolean {
  return c.type === "number" || c.type === "percent";
}

function cell(c: ReportColumn, v: ReportValue): ReactNode {
  if (v === null || v === "") return <span className="text-subtle">—</span>;
  switch (c.type) {
    case "bool":
      return v ? "Yes" : "No";
    case "percent":
      return `${Number(v).toLocaleString(undefined, { maximumFractionDigits: 1 })}%`;
    case "number":
      return Number(v).toLocaleString(undefined, { maximumFractionDigits: 1 });
    case "time":
      return formatDateTime(String(v));
    default:
      return String(v);
  }
}
