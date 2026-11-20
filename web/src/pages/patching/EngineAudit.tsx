import { Link } from "react-router";
import { ChevronLeft, ChevronRight, ScrollText } from "lucide-react";
import { useApi } from "../../api/hooks";
import type { PatchAuditEntry, PatchAuditPage } from "../../api/types";
import { OrganizationSelect } from "../../components/Filters";
import { Alert, Button, EmptyState, ErrorState, Field, Input, Mono, Select, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";

// Settings → Patching → Audit log: EasyPatch's own audit log, which records what EasyRMM's users
// did through EasyRMM, what was done in EasyPatch's console or API before it was imported, and what EasyPatch did on its own (the rollout guard,
// retention, scheduled reports). EasyRMM's audit log has its own record of the first.

/** EasyPatch's areas, by the start of their actions' names. */
export const ENGINE_AREAS: [string, string][] = [
  ["organization.", "Organizations"],
  ["site.", "Sites"],
  ["endpoint.", "Devices"],
  ["policy.", "Policies"],
  ["tag.", "Tags"],
  ["job.", "Jobs"],
  ["update.", "Updates and holds"],
  ["report", "Reports"],
  ["alert", "Alerts"],
  ["notifications.", "Notifications"],
  ["settings.", "Server settings"],
  ["lifecycle.", "OS lifecycle"],
  ["auth.", "Sign-ins"],
  ["user.", "Patching engine users"],
  ["api_token.", "API tokens"],
  ["sso.", "Single sign-on"],
];

const NOUNS: Record<string, string> = {
  organization: "Organization",
  site: "Site",
  endpoint: "Device",
  policy: "Policy",
  tag: "Tag",
  job: "Job",
  update: "Update",
  report: "Report",
  report_schedule: "Report schedule",
  alert: "Alert",
  alert_rule: "Alert rule",
  notifications: "Notifications",
  settings: "Server settings",
  lifecycle: "OS lifecycle entry",
  auth: "Sign-in",
  user: "User",
  api_token: "API token",
  sso: "Single sign-on",
  enrollment_token: "Enrollment token",
  enrollment_request: "Enrollment request",
  deployment_code: "Deployment code",
  cli: "Command line",
};

const VERBS: Record<string, string> = {
  create: "added",
  update: "changed",
  delete: "deleted",
  archive: "archived",
  restore: "restored",
  hold: "held",
  release: "released",
  approve: "approved",
  reject: "rejected",
  revoke: "revoked",
  cancel: "cancelled",
  retry: "retried",
  generate: "made",
  send: "sent",
  reset: "reset",
};

/** "Policy changed" for policy.update; the action itself, made readable, when it is not one of these. */
export function engineActionLabel(action: string): string {
  const dot = action.indexOf(".");
  if (dot < 0) return action;
  const noun = NOUNS[action.slice(0, dot)];
  const verb = action.slice(dot + 1);
  if (!noun) return action;
  return `${noun} ${VERBS[verb] ?? verb.replaceAll("_", " ")}`;
}

/** EasyPatch's details, laid out when they are JSON. */
function details(text: string): string {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

/** The start of a day in the browser's time zone, from 2006-01-02, as an instant; after adds a day. */
function dayStart(date: string, after = false): string | null {
  const [y, m, d] = date.split("-").map(Number);
  if (!y || !m || !d) return null;
  return new Date(y, m - 1, d + (after ? 1 : 0)).toISOString();
}

function Who({ e }: { e: PatchAuditEntry }) {
  if (e.via === "system") return <span className="text-muted">The patching engine, on its own</span>;
  return (
    <span className="flex min-w-0 flex-col items-start gap-0.5">
      <span className="block max-w-48 truncate" title={e.actor}>
        {e.actor}
      </span>
      <span className="text-xs text-muted">{e.via === "easyrmm" ? "Through EasyRMM" : "In the patching engine"}</span>
    </span>
  );
}

export function EngineAuditPanel() {
  const url = useUrlState();
  const organizationId = url.get("organizationId");
  const area = url.get("area");
  const from = url.get("from");
  const to = url.get("to");
  const page = Math.max(1, Number(url.get("page")) || 1);
  const backwards = from !== "" && to !== "" && to < from;
  const list = useApi<PatchAuditPage>(
    backwards ? null : "/patching/audit",
    {
      organizationId: organizationId || undefined,
      area: area || undefined,
      from: from ? (dayStart(from) ?? undefined) : undefined,
      to: to ? (dayStart(to, true) ?? undefined) : undefined,
      page: page > 1 ? page : undefined,
    },
    { keepPrevious: true },
  );
  const filtered = Boolean(organizationId || area || from || to);
  const pages = list.data ? Math.max(1, Math.ceil(list.data.totalCount / list.data.pageSize)) : 1;

  return (
    <div className="flex flex-col gap-3">
      <p className="max-w-3xl text-sm text-muted">
        The patching engine&apos;s own record: what people did through EasyRMM or in the engine directly, and what the engine did on its
        own, such as holding a failing update. EasyRMM&apos;s audit log, under Settings → Audit log, has its own record of what was done here.
      </p>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, page: null })} />
        <Field label="Area" htmlFor="engine-audit-area" className="min-w-44">
          <Select id="engine-audit-area" value={area} onChange={(e) => url.set({ area: e.target.value, page: null })}>
            <option value="">All areas</option>
            {ENGINE_AREAS.map(([prefix, label]) => (
              <option key={prefix} value={prefix}>
                {label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="From" htmlFor="engine-audit-from">
          <Input id="engine-audit-from" type="date" value={from} max={to || undefined} onChange={(e) => url.set({ from: e.target.value, page: null })} />
        </Field>
        <Field label="To" htmlFor="engine-audit-to">
          <Input id="engine-audit-to" type="date" value={to} min={from || undefined} onChange={(e) => url.set({ to: e.target.value, page: null })} />
        </Field>
        {filtered && (
          <Button variant="ghost" className="mb-0.5" onClick={() => url.set({ organizationId: null, area: null, from: null, to: null, page: null })}>
            Clear filters
          </Button>
        )}
      </Toolbar>
      {list.data && !list.data.everything && (
        <p className="text-xs text-muted">
          You see the entries of organizations whose patching and audit log you see as a whole. Entries of no organization, such
          as server settings, are for those who see every organization.
        </p>
      )}

      {backwards ? (
        <Alert tone="warn">Choose a To date on or after the From date.</Alert>
      ) : list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.data.items.length === 0 ? (
        <EmptyState title={filtered ? "No entries match these filters" : "No entries yet"} icon={<ScrollText className="size-8" aria-hidden />} />
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <caption className="sr-only">The patching engine&apos;s audit log</caption>
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Who</th>
                  <th scope="col">Action</th>
                  <th scope="col" className="hidden md:table-cell">
                    Organization
                  </th>
                  <th scope="col" className="hidden md:table-cell">
                    Device
                  </th>
                  <th scope="col" className="hidden xl:table-cell">
                    Source IP
                  </th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((e) => (
                  <tr key={e.id} className="align-top">
                    <td className="whitespace-nowrap" title={formatRelative(e.createdAt)}>
                      {formatDateTime(e.createdAt)}
                    </td>
                    <td>
                      <Who e={e} />
                    </td>
                    <td className="whitespace-nowrap" title={e.action}>
                      {engineActionLabel(e.action)}
                    </td>
                    <td className="hidden text-sm md:table-cell">
                      {e.organizationId ? (
                        <Link to={`/organizations/${e.organizationId}`} className="text-accent hover:underline">
                          {e.organizationName}
                        </Link>
                      ) : (
                        <span className="text-subtle">—</span>
                      )}
                    </td>
                    <td className="hidden text-sm md:table-cell">
                      {e.deviceId ? (
                        <Link to={`/devices/${e.deviceId}`} className="text-accent hover:underline">
                          {e.deviceName}
                        </Link>
                      ) : (
                        <span className="text-subtle">—</span>
                      )}
                    </td>
                    <td className="hidden font-mono text-xs whitespace-nowrap xl:table-cell">{e.ipAddress || "—"}</td>
                    <td className="max-w-md">
                      <details className="group">
                        <summary className="inline-flex cursor-pointer list-none items-center gap-0.5 text-xs text-accent [&::-webkit-details-marker]:hidden">
                          <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" aria-hidden />
                          Show
                        </summary>
                        <div className="mt-1 space-y-1">
                          <Mono className="inline-block">{e.action}</Mono>
                          {e.targetType && (
                            <p className="text-xs text-muted">
                              {e.targetType}
                              {e.targetId ? ` ${e.targetId}` : ""}
                            </p>
                          )}
                          {e.details && e.details !== "{}" && (
                            <pre className="max-h-64 overflow-auto rounded-md bg-raised p-2 font-mono text-xs whitespace-pre-wrap">{details(e.details)}</pre>
                          )}
                        </div>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <nav className="flex items-center justify-between gap-2 text-sm text-muted" aria-label="Pagination">
            <span>
              {formatNumber(list.data.totalCount)} entries, newest first{pages > 1 ? `; page ${formatNumber(page)} of ${formatNumber(pages)}` : ""}
            </span>
            {pages > 1 && (
              <div className="flex items-center gap-1">
                <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => url.set({ page: page - 1 > 1 ? String(page - 1) : null })}>
                  <ChevronLeft className="size-4" aria-hidden />
                  Newer
                </Button>
                <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => url.set({ page: String(page + 1) })}>
                  Older
                  <ChevronRight className="size-4" aria-hidden />
                </Button>
              </div>
            )}
          </nav>
        </>
      )}
    </div>
  );
}
