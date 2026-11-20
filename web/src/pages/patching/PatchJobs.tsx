import { ListChecks } from "lucide-react";
import { useApi } from "../../api/hooks";
import type { PatchJobList } from "../../api/types";
import { OrganizationSelect } from "../../components/Filters";
import { Button, Card, EmptyState, ErrorState, Segmented, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import {
  FilterSelect,
  isActiveJob,
  JOB_STATUS_OPTIONS,
  JOB_TRIGGERS,
  JOB_TYPE_OPTIONS,
  jobOutcome,
  jobTypeLabel,
  PatchJobBadge,
  requester,
  triggerLabel,
} from "./patchText";

const PERIODS = [
  { value: "", label: "Any time" },
  { value: "1", label: "Last 24 hours" },
  { value: "7", label: "Last 7 days" },
  { value: "30", label: "Last 30 days" },
];

/** The URL parameters the Jobs tab filters on, cleared together. */
export const JOB_FILTERS = { type: null, status: null, trigger: null, days: null } as const;

/** The start of a period of days back from now, to the minute, so the query does not change on every render. */
function since(days: string): string | undefined {
  const n = Number(days);
  if (!n) return undefined;
  return new Date(Math.floor(Date.now() / 60_000) * 60_000 - n * 86_400_000).toISOString();
}

/**
 * Patching → Jobs: the newest EasyPatch jobs of the devices the caller may see, refreshing quickly while any runs.
 * Running jobs by default; all recent ones filter by status, how they started and when.
 */
export function PatchJobs({ onJob }: { onJob: (id: string) => void }) {
  const url = useUrlState();
  const organizationId = url.get("organizationId");
  const which = url.get("active") === "false" ? "all" : "active";
  const type = url.get("type");
  const status = which === "all" ? url.get("status") : "";
  const trigger = which === "all" ? url.get("trigger") : "";
  const days = which === "all" ? url.get("days") : "";
  const filtered = Boolean(type || status || trigger || days);
  const jobs = useApi<PatchJobList>(
    "/patching/jobs",
    {
      organizationId: organizationId || undefined,
      active: which === "active" ? "true" : undefined,
      type: type || undefined,
      status: status || undefined,
      trigger: trigger || undefined,
      from: since(days),
    },
    {
      keepPrevious: true,
      refetchInterval: (data) => (data?.items.some(isActiveJob) ? 4_000 : 30_000),
    },
  );
  const items = jobs.data?.items ?? [];
  return (
    <>
      <Toolbar>
        <Segmented
          label="Jobs to show"
          className="self-end"
          value={which}
          onChange={(v) => url.set({ active: v === "all" ? "false" : null, status: null, trigger: null, days: null })}
          options={[
            { value: "active", label: "Still running" },
            { value: "all", label: "All recent" },
          ]}
        />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v })} />
        <FilterSelect
          label="Type"
          value={type}
          onChange={(v) => url.set({ type: v || null })}
          options={[{ value: "", label: "Any type" }, ...JOB_TYPE_OPTIONS]}
          className="w-48"
        />
        {which === "all" && (
          <>
            <FilterSelect
              label="Status"
              value={status}
              onChange={(v) => url.set({ status: v || null })}
              options={[{ value: "", label: "Any status" }, ...JOB_STATUS_OPTIONS]}
              className="w-44"
            />
            <FilterSelect
              label="Started"
              value={trigger}
              onChange={(v) => url.set({ trigger: v || null })}
              options={[{ value: "", label: "Any way" }, ...Object.entries(JOB_TRIGGERS).map(([value, label]) => ({ value, label }))]}
              className="w-36"
            />
            <FilterSelect label="Requested" value={days} onChange={(v) => url.set({ days: v || null })} options={PERIODS} className="w-36" />
          </>
        )}
      </Toolbar>
      {jobs.isPending ? (
        <Spinner />
      ) : jobs.isError ? (
        <ErrorState error={jobs.error} onRetry={() => void jobs.refetch()} />
      ) : items.length === 0 ? (
        <Card>
          {filtered ? (
            <EmptyState title="No jobs match" icon={<ListChecks className="size-8" aria-hidden />} compact>
              <p>Try other filters{which === "all" ? " or a longer period" : ""}.</p>
              <Button className="mt-3" onClick={() => url.set({ ...JOB_FILTERS })}>
                Clear filters
              </Button>
            </EmptyState>
          ) : (
            <EmptyState title={which === "active" ? "No patch jobs running" : "No patch jobs yet"} icon={<ListChecks className="size-8" aria-hidden />} compact>
              Scans, installs and restarts started here, from a device, or by the patching engine's own schedules show here.
            </EmptyState>
          )}
        </Card>
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Job</th>
                  <th>Status</th>
                  <th className="hidden md:table-cell">Result</th>
                  <th className="hidden lg:table-cell">Requested by</th>
                  <th className="hidden sm:table-cell">Requested</th>
                </tr>
              </thead>
              <tbody>
                {items.map((j) => (
                  <tr key={j.id} className="cursor-pointer" onClick={() => onJob(j.id)}>
                    <td>
                      <button type="button" className="rounded-sm text-left font-medium hover:text-accent" onClick={(e) => (e.stopPropagation(), onJob(j.id))}>
                        {jobTypeLabel(j.type)}
                      </button>
                      <p className="text-xs text-muted">{j.deviceName}</p>
                    </td>
                    <td>
                      <PatchJobBadge job={j} />
                      {j.progressMessage && isActiveJob(j) && <p className="mt-1 max-w-xs truncate text-xs text-muted">{j.progressMessage}</p>}
                    </td>
                    <td className="hidden text-muted md:table-cell">
                      {j.errorMessage ? <span className="text-danger">{j.errorMessage}</span> : jobOutcome(j) || "—"}
                    </td>
                    <td className="hidden max-w-56 text-muted lg:table-cell">
                      <span className="block truncate">{j.trigger === "Manual" ? requester(j.requestedBy) : triggerLabel(j.trigger)}</span>
                    </td>
                    <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={formatDateTime(j.createdAt)}>
                      {formatRelative(j.createdAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          {jobs.data?.capped && (
            <p className="mt-2 text-xs text-muted">
              These are the newest {items.length.toLocaleString()} that match; older ones are left out. Narrow the filters{which === "all" ? " or the period" : ""} to
              find them.
            </p>
          )}
        </>
      )}
    </>
  );
}
