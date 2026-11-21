import { useId, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
import { ListChecks, PackagePlus } from "lucide-react";
import { useList, usePrefetch } from "../../api/hooks";
import type { Job } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { DeviceScope, OrganizationSelect, SiteSelect } from "../../components/Filters";
import { Button, EmptyState, ErrorState, Field, PageHeader, Select, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useRowKeys } from "../../lib/rowKeys";
import { useUrlState } from "../../lib/urlState";
import { JobStateBadge, StatusBreakdown } from "../scripts/parts";
import { SoftwareDialog } from "../software/SoftwareDialog";

/** The server's cap on one list response (jobs.MaxList). */
const MAX_JOBS = 200;

/** Refresh quickly while something is still running, slowly otherwise. */
export function jobsInterval(items: { finished: boolean }[] | undefined): number {
  return items?.some((j) => !j.finished) ? 4_000 : 30_000;
}

export function JobsPage() {
  const url = useUrlState();
  const status = url.get("status");
  const organizationId = url.get("organizationId");
  const siteId = url.get("siteId");
  const deviceId = url.get("deviceId");
  const kind = url.get("kind");
  const filtered = Boolean(status || organizationId || siteId || deviceId || kind);
  const { can } = useAuth();
  const [installing, setInstalling] = useState(false);
  return (
    <>
      <PageHeader
        title="Jobs"
        subtitle="Scripts, software actions and hardening checks started on devices, newest first. A job runs one script on one or more devices."
        actions={
          can("software.manage") && (
            <Button icon={<PackagePlus className="size-4" aria-hidden />} onClick={() => setInstalling(true)}>
              Install software
            </Button>
          )
        }
      />
      <SoftwareDialog open={installing} onClose={() => setInstalling(false)} />
      <Toolbar>
        <KindSelect value={kind} onChange={(v) => url.set({ kind: v })} />
        <StatusSelect value={status} onChange={(v) => url.set({ status: v })} />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null, deviceId: null })} />
        <SiteSelect organizationId={organizationId} value={siteId} onChange={(v) => url.set({ siteId: v, deviceId: null })} />
        {deviceId && <DeviceScope deviceId={deviceId} clearLabel="Show jobs on every device" onClear={() => url.set({ deviceId: null })} />}
      </Toolbar>
      <JobsTable
        params={{
          status: status || undefined,
          kind: kind || undefined,
          organizationId: organizationId || undefined,
          siteId: siteId || undefined,
          deviceId: deviceId || undefined,
        }}
        empty={filtered ? "No jobs match these filters." : "No jobs yet. Run a script from the script library or a device, or install software."}
        withCount
      />
    </>
  );
}

/** Jobs as a table with row travel; refreshes while any is running. */
export function JobsTable({ params, empty, withCount = false }: { params: Record<string, string | undefined>; empty: string; withCount?: boolean }) {
  const navigate = useNavigate();
  const prefetch = usePrefetch();
  const tableRef = useRef<HTMLDivElement>(null);
  const list = useList<Job>("/jobs", params, { keepPrevious: true, refetchInterval: (data) => jobsInterval(data?.items) });
  useRowKeys(tableRef, (link) => link.dataset.id && prefetch(`/jobs/${link.dataset.id}`));

  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  if (list.items.length === 0) {
    return (
      <div className="rounded-lg border border-line bg-surface">
        <EmptyState title={empty} icon={<ListChecks className="size-8" aria-hidden />} compact />
      </div>
    );
  }
  return (
    <>
      <TableWrap>
        <div ref={tableRef}>
          <table className="table-base">
            <thead>
              <tr>
                <th>Job</th>
                <th>Status</th>
                <th className="hidden md:table-cell">Devices</th>
                <th className="hidden lg:table-cell">Started by</th>
                <th className="hidden sm:table-cell">Started</th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((j) => (
                <tr key={j.id} className="cursor-pointer" onClick={() => navigate(`/jobs/${j.id}`)} onMouseEnter={() => prefetch(`/jobs/${j.id}`)}>
                  <td>
                    <Link
                      to={`/jobs/${j.id}`}
                      className="rounded-sm font-medium hover:text-accent"
                      data-row-link
                      data-id={j.id}
                      onClick={(e) => e.stopPropagation()}
                      onFocus={() => prefetch(`/jobs/${j.id}`)}
                    >
                      {j.scriptName}
                    </Link>
                    <p className="text-xs text-muted md:hidden">{plural(j.total, "device")}</p>
                  </td>
                  <td>
                    <JobStateBadge job={j} />
                  </td>
                  <td className="hidden md:table-cell">
                    <StatusBreakdown job={j} />
                  </td>
                  <td className="hidden max-w-56 truncate text-muted lg:table-cell">{j.createdBy}</td>
                  <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={formatDateTime(j.createdAt)}>
                    {formatRelative(j.createdAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </TableWrap>
      {withCount && (
        <p className="mt-2 text-xs text-muted">
          {list.items.length >= MAX_JOBS ? `Showing the newest ${MAX_JOBS} jobs` : plural(list.items.length, "job")}
          <span className="hidden sm:inline">
            . Press <kbd>j</kbd> and <kbd>k</kbd> to move between rows.
          </span>
        </p>
      )}
    </>
  );
}

function KindSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId();
  return (
    <Field label="Kind" htmlFor={id} className="min-w-40">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Every kind</option>
        <option value="script">Scripts</option>
        <option value="software">Software</option>
        <option value="hardening">Hardening</option>
      </Select>
    </Field>
  );
}

function StatusSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId();
  return (
    <Field label="Status" htmlFor={id} className="min-w-40">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Any status</option>
        <option value="open">Running or waiting</option>
        <option value="finished">Finished</option>
      </Select>
    </Field>
  );
}
