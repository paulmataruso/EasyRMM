import { Link } from "react-router";
import { PackageCheck, PauseCircle } from "lucide-react";
import { fieldError } from "../../api/client";
import { useApi } from "../../api/hooks";
import type { PatchFleetUpdate, PatchPage, PatchUpdateState } from "../../api/types";
import { OrganizationSelect, SearchInput, SiteSelect } from "../../components/Filters";
import { Badge, Card, cx, EmptyState, ErrorState, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDate, formatSize } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { categoryLabel, FilterSelect, Pager, UPDATE_STATES } from "./patchText";

/** EasyPatch's update categories. */
export const UPDATE_CATEGORIES = ["Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Feature", "Driver", "Other", "Application"];

/** The states the catalogue filters on; without one it lists what some device still needs. */
const STATE_FILTERS: PatchUpdateState[] = ["Missing", "Failed", "PendingReboot", "Reoffered", "Installed", "Excluded"];

const SORTS: { value: string; label: string }[] = [
  { value: "", label: "Exploited first, then most needed" },
  { value: "missing", label: "Most devices missing it" },
  { value: "failed", label: "Most failures" },
  { value: "installed", label: "Most installed" },
];

/** The query string of a scope (organization, site), for links that keep it. */
export function scopeQuery(organizationId: string, siteId: string): string {
  const q = new URLSearchParams();
  if (organizationId) q.set("organizationId", organizationId);
  if (siteId) q.set("siteId", siteId);
  const s = q.toString();
  return s ? `?${s}` : "";
}

/**
 * Patching → Updates: every update the devices in scope report, counted across them; those
 * fixing vulnerabilities exploited in the wild first. EasyPatch counts whole organizations or one site, so people
 * whose role covers single sites choose one.
 */
export function PatchUpdates() {
  const url = useUrlState();
  const q = url.get("q");
  const organizationId = url.get("organizationId");
  const siteId = url.get("siteId");
  const category = url.get("category");
  const state = url.get("state");
  const exploited = url.get("exploited");
  const sort = url.get("sort");
  const page = Math.max(1, Number(url.get("page")) || 1);
  const list = useApi<PatchPage<PatchFleetUpdate>>(
    "/patching/updates",
    {
      q: q || undefined,
      organizationId: organizationId || undefined,
      siteId: siteId || undefined,
      category: category || undefined,
      state: state || undefined,
      knownExploited: exploited === "true" ? "true" : undefined,
      sort: sort || undefined,
      page: page > 1 ? String(page) : undefined,
    },
    { keepPrevious: true, refetchInterval: 60_000 },
  );
  const filtered = Boolean(q || category || state || exploited);
  // Choosing an organization or a site is what the server asks of some roles, not an error.
  const choose = list.isError ? (fieldError(list.error, "siteId") ?? fieldError(list.error, "organizationId")) : null;
  const scope = scopeQuery(organizationId, siteId);

  return (
    <>
      <Toolbar>
        <SearchInput value={q} onChange={(v) => url.set({ q: v, page: null })} placeholder="Title, KB or package" className="max-w-xs" />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null, page: null })} />
        <SiteSelect organizationId={organizationId} value={siteId} onChange={(v) => url.set({ siteId: v, page: null })} className="max-w-64" />
        <FilterSelect
          label="Category"
          value={category}
          onChange={(v) => url.set({ category: v, page: null })}
          options={[{ value: "", label: "Every category" }, ...UPDATE_CATEGORIES.map((c) => ({ value: c, label: categoryLabel(c) }))]}
          className="min-w-36"
        />
        <FilterSelect
          label="Devices where it is"
          value={state}
          onChange={(v) => url.set({ state: v, page: null })}
          options={[{ value: "", label: "Still needed" }, ...STATE_FILTERS.map((s) => ({ value: s, label: UPDATE_STATES[s].label }))]}
          className="min-w-40"
        />
        <FilterSelect
          label="Exploitation"
          value={exploited === "true" ? "true" : ""}
          onChange={(v) => url.set({ exploited: v || null, page: null })}
          options={[
            { value: "", label: "Any" },
            { value: "true", label: "Exploited in the wild" },
          ]}
          className="min-w-36"
        />
        <FilterSelect label="Order" value={sort} onChange={(v) => url.set({ sort: v || null, page: null })} options={SORTS} className="min-w-52" />
      </Toolbar>
      {list.isPending ? (
        <Spinner />
      ) : choose ? (
        <Card>
          <EmptyState title={fieldError(list.error, "siteId") ? "Choose a site" : "Choose an organization"} icon={<PackageCheck className="size-8" aria-hidden />}>
            {choose}
          </EmptyState>
        </Card>
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.data.items.length === 0 ? (
        <Card>
          <EmptyState title={filtered ? "No updates match these filters" : "No updates needed"} icon={<PackageCheck className="size-8" aria-hidden />}>
            {!filtered && "No device in this view misses an update, fails one or waits for a restart after one, as of its last scan."}
          </EmptyState>
        </Card>
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Update</th>
                  <th className="text-right">Missing</th>
                  <th className="hidden text-right sm:table-cell">Failed</th>
                  <th className="hidden text-right md:table-cell">Needs a restart</th>
                  <th className="hidden text-right md:table-cell">Installed</th>
                  <th className="hidden text-right lg:table-cell">Excluded</th>
                  <th className="hidden xl:table-cell">Released</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((u) => (
                  <tr key={u.updateGuid}>
                    <td className="max-w-md">
                      <Link to={`/patching/updates/${u.updateGuid}${scope}`} className="block rounded-sm font-medium break-words hover:text-accent">
                        {u.title}
                      </Link>
                      <span className="text-xs text-muted">
                        {u.kbNumber && <>KB{u.kbNumber.replace(/^KB/i, "")} · </>}
                        {u.package && <>{u.package.name} · </>}
                        {categoryLabel(u.category)}
                        {u.msrcSeverity && <> · {u.msrcSeverity}</>}
                        {u.sizeBytes ? <> · {formatSize(u.sizeBytes)}</> : null}
                        {u.cveCount > 0 && <> · {u.cveCount === 1 ? "1 CVE" : `${u.cveCount.toLocaleString()} CVEs`}</>}
                      </span>
                      {(u.knownExploited || u.onHold) && (
                        <span className="mt-1 flex flex-wrap gap-1">
                          {u.knownExploited && <Badge tone="danger">Exploited in the wild</Badge>}
                          {u.onHold && (
                            <Badge tone="warn" icon={<PauseCircle className="size-3" aria-hidden />} title="Not installed automatically until the hold is released">
                              On hold
                            </Badge>
                          )}
                        </span>
                      )}
                    </td>
                    <Count n={u.missingCount + u.reofferedCount} tone={u.missingCount + u.reofferedCount > 0 ? "text-warn" : undefined} />
                    <Count n={u.failedCount} tone={u.failedCount > 0 ? "text-danger" : undefined} className="hidden sm:table-cell" />
                    <Count n={u.pendingRebootCount} className="hidden md:table-cell" />
                    <Count n={u.installedCount} className="hidden md:table-cell" />
                    <Count n={u.excludedCount} className="hidden lg:table-cell" />
                    <td className="hidden whitespace-nowrap text-muted xl:table-cell">{u.releaseDate ? formatDate(u.releaseDate) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pager page={list.data.page} total={list.data.totalCount} size={list.data.pageSize || 50} onPage={(p) => url.set({ page: p > 1 ? String(p) : null })} />
          <p className="mt-2 text-xs text-muted">Counted from each device's last scan, as EasyPatch reports it; refreshed every minute.</p>
        </>
      )}
    </>
  );
}

function Count({ n, tone, className }: { n: number; tone?: string; className?: string }) {
  return <td className={cx("text-right tabular-nums", n === 0 ? "text-subtle" : (tone ?? "text-fg"), className)}>{n.toLocaleString()}</td>;
}
