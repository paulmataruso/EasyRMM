import { useId, useRef } from "react";
import { Link, useNavigate } from "react-router";
import { FileCode2, Plus } from "lucide-react";
import { useList, useOrganizations, usePrefetch } from "../../api/hooks";
import type { Script } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { SearchInput, SiteSelect } from "../../components/Filters";
import { buttonClasses, EmptyState, ErrorState, Field, PageHeader, Select, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useRowKeys } from "../../lib/rowKeys";
import { useUrlState } from "../../lib/urlState";
import { formatSeconds, scriptScope, SHELL_NAMES } from "./scriptText";

/** Whether the caller can write scripts somewhere, so the page offers "New script". */
export function useCanWriteScripts(): boolean {
  const { can, session } = useAuth();
  return session?.isSuperAdmin === true || can("script.manage");
}

export function ScriptsPage() {
  const url = useUrlState();
  const navigate = useNavigate();
  const prefetch = usePrefetch();
  const tableRef = useRef<HTMLDivElement>(null);
  const canWrite = useCanWriteScripts();
  const search = url.get("q");
  const library = url.get("library");
  const organizationId = library && library !== "shared" ? library : "";
  const siteId = organizationId ? url.get("siteId") : "";
  const filtered = Boolean(search || library);

  const params = {
    q: search || undefined,
    level: library === "shared" ? "shared" : undefined,
    organizationId: organizationId || undefined,
    siteId: siteId || undefined,
  };
  const list = useList<Script>("/scripts", params, { keepPrevious: true });
  const newLink = (
    <Link to="/scripts/new" className={buttonClasses("primary")}>
      <Plus className="size-4" aria-hidden />
      New script
    </Link>
  );

  useRowKeys(tableRef, (link) => link.dataset.id && prefetch(`/scripts/${link.dataset.id}`));

  return (
    <>
      <PageHeader
        title="Scripts"
        subtitle="The script library. Shared scripts run in every organization; organization and site scripts run only there."
        actions={canWrite ? newLink : undefined}
      />
      <Toolbar>
        <SearchInput value={search} onChange={(v) => url.set({ q: v })} placeholder="Name or description" className="max-w-xs" />
        <LibrarySelect value={library} onChange={(v) => url.set({ library: v, siteId: null })} />
        {organizationId && <SiteSelect organizationId={organizationId} value={siteId} onChange={(v) => url.set({ siteId: v })} />}
      </Toolbar>

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.items.length === 0 ? (
        <EmptyState
          title={filtered ? "No scripts match these filters" : "No scripts yet"}
          icon={<FileCode2 className="size-8" aria-hidden />}
          action={!filtered && canWrite ? newLink : undefined}
        >
          {!filtered &&
            (canWrite
              ? "Add a PowerShell or cmd script for Windows devices, or a Bash, sh or Python 3 script for Linux devices, then run it on devices that have the EasyRMM agent."
              : "An administrator adds scripts to the library; you can run them on the devices you support once they do.")}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <div ref={tableRef}>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th className="hidden md:table-cell">Runs in</th>
                    <th className="hidden sm:table-cell">Shell</th>
                    <th className="hidden lg:table-cell">Timeout</th>
                    <th className="hidden lg:table-cell">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {list.items.map((s) => (
                    <tr key={s.id} className="cursor-pointer" onClick={() => navigate(`/scripts/${s.id}`)} onMouseEnter={() => prefetch(`/scripts/${s.id}`)}>
                      <td>
                        <Link
                          to={`/scripts/${s.id}`}
                          className="rounded-sm font-medium hover:text-accent"
                          data-row-link
                          data-id={s.id}
                          onClick={(e) => e.stopPropagation()}
                          onFocus={() => prefetch(`/scripts/${s.id}`)}
                        >
                          {s.name}
                        </Link>
                        {s.description && <p className="max-w-md truncate text-xs text-muted">{s.description}</p>}
                        <p className="max-w-52 truncate text-xs text-muted md:hidden">{scriptScope(s)}</p>
                      </td>
                      <td className="hidden max-w-72 truncate md:table-cell">
                        {s.level === "shared" ? <span className="text-muted">All organizations</span> : scriptScope(s)}
                      </td>
                      <td className="hidden whitespace-nowrap sm:table-cell">{SHELL_NAMES[s.shell] ?? s.shell}</td>
                      <td className="hidden whitespace-nowrap text-muted lg:table-cell">{formatSeconds(s.timeoutSeconds)}</td>
                      <td className="hidden whitespace-nowrap text-muted lg:table-cell" title={formatDateTime(s.updatedAt)}>
                        {formatRelative(s.updatedAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </TableWrap>
          <p className="mt-2 text-xs text-muted">
            {plural(list.items.length, "script")}
            <span className="hidden sm:inline">
              . Press <kbd>j</kbd> and <kbd>k</kbd> to move between rows, <kbd>/</kbd> to search.
            </span>
          </p>
        </>
      )}
    </>
  );
}

/** All scripts, the shared library, or one organization's scripts (with its sites'). */
function LibrarySelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const orgs = useOrganizations();
  const id = useId();
  return (
    <Field label="Library" htmlFor={id} className="min-w-44">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} disabled={orgs.isPending}>
        <option value="">All scripts</option>
        <option value="shared">Shared library</option>
        {orgs.items.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name}
          </option>
        ))}
      </Select>
    </Field>
  );
}
