import { useMemo, useState } from "react";
import { Link } from "react-router";
import { ChevronRight, ScrollText, ShieldCheck } from "lucide-react";
import { api, errorMessage } from "../../api/client";
import { useList, useOrganizations } from "../../api/hooks";
import type { AuditEntry, AuditVerifyResult } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { OrganizationSelect } from "../../components/Filters";
import { ACTION_GROUPS, actionLabel, auditTarget, OutcomeBadge } from "../../components/StatusBadges";
import { Alert, Button, EmptyState, ErrorState, Field, Mono, Select, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";

export function AuditTab() {
  const { isSuperAdmin } = useAuth();
  const url = useUrlState();
  const orgs = useOrganizations();
  const organizationId = url.get("organizationId");
  const action = url.get("action");
  const actorId = url.get("actorId");
  const before = url.get("before");
  const list = useList<AuditEntry>("/audit", { organizationId, action, actorId, before, limit: 100 }, { keepPrevious: true });
  const filtered = Boolean(organizationId || action || actorId);
  const orgNames = useMemo(() => new Map(orgs.items.map((o) => [o.id, o.name])), [orgs.items]);
  const actorName = actorId ? list.items.find((e) => e.actorId === actorId)?.actorLabel : null;
  const verify = useChainVerification();

  return (
    <>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, before: null })} />
        <Field label="Area" htmlFor="audit-action" className="min-w-44">
          <Select id="audit-action" value={action} onChange={(e) => url.set({ action: e.target.value, before: null })}>
            <option value="">All actions</option>
            {ACTION_GROUPS.map(([prefix, label]) => (
              <option key={prefix} value={prefix}>
                {label}
              </option>
            ))}
          </Select>
        </Field>
        {filtered && (
          <Button variant="ghost" className="mb-0.5" onClick={() => url.set({ organizationId: null, action: null, actorId: null, before: null })}>
            Clear filters
          </Button>
        )}
        <div className="flex-1" />
        {isSuperAdmin && (
          <Button icon={<ShieldCheck className="size-4" aria-hidden />} loading={verify.busy} onClick={() => void verify.run()} className="mb-0.5">
            Verify integrity
          </Button>
        )}
      </Toolbar>
      {isSuperAdmin && <VerifyResult state={verify} />}
      {actorId && (
        <p className="mb-3 text-xs text-muted">
          Showing entries by {actorName ?? "one user"}.{" "}
          <button type="button" className="text-accent hover:underline" onClick={() => url.set({ actorId: null, before: null })}>
            Show everyone
          </button>
        </p>
      )}
      {!isSuperAdmin && <p className="mb-3 text-xs text-muted">You see entries for the organizations and sites where your role includes the audit log.</p>}

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.items.length === 0 ? (
        <EmptyState title={filtered ? "No audit entries match these filters" : "No audit entries yet"} icon={<ScrollText className="size-8" aria-hidden />} />
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
                  <th className="hidden md:table-cell">Organization</th>
                  <th className="hidden lg:table-cell">Source IP</th>
                  <th>Outcome</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {list.items.map((e) => (
                  <tr key={e.id} className="align-top">
                    <td className="whitespace-nowrap" title={formatRelative(e.occurredAt)}>
                      {formatDateTime(e.occurredAt)}
                    </td>
                    <td>
                      {e.actorId ? (
                        <button
                          type="button"
                          className="block max-w-48 truncate text-left hover:text-accent"
                          title={`${e.actorLabel}: show only this user's entries`}
                          onClick={() => url.set({ actorId: e.actorId, before: null })}
                        >
                          {e.actorLabel}
                        </button>
                      ) : (
                        <span className="block max-w-48 truncate text-muted" title={e.actorLabel || e.actorType}>
                          {e.actorLabel || e.actorType}
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap" title={e.action}>
                      {actionLabel(e.action)}
                    </td>
                    <td className="max-w-56 break-words">{auditTarget(e)}</td>
                    <td className="hidden text-sm md:table-cell">
                      {e.organizationId ? (
                        orgNames.has(e.organizationId) ? (
                          <Link to={`/organizations/${e.organizationId}`} className="text-accent hover:underline">
                            {orgNames.get(e.organizationId)}
                          </Link>
                        ) : (
                          <span className="text-muted" title={e.organizationId}>
                            Deleted organization
                          </span>
                        )
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className="hidden font-mono text-xs whitespace-nowrap lg:table-cell">{e.sourceIp ?? "—"}</td>
                    <td>
                      <OutcomeBadge outcome={e.outcome} />
                    </td>
                    <td className="max-w-md">
                      <details className="group">
                        <summary className="inline-flex cursor-pointer list-none items-center gap-0.5 text-xs text-accent [&::-webkit-details-marker]:hidden">
                          <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" aria-hidden />
                          Show
                        </summary>
                        <div className="mt-1 space-y-1">
                          <Mono className="inline-block">{e.action}</Mono>
                          {e.details && Object.keys(e.details).length > 0 && (
                            <pre className="max-h-64 overflow-auto rounded-md bg-raised p-2 font-mono text-xs whitespace-pre-wrap">{JSON.stringify(e.details, null, 2)}</pre>
                          )}
                          {e.userAgent && <p className="text-[11px] break-all text-subtle">{e.userAgent}</p>}
                        </div>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <nav className="mt-3 flex items-center justify-between gap-2 text-sm text-muted" aria-label="Pagination">
            <span>
              {formatNumber(list.items.length)} entries{before ? ", older page" : ", newest first"}
            </span>
            <div className="flex items-center gap-1">
              {before && (
                <Button size="sm" variant="ghost" onClick={() => url.set({ before: null })}>
                  Newest
                </Button>
              )}
              {list.next && (
                <Button size="sm" variant="ghost" onClick={() => url.set({ before: list.next })}>
                  Older entries
                  <ChevronRight className="size-4" aria-hidden />
                </Button>
              )}
            </div>
          </nav>
        </>
      )}
    </>
  );
}

const VERIFY_LIMIT = 1_000_000;

type Verification = { busy: boolean; result?: AuditVerifyResult; error?: unknown };

/** Recomputes the audit log's hash chain on the server (platform-wide auditors only). */
function useChainVerification() {
  const [state, setState] = useState<Verification>({ busy: false });
  async function run() {
    setState({ busy: true });
    try {
      setState({ busy: false, result: await api.get<AuditVerifyResult>("/audit/verify", { limit: VERIFY_LIMIT }) });
    } catch (error) {
      setState({ busy: false, error });
    }
  }
  return { ...state, run };
}

function VerifyResult({ state }: { state: Verification }) {
  if (state.error !== undefined) {
    return (
      <Alert tone="danger" className="mb-3">
        Could not verify the audit log. {errorMessage(state.error)}
      </Alert>
    );
  }
  if (!state.result) return null;
  const { checked, firstBadId } = state.result;
  return firstBadId === undefined ? (
    <Alert tone="ok" className="mb-3">
      Intact: {checked >= VERIFY_LIMIT ? `the first ${formatNumber(checked)}` : formatNumber(checked)} entries checked, none altered or removed.
    </Alert>
  ) : (
    <Alert tone="danger" title="The audit log has been altered" className="mb-3">
      Entry #{firstBadId} does not match the chain. Investigate the database before trusting entries from that point on.
    </Alert>
  );
}
