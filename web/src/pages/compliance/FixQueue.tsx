import { useMemo, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api/client";
import { useApiMutation, useList } from "../../api/hooks";
import type { FixItem, Permission } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { useToast } from "../../components/Toast";
import { Badge, Button, EmptyState, ErrorState, Segmented, Spinner, TableWrap } from "../../components/ui";
import { formatRelative } from "../../lib/format";
import { DeclineDialog } from "./DeclineDialog";
import { FixDialog, type FixAct } from "./FixDialog";
import { bulkProblem, FIX_STATES, TIERS, valueText } from "./complianceText";

type View = "queue" | "history";

/** States an agent is working on: the queue asks again soon. */
const BUSY = ["applying", "applied", "undoing"];

/**
 * The fix queue (ADR-0078, section 6): one item per failed control on a computer, with the warning's tier, its state, the
 * requirements it would help, and what the person may do with it. Nothing is chosen by default and there is no "fix all":
 * safe items may be chosen together, one control of tier 2 on several computers, and tier 3 one at a time.
 */
export function FixQueue({ organizationId, deviceId, siteId }: { organizationId: string; deviceId?: string; siteId?: string }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const [view, setView] = useState<View>("queue");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<{ act: FixAct; items: FixItem[] } | null>(null);
  const [declining, setDeclining] = useState<FixItem | null>(null);
  const list = useList<FixItem>(
    `/organizations/${organizationId}/compliance/fixes`,
    { state: view === "queue" ? "active" : "history", deviceId, siteId },
    { refetchInterval: (d) => (d?.items.some((i) => BUSY.includes(i.state)) ? 3_000 : 15_000), keepPrevious: true },
  );
  const reopen = useApiMutation((item: FixItem) => api.post(`/organizations/${organizationId}/compliance/fixes/${item.id}/reopen`), {
    invalidate: [`/organizations/${organizationId}/compliance`],
    onSuccess: () => toast.success("Back in the queue."),
  });
  const at = (p: Permission, i: FixItem) => canAt(p, { organizationId, siteId: i.siteId });
  const mayFix = (i: FixItem) => at(i.tier === "T3" ? "compliance.fix_high" : "compliance.fix", i) && at("device.harden", i);

  const items = list.items;
  const picked = useMemo(() => items.filter((i) => chosen.has(i.id)), [items, chosen]);
  const problem = bulkProblem(picked);
  const toggle = (id: string, on: boolean) =>
    setChosen((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  const open = (i: FixItem) => i.state === "open" || i.state === "not_verified";

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Segmented
          label="Show"
          value={view}
          onChange={(v) => {
            setView(v);
            setChosen(new Set());
          }}
          options={[
            { value: "queue", label: "Queue" },
            { value: "history", label: "History" },
          ]}
        />
        {view === "queue" && picked.length > 0 && (
          <div className="flex items-center gap-2">
            {problem && <span className="text-xs text-warn">{problem}</span>}
            <Button variant="danger" disabled={problem !== null || !picked.every(mayFix)} onClick={() => setDialog({ act: "apply", items: picked })}>
              Apply {picked.length} chosen…
            </Button>
          </div>
        )}
      </div>

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : items.length === 0 ? (
        <EmptyState title={view === "queue" ? "Nothing to fix" : "No history yet"} compact>
          {view === "queue" ? "A scan adds an item for each control that does not meet and has a fix." : "Fixes, undos and items set aside show here."}
        </EmptyState>
      ) : (
        <TableWrap>
          <table className="w-full text-left text-sm" aria-label={view === "queue" ? "Fix queue" : "Fix history"}>
            <thead>
              <tr className="text-xs text-muted">
                <th className="w-8 px-3 py-2" />
                {!deviceId && <th className="px-2 py-2 font-medium">Computer</th>}
                <th className="px-2 py-2 font-medium">Control</th>
                <th className="px-2 py-2 font-medium">Risk</th>
                <th className="px-2 py-2 font-medium">State</th>
                <th className="px-2 py-2 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {items.map((i) => {
                const st = FIX_STATES[i.state];
                const selectable = view === "queue" && open(i) && i.applyBlocked === "" && i.tier !== "T3" && mayFix(i);
                return (
                  <tr key={i.id}>
                    <td className="px-3 py-2 align-top">
                      {selectable && (
                        <input
                          type="checkbox"
                          className="size-4 accent-accent"
                          aria-label={`Choose ${i.title} on ${i.deviceName}`}
                          checked={chosen.has(i.id)}
                          onChange={(e) => toggle(i.id, e.target.checked)}
                        />
                      )}
                    </td>
                    {!deviceId && (
                      <td className="px-2 py-2 align-top">
                        <Link to={`/devices/${i.deviceId}?tab=compliance`} className="text-accent hover:underline">
                          {i.deviceName}
                        </Link>
                      </td>
                    )}
                    <td className="px-2 py-2 align-top">
                      <span className="font-medium">{i.title}</span>
                      {valueText(i.observed) !== "" && (
                        <span className="block text-xs text-muted">
                          Now {valueText(i.observed)}
                          {valueText(i.expected) !== "" && valueText(i.expected) !== valueText(i.observed) ? `, wanted ${valueText(i.expected)}` : ""}
                        </span>
                      )}
                      {i.requirements.length > 0 && (
                        <span className="block text-xs text-muted">
                          Would help: {i.requirements.slice(0, 4).map((r) => `${r.framework} ${r.id}`).join(", ")}
                          {i.requirements.length > 4 ? ` and ${i.requirements.length - 4} more` : ""}
                        </span>
                      )}
                      {i.applyBlocked !== "" && open(i) && <span className="block text-xs text-muted">{i.applyBlocked}</span>}
                      {i.failReason !== "" && <span className="block text-xs text-warn">{i.failReason}</span>}
                      {i.decline && (
                        <span className="block text-xs text-muted">
                          {i.decline.kind === "deferred" ? "Deferred" : "Risk accepted"}: {i.decline.reason}
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-2 align-top">
                      <Badge tone={TIERS[i.tier].tone} title={TIERS[i.tier].title}>
                        {TIERS[i.tier].label}
                      </Badge>
                    </td>
                    <td className="px-2 py-2 align-top">
                      <Badge tone={st.tone} title={st.title}>
                        {st.label}
                      </Badge>
                      <span className="block text-xs text-muted">{formatRelative(i.updatedAt)}</span>
                    </td>
                    <td className="px-2 py-2 text-right align-top">
                      <div className="flex flex-wrap justify-end gap-1.5">
                        {open(i) && i.applyBlocked === "" && mayFix(i) && (
                          <Button size="sm" variant="danger" aria-label={`Apply ${i.title} on ${i.deviceName}`} onClick={() => setDialog({ act: "apply", items: [i] })}>
                            Apply…
                          </Button>
                        )}
                        {i.state === "awaiting_approval" && at("compliance.fix_approve", i) && (
                          <Button size="sm" aria-label={`Approve ${i.title} on ${i.deviceName}`} onClick={() => setDialog({ act: "approve", items: [i] })}>
                            Approve…
                          </Button>
                        )}
                        {i.canUndo && mayFix(i) && (
                          <Button size="sm" aria-label={`Undo ${i.title} on ${i.deviceName}`} onClick={() => setDialog({ act: "undo", items: [i] })}>
                            Undo…
                          </Button>
                        )}
                        {(i.state === "open" || i.state === "awaiting_approval") && at("compliance.fix", i) && (
                          <Button size="sm" variant="ghost" aria-label={`Set aside ${i.title} on ${i.deviceName}`} onClick={() => setDeclining(i)}>
                            Set aside…
                          </Button>
                        )}
                        {i.state === "declined" && at("compliance.fix", i) && (
                          <Button size="sm" variant="ghost" loading={reopen.isPending} onClick={() => reopen.mutate(i)}>
                            Reopen
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
      <FixDialog
        act={dialog?.act ?? null}
        items={dialog?.items ?? []}
        organizationId={organizationId}
        onClose={() => {
          setDialog(null);
          setChosen(new Set());
        }}
      />
      <DeclineDialog item={declining} organizationId={organizationId} onClose={() => setDeclining(null)} />
    </div>
  );
}
