import { useState } from "react";
import { Link, useLocation } from "react-router";
import { BellOff, CheckCheck, X } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchAlert, PatchAlertList } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { SearchInput } from "../../components/Filters";
import { useToast } from "../../components/Toast";
import { Button, Card, cx, EmptyState, ErrorState, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { PatchAlertCard } from "./PatchAlertCard";
import { PatchAlertState, PatchSeverityBadge, RULE_KIND_ORDER, RULE_KINDS, SEVERITIES } from "./patchAlertText";
import { FilterSelect } from "./patchText";

/** The URL parameters the Alerts tab filters on, cleared together. */
export const ALERT_FILTERS = { show: null, severity: null, ruleType: null, search: null, deviceId: null } as const;

const SHOW = [
  { value: "", label: "Needs attention" },
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
  { value: "all", label: "All" },
];

/**
 * Patching → Alerts: the alerts EasyPatch raises by its rules, for the devices whose patching the
 * caller sees, and an organization's own alerts for those who see all of it. Open and acknowledged ones by default, the
 * most severe first; acknowledging says someone is on it, and EasyPatch resolves an alert itself once its cause is gone.
 */
export function PatchAlerts() {
  const url = useUrlState();
  const toast = useToast();
  const { can, session } = useAuth();
  const location = useLocation();
  const organizationId = url.get("organizationId");
  const show = url.get("show");
  const severity = url.get("severity");
  const ruleType = url.get("ruleType");
  const search = url.get("search");
  const deviceId = url.get("deviceId");
  const filtered = Boolean(show || severity || ruleType || search || deviceId);
  const list = useApi<PatchAlertList>(
    "/patching/alerts",
    {
      organizationId: organizationId || undefined,
      status: show || undefined,
      severity: severity || undefined,
      ruleType: ruleType || undefined,
      search: search || undefined,
      deviceId: deviceId || undefined,
    },
    { keepPrevious: true, refetchInterval: 60_000 },
  );
  const items = list.data?.items ?? [];
  const selectable = items.filter((a) => a.canAcknowledge);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const chosen = selectable.filter((a) => selected.has(a.id));
  const all = selectable.length > 0 && chosen.length === selectable.length;
  const showSelect = can("patch.manage") && selectable.length > 0;
  const acknowledge = useApiMutation((ids: string[]) => api.post<{ acknowledged: number }>("/patching/alerts/acknowledge", { alertIds: ids }), {
    invalidate: ["/patching/alerts"],
    onSuccess: (r, ids) => {
      setSelected(new Set());
      if (r.acknowledged === ids.length) toast.success(`${plural(r.acknowledged, "alert")} acknowledged.`);
      else toast.info(`${plural(r.acknowledged, "alert")} acknowledged; the rest were acknowledged or resolved already.`);
    },
  });
  const device = deviceId ? items.find((a) => a.deviceId === deviceId)?.deviceName : null;
  // The alert whose card is open: its row as the list last loaded it, or as the card last knew it once the list no
  // longer has it (acknowledged under the Open filter, say). The card stays open only on the address it opened on, so
  // a link in it that leads elsewhere on this page closes it.
  const [card, setCard] = useState<PatchAlert | null>(null);
  const [openOn, setOpenOn] = useState<string | null>(null);
  const shown = card ? (items.find((a) => a.id === card.id) ?? card) : null;
  const acknowledgeShown = () => {
    if (!shown) return;
    acknowledge.mutate([shown.id], {
      // EasyPatch answers with a count only: one means it is acknowledged now, by this user.
      onSuccess: (r) =>
        setCard({
          ...shown,
          canAcknowledge: false,
          ...(r.acknowledged > 0 ? { status: "Acknowledged" as const, acknowledgedAt: new Date().toISOString(), acknowledgedBy: session?.user.email ?? null } : {}),
        }),
    });
  };
  const cardError = shown && acknowledge.isError && acknowledge.variables?.length === 1 && acknowledge.variables[0] === shown.id ? acknowledge.error.message : null;

  return (
    <>
      <Toolbar>
        <FilterSelect label="Show" value={show} onChange={(v) => url.set({ show: v || null })} options={SHOW} className="w-44" />
        <FilterSelect
          label="Severity"
          value={severity}
          onChange={(v) => url.set({ severity: v || null })}
          options={[{ value: "", label: "Any severity" }, ...SEVERITIES.map((s) => ({ value: s, label: s }))]}
          className="w-36"
        />
        <FilterSelect
          label="Type"
          value={ruleType}
          onChange={(v) => url.set({ ruleType: v || null })}
          options={[{ value: "", label: "Any type" }, ...RULE_KIND_ORDER.map((k) => ({ value: k, label: RULE_KINDS[k].label }))]}
          className="w-60"
        />
        <SearchInput value={search} onChange={(v) => url.set({ search: v || null })} placeholder="Search alerts" className="w-56" />
      </Toolbar>
      {deviceId && (
        <p className="-mt-1 mb-3 flex items-center gap-2 text-sm text-muted">
          Alerts of {device ?? "one device"}
          <Button size="sm" variant="ghost" onClick={() => url.set({ deviceId: null })} icon={<X className="size-3.5" aria-hidden />}>
            Show every device
          </Button>
        </p>
      )}
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : items.length === 0 ? (
        <Card>
          {filtered ? (
            <EmptyState title="No alerts match" icon={<BellOff className="size-8" aria-hidden />} compact>
              <p>Try other filters.</p>
              <Button className="mt-3" onClick={() => url.set({ ...ALERT_FILTERS })}>
                Clear filters
              </Button>
            </EmptyState>
          ) : (
            <EmptyState title="Nothing needs attention" icon={<BellOff className="size-8" aria-hidden />} compact>
              The patching engine checks its alert rules every 2 minutes. Alerts it raises for your devices show here until their cause is gone.
            </EmptyState>
          )}
        </Card>
      ) : (
        <>
          {showSelect && (
            <div className="mb-2 flex min-h-9 flex-wrap items-center gap-3 text-sm">
              <span className="text-muted">{chosen.length > 0 ? `${plural(chosen.length, "alert")} selected` : "Select alerts to acknowledge them together."}</span>
              {chosen.length > 0 && (
                <Button
                  size="sm"
                  variant="primary"
                  loading={acknowledge.isPending}
                  icon={<CheckCheck className="size-3.5" aria-hidden />}
                  onClick={() => acknowledge.mutate(chosen.map((a) => a.id))}
                >
                  Acknowledge
                </Button>
              )}
              {acknowledge.error && <span className="text-danger">{acknowledge.error.message}</span>}
            </div>
          )}
          <TableWrap>
            <table className="table-base">
              <caption className="sr-only">Patching alerts</caption>
              <thead>
                <tr>
                  {showSelect && (
                    <th scope="col" className="w-10">
                      <input
                        type="checkbox"
                        aria-label="Select every alert you can acknowledge"
                        checked={all}
                        ref={(el) => {
                          if (el) el.indeterminate = chosen.length > 0 && !all;
                        }}
                        onChange={(e) => setSelected(e.target.checked ? new Set(selectable.map((a) => a.id)) : new Set())}
                      />
                    </th>
                  )}
                  <th scope="col">Alert</th>
                  <th scope="col" className="hidden md:table-cell">
                    Device
                  </th>
                  <th scope="col" className="hidden sm:table-cell">
                    Opened
                  </th>
                  <th scope="col">State</th>
                  <th scope="col" className="w-0">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <AlertRow
                    key={a.id}
                    alert={a}
                    showSelect={showSelect}
                    selected={selected.has(a.id)}
                    onSelect={(on) =>
                      setSelected((s) => {
                        const next = new Set(s);
                        if (on) next.add(a.id);
                        else next.delete(a.id);
                        return next;
                      })
                    }
                    onAcknowledge={() => acknowledge.mutate([a.id])}
                    onOpen={() => {
                      setCard(a);
                      setOpenOn(location.key);
                      acknowledge.reset();
                    }}
                    busy={acknowledge.isPending}
                  />
                ))}
              </tbody>
            </table>
          </TableWrap>
          {list.data.capped && (
            <p className="mt-2 text-xs text-muted">
              These are the first {items.length.toLocaleString()} that match, the most severe first; the rest are left out. Narrow the filters to find
              them.
            </p>
          )}
        </>
      )}
      <PatchAlertCard
        alert={shown}
        open={openOn === location.key}
        onClose={() => setOpenOn(null)}
        onAcknowledge={acknowledgeShown}
        busy={acknowledge.isPending}
        error={cardError}
      />
    </>
  );
}

function Where({ a }: { a: PatchAlert }) {
  if (a.deviceId) {
    return (
      <>
        <Link to={`/devices/${a.deviceId}?tab=patches`} className="rounded-sm font-medium hover:text-accent">
          {a.deviceName}
        </Link>
        <span className="block text-xs text-muted">{a.organizationName}</span>
      </>
    );
  }
  if (a.hostname) {
    return (
      <>
        <span className="font-medium">{a.hostname}</span>
        <span className="block text-xs text-muted">{a.organizationName}, no EasyRMM device</span>
      </>
    );
  }
  return (
    <>
      <span>{a.organizationName}</span>
      <span className="block text-xs text-muted">The whole organization</span>
    </>
  );
}

function AlertRow({ alert: a, showSelect, selected, onSelect, onAcknowledge, onOpen, busy }: {
  alert: PatchAlert;
  showSelect: boolean;
  selected: boolean;
  onSelect: (on: boolean) => void;
  onAcknowledge: () => void;
  /** Opens the alert's card. */
  onOpen: () => void;
  busy: boolean;
}) {
  return (
    <tr className={cx("align-top", selected && "bg-accent-soft/40")}>
      {showSelect && (
        <td>
          {a.canAcknowledge && <input type="checkbox" aria-label={`Select ${a.title}`} checked={selected} onChange={(e) => onSelect(e.target.checked)} />}
        </td>
      )}
      <td>
        <div className="flex flex-col items-start gap-1">
          <PatchSeverityBadge severity={a.severity} />
          <button
            type="button"
            onClick={onOpen}
            aria-label={`${a.title}, details`}
            title="Show the alert's details"
            className="max-w-xl rounded-sm text-left font-medium break-words hover:text-accent"
          >
            {a.title}
          </button>
          {a.details && <span className="max-w-xl text-xs whitespace-pre-line text-muted">{a.details}</span>}
          <span className="text-xs text-muted">
            {RULE_KINDS[a.ruleType]?.label ?? a.ruleType}
            {a.ruleName && a.ruleName !== RULE_KINDS[a.ruleType]?.label ? ` · ${a.ruleName}` : ""}
          </span>
          {/* On a phone, the device goes under the alert. */}
          <span className="text-xs md:hidden">
            <Where a={a} />
          </span>
        </div>
      </td>
      <td className="hidden md:table-cell">
        <Where a={a} />
      </td>
      <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={formatDateTime(a.openedAt)}>
        {formatRelative(a.openedAt)}
        {a.status !== "Resolved" && a.lastSeenAt !== a.openedAt && <span className="block text-xs">seen {formatRelative(a.lastSeenAt)}</span>}
      </td>
      <td>
        <PatchAlertState alert={a} />
      </td>
      <td className="whitespace-nowrap">
        {a.canAcknowledge && (
          <Button size="sm" variant="ghost" onClick={onAcknowledge} disabled={busy} aria-label={`Acknowledge ${a.title}`}>
            Acknowledge
          </Button>
        )}
      </td>
    </tr>
  );
}
