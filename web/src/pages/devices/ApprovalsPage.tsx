import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { Check, Hourglass, Info, KeyRound, X } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList, useSites } from "../../api/hooks";
import type { ApproveInput, DeviceGroup, EnrollmentDecision, EnrollmentRequest, EnrollmentRequestList, Platform, Site } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import {
  Button,
  buttonClasses,
  Card,
  cx,
  Dot,
  EmptyState,
  ErrorState,
  IconButton,
  InlineError,
  Mono,
  PageHeader,
  SelectField,
  Spinner,
  TableWrap,
  Tabs,
} from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { platformName } from "./platform";

type View = "pending" | "rejected";

/**
 * Devices installed with an approval token (ADR-0024). They wait here, in no organization yet, until someone who
 * manages enrollment platform-wide approves them into a site, where they take their computer's name, or rejects them.
 */
export function ApprovalsPage() {
  const { canGlobal } = useAuth();
  const url = useUrlState();
  const view: View = url.get("state") === "rejected" ? "rejected" : "pending";
  const allowed = canGlobal("enrollment.manage");
  const list = useApi<EnrollmentRequestList>(allowed ? "/enrollment-requests" : null, view === "rejected" ? { state: "rejected" } : undefined, {
    refetchInterval: view === "pending" ? 10_000 : 60_000,
  });

  const header = (
    <PageHeader
      breadcrumb={
        <Link to="/devices" className="hover:text-fg">
          Devices
        </Link>
      }
      title="Waiting for approval"
      subtitle="Devices installed with an approval token wait here until you approve them into a site, where each takes its computer's name."
      actions={
        allowed && (
          <Link to="/devices/add?mode=approval" className={buttonClasses("secondary")}>
            <KeyRound className="size-4" aria-hidden />
            New approval token
          </Link>
        )
      }
    />
  );

  if (!allowed) {
    return (
      <>
        {header}
        <EmptyState title="Not available to your role" icon={<KeyRound className="size-8" aria-hidden />}>
          Devices waiting for approval belong to no organization yet, so deciding on them needs a role that manages enrollment on the whole server,
          such as Super Administrator.
        </EmptyState>
      </>
    );
  }

  const waiting = list.data?.waiting;
  return (
    <>
      {header}
      <Tabs
        className="mb-4"
        active={view}
        onChange={(id) => url.set({ state: id === "rejected" ? "rejected" : null })}
        tabs={[
          {
            id: "pending",
            label: (
              <>
                Waiting
                {waiting !== undefined && waiting > 0 && <span className="ml-1.5 text-xs text-muted tabular-nums">{waiting.toLocaleString()}</span>}
              </>
            ),
          },
          { id: "rejected", label: "Rejected" },
        ]}
      />
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : view === "pending" ? (
        <WaitingTable items={list.data.items} />
      ) : (
        <RejectedTable items={list.data.items} />
      )}
    </>
  );
}

function systemLine(r: EnrollmentRequest): string {
  return [platformName(r.platform as Platform), r.arch, r.agentVersion && `agent ${r.agentVersion}`].filter(Boolean).join(" · ");
}

function DeviceCell({ r }: { r: EnrollmentRequest }) {
  return (
    <>
      <span className="block max-w-72 truncate font-medium" title={r.hostname}>
        {r.hostname}
      </span>
      <span className="block text-xs text-muted">
        Code <Mono className="whitespace-nowrap">{r.code}</Mono>
      </span>
      {r.matches.length > 0 && (
        <span className="mt-1 flex items-start gap-1 text-xs text-muted">
          <Info className="mt-0.5 size-3 shrink-0 text-info" aria-hidden />
          <span>
            Same name as{" "}
            {r.matches.map((m, i) => (
              <span key={m.deviceId}>
                {i > 0 && ", "}
                <Link to={`/devices/${m.deviceId}`} className="text-accent hover:underline">
                  {m.name}
                </Link>{" "}
                in {m.organizationName} / {m.siteName}
              </span>
            ))}
            . A reinstall comes back as a new device.
          </span>
        </span>
      )}
    </>
  );
}

function SystemCell({ r }: { r: EnrollmentRequest }) {
  return (
    <td className="hidden align-top lg:table-cell">
      <span className="block max-w-56 truncate" title={r.os}>
        {r.os || platformName(r.platform as Platform)}
      </span>
      <span className="block max-w-56 truncate text-xs text-muted">{systemLine(r)}</span>
    </td>
  );
}

/** Where the request came from: the address the agent asked from, and the token it used. */
function FromCell({ r }: { r: EnrollmentRequest }) {
  return (
    <td className="hidden align-top xl:table-cell">
      <span className="block whitespace-nowrap tabular-nums">{r.sourceIp || <span className="text-muted">Unknown address</span>}</span>
      <span className="block max-w-44 truncate text-xs text-muted" title={`Token: ${r.tokenName}`}>
        {r.tokenName}
      </span>
    </td>
  );
}

function AskedState({ r }: { r: EnrollmentRequest }) {
  return (
    <>
      <span className="flex items-center gap-1.5 whitespace-nowrap">
        <Dot tone={r.online ? "ok" : "neutral"} />
        {r.online ? "Waiting now" : formatRelative(r.lastSeenAt)}
      </span>
      {!r.online && <span className="block text-xs text-muted">not asking</span>}
    </>
  );
}

function WaitingTable({ items }: { items: EnrollmentRequest[] }) {
  const toast = useToast();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [approving, setApproving] = useState<EnrollmentRequest[] | null>(null);
  const [rejecting, setRejecting] = useState<EnrollmentRequest[] | null>(null);

  // Decided or vanished requests leave the selection when the list refreshes.
  useEffect(() => {
    setSelected((prev) => {
      const ids = new Set(items.map((r) => r.id));
      const next = new Set([...prev].filter((id) => ids.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [items]);

  const reject = useApiMutation((rs: EnrollmentRequest[]) => api.post<EnrollmentDecision>("/enrollment-requests/reject", { ids: rs.map((r) => r.id) }), {
    invalidate: ["/enrollment-requests", "/approval-tokens", "/audit"],
    onSuccess: (d) => {
      toast.success(`Rejected ${plural(d.decided.length, "device")}. ${d.decided.length === 1 ? "Its agent stops" : "Their agents stop"} asking.`);
      if (d.skipped.length > 0) toast.info(`${plural(d.skipped.length, "device was", "devices were")} already decided.`);
      setRejecting(null);
      setSelected(new Set());
    },
  });

  if (items.length === 0) {
    return (
      <Card padded={false}>
        <EmptyState title="No devices waiting" icon={<Hourglass className="size-8" aria-hidden />}>
          A computer appears here as soon as it runs the install command of an{" "}
          <Link to="/devices/add?mode=approval" className="font-medium text-accent hover:underline">
            approval token
          </Link>
          . This page checks for new ones every few seconds.
        </EmptyState>
      </Card>
    );
  }

  const chosen = items.filter((r) => selected.has(r.id));
  const all = chosen.length === items.length;
  const toggle = (id: string, on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });

  return (
    <Card
      padded={false}
      title={chosen.length > 0 ? `${chosen.length.toLocaleString()} selected` : plural(items.length, "device")}
      actions={
        chosen.length > 0 && (
          <div className="flex items-center gap-2">
            <Button size="sm" variant="danger-ghost" onClick={() => setRejecting(chosen)}>
              <X className="size-3.5" aria-hidden />
              Reject selected
            </Button>
            <Button size="sm" variant="primary" onClick={() => setApproving(chosen)}>
              <Check className="size-3.5" aria-hidden />
              Approve selected…
            </Button>
          </div>
        )
      }
    >
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th className="w-10">
                <input
                  type="checkbox"
                  aria-label="Select all"
                  checked={all}
                  ref={(el) => {
                    if (el) el.indeterminate = chosen.length > 0 && !all;
                  }}
                  onChange={(e) => setSelected(e.target.checked ? new Set(items.map((r) => r.id)) : new Set())}
                />
              </th>
              <th>Device</th>
              <th className="hidden lg:table-cell">System</th>
              <th className="hidden xl:table-cell">From</th>
              <th className="hidden sm:table-cell">Asked</th>
              <th className="text-right">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id} className={cx(selected.has(r.id) && "bg-accent-soft/40")}>
                <td className="align-top">
                  <input type="checkbox" aria-label={`Select ${r.hostname}`} checked={selected.has(r.id)} onChange={(e) => toggle(r.id, e.target.checked)} />
                </td>
                <td className="align-top">
                  <DeviceCell r={r} />
                  <div className="mt-1 text-xs sm:hidden">
                    <AskedState r={r} />
                  </div>
                </td>
                <SystemCell r={r} />
                <FromCell r={r} />
                <td className="hidden align-top sm:table-cell" title={`First asked ${formatDateTime(r.createdAt)}, last ${formatDateTime(r.lastSeenAt)}`}>
                  <AskedState r={r} />
                </td>
                <td className="text-right align-top whitespace-nowrap">
                  <Button size="sm" aria-label={`Approve ${r.hostname}…`} onClick={() => setApproving([r])}>
                    Approve…
                  </Button>
                  <IconButton label={`Reject ${r.hostname}`} onClick={() => setRejecting([r])} className="ml-1 hover:text-danger">
                    <X className="size-4" aria-hidden />
                  </IconButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <ApproveDialog
        requests={approving}
        onClose={() => setApproving(null)}
        onDone={() => {
          setApproving(null);
          setSelected(new Set());
        }}
      />
      <ConfirmDialog
        open={rejecting !== null}
        onClose={() => {
          setRejecting(null);
          reject.reset();
        }}
        onConfirm={() => rejecting && reject.mutate(rejecting)}
        title={rejecting?.length === 1 ? `Reject ${rejecting[0]!.hostname}` : `Reject ${plural(rejecting?.length ?? 0, "device")}`}
        confirmLabel="Reject"
        tone="danger"
        loading={reject.isPending}
        error={reject.error}
      >
        <p>
          {rejecting?.length === 1 ? "Its agent stops asking and stays" : "Their agents stop asking and stay"} idle until uninstalled. To add{" "}
          {rejecting?.length === 1 ? "it" : "one"} later after all, uninstall the agent and install it again.
        </p>
      </ConfirmDialog>
    </Card>
  );
}

function ApproveDialog({ requests, onClose, onDone }: { requests: EnrollmentRequest[] | null; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const open = requests !== null;
  const sites = useSites(null);
  const [siteId, setSiteId] = useState("");
  const [groupId, setGroupId] = useState("");
  const groups = useList<DeviceGroup>(open && siteId ? `/sites/${siteId}/device-groups` : null);
  const approve = useApiMutation((input: ApproveInput) => api.post<EnrollmentDecision>("/enrollment-requests/approve", input), {
    invalidate: ["/enrollment-requests", "/approval-tokens", "/devices", "/sites", "/organizations", "/audit"],
    onSuccess: (d) => {
      const site = sites.items.find((s) => s.id === siteId);
      const where = site ? ` into ${site.organizationName} / ${site.name}` : "";
      if (d.decided.length > 0) toast.success(`Approved ${plural(d.decided.length, "device")}${where}. ${d.decided.length === 1 ? "It connects" : "They connect"} within seconds.`);
      if (d.skipped.length > 0) toast.info(`${plural(d.skipped.length, "device was", "devices were")} already decided by someone else.`);
      onDone();
    },
  });

  useEffect(() => {
    if (open) {
      setGroupId("");
      approve.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const byOrg = useMemo(() => {
    const m = new Map<string, Site[]>();
    for (const s of sites.items) m.set(s.organizationName, [...(m.get(s.organizationName) ?? []), s]);
    return [...m.entries()];
  }, [sites.items]);

  const rs = requests ?? [];
  const shown = rs.slice(0, 6);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!siteId || approve.isPending) return;
    approve.mutate({ ids: rs.map((r) => r.id), siteId, deviceGroupId: groupId || null });
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={rs.length === 1 ? `Approve ${rs[0]!.hostname}` : `Approve ${plural(rs.length, "device")}`}
      description="Choose the site the device joins. It takes its computer's name, which you can change later."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="approve-form" variant="primary" loading={approve.isPending} disabled={!siteId}>
            {rs.length === 1 ? "Approve" : `Approve ${plural(rs.length, "device")}`}
          </Button>
        </>
      }
    >
      <form id="approve-form" onSubmit={submit} className="flex flex-col gap-3.5">
        <ul className="divide-y divide-line rounded-md border border-line text-sm" aria-label="Devices to approve">
          {shown.map((r) => (
            <li key={r.id} className="flex items-center justify-between gap-3 px-3 py-1.5">
              <span className="min-w-0 truncate font-medium">{r.hostname}</span>
              <Mono className="shrink-0 text-xs text-muted">{r.code}</Mono>
            </li>
          ))}
          {rs.length > shown.length && <li className="px-3 py-1.5 text-muted">and {plural(rs.length - shown.length, "more device")}</li>}
        </ul>
        {sites.isPending ? (
          <Spinner />
        ) : sites.isError ? (
          <ErrorState compact error={sites.error} onRetry={() => void sites.refetch()} />
        ) : sites.items.length === 0 ? (
          <EmptyState title="No sites yet" compact>
            A device joins a site.{" "}
            <Link to="/organizations" className="font-medium text-accent hover:underline">
              Add a site to an organization
            </Link>{" "}
            first.
          </EmptyState>
        ) : (
          <>
            <SelectField
              label="Site"
              required
              value={siteId}
              error={fieldError(approve.error, "siteId")}
              onChange={(e) => {
                setSiteId(e.target.value);
                setGroupId("");
              }}
            >
              <option value="">Choose a site</option>
              {byOrg.map(([org, list]) => (
                <optgroup key={org} label={org}>
                  {list.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </optgroup>
              ))}
            </SelectField>
            <SelectField
              label="Device group"
              value={groupId}
              onChange={(e) => setGroupId(e.target.value)}
              disabled={!siteId || groups.isPending}
              error={fieldError(approve.error, "deviceGroupId")}
              hint="Optional."
            >
              <option value="">None</option>
              {groups.items.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </SelectField>
          </>
        )}
        <InlineError error={approve.error} fields={["siteId", "deviceGroupId"]} />
      </form>
    </Dialog>
  );
}

function RejectedTable({ items }: { items: EnrollmentRequest[] }) {
  if (items.length === 0) {
    return (
      <Card padded={false}>
        <EmptyState title="No rejected devices" compact>
          Devices you reject are listed here for 30 days.
        </EmptyState>
      </Card>
    );
  }
  return (
    <Card padded={false}>
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th>Device</th>
              <th className="hidden lg:table-cell">System</th>
              <th className="hidden xl:table-cell">From</th>
              <th>Rejected</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id}>
                <td className="align-top">
                  <DeviceCell r={r} />
                </td>
                <SystemCell r={r} />
                <FromCell r={r} />
                <td className="align-top whitespace-nowrap" title={formatDateTime(r.decidedAt)}>
                  {formatRelative(r.decidedAt)}
                  {r.decidedByName && <span className="block text-xs text-muted">by {r.decidedByName}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}
