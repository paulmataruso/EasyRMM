// An alert's card: everything recorded about one alert, opened from wherever alerts are listed (alertLink.tsx). Each
// section shows only what the server records; nothing here is inferred.
import { useEffect, useRef, type ReactNode } from "react";
import { Info } from "lucide-react";
import { Link, useSearchParams } from "react-router";
import { ApiError } from "../../api/client";
import { useApi, useList } from "../../api/hooks";
import type { AlertEntry, AlertMetrics, AlertPolicy, Device, DiskHealthDetail } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Dialog } from "../../components/Dialog";
import { TimeChart, type TimeSeries } from "../../components/TimeChart";
import { Badge, Button, ErrorState, KeyValueList, Spinner } from "../../components/ui";
import { formatDate, formatDateTime, formatDuration, plural } from "../../lib/format";
import { DiskFacts, DiskState } from "../devices/DeviceDisks";
import { AlertActions, useAlertAction } from "./AlertActions";
import { RepairSteps } from "../devices/remoteRepair";
import { alertGuide } from "./alertGuide";
import { linkClass, muted, RawDetails, Section, When } from "./cardParts";
import { ALERT_PARAM, AlertLink, useCloseAlertCard } from "./alertLink";
import { CHECK_NAMES, conditionText, formatMinutes, KIND_NAMES, policyScope, resolutionText, SeverityBadge, valueText } from "./alertText";

/** The card for ?alert=<id>, over whatever page is showing. The layout mounts it once a card is first opened, so that
 * closing it hands focus back to the link that opened it. */
export function AlertCard() {
  const [params] = useSearchParams();
  const id = params.get(ALERT_PARAM) ?? "";
  const close = useCloseAlertCard();
  const alert = useApi<AlertEntry>(id ? `/alerts/${encodeURIComponent(id)}` : null, undefined, { refetchInterval: 30_000 });
  const actions = useAlertAction();
  const a = alert.data;
  // Another alert opened from the card's history replaces the link that opened it, so the card's title, which stays,
  // takes the focus. Opening the card from a page leaves focus to the dialog.
  const title = useRef<HTMLSpanElement>(null);
  const shown = useRef("");
  useEffect(() => {
    if (shown.current !== "" && id !== "" && shown.current !== id) title.current?.focus();
    shown.current = id;
  }, [id]);
  return (
    <Dialog
      open={id !== ""}
      onClose={close}
      size="lg"
      title={
        <span ref={title} tabIndex={-1} className="rounded-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
          {a?.name ?? "Alert"}
        </span>
      }
      description={a ? `${KIND_NAMES[a.kind] ?? a.kind} on ${a.deviceName}` : undefined}
      footer={
        <>
          {a && <AlertActions alert={a} actions={actions} />}
          <Button onClick={close}>Close</Button>
        </>
      }
    >
      {alert.isPending ? (
        <Spinner />
      ) : alert.isError ? (
        <ErrorState error={alert.error} onRetry={() => void alert.refetch()} compact />
      ) : (
        <AlertDetail alert={alert.data} />
      )}
    </Dialog>
  );
}

/** The repairs tried on the device since a remote access alert opened (ADR-0069). */
function RepairsSection({ alert: a }: { alert: AlertEntry }) {
  // A Repair failed alert is about one agent: only its repairs show.
  const repairs = (a.repairs ?? []).filter((r) => a.kind !== "repair_failed" || r.target === a.subject);
  return (
    <Section title="Repairs tried">
      {repairs.length === 0 ? (
        <p className="text-sm text-muted">None since the alert opened.</p>
      ) : (
        <ul className="space-y-3 text-sm">
          {repairs.map((r) => (
            <li key={r.startedAt}>
              <span className="font-medium">
                {r.trigger === "automatic" ? "Automatic" : "By hand"} · {r.target} ·{" "}
                {r.state === "running" ? "running" : r.state === "succeeded" ? "it came back" : "it did not come back"}
              </span>
              <span className="text-muted">
                {" "}
                · <When at={r.startedAt} />
              </span>
              <RepairSteps repair={{ ...r, id: r.startedAt, carriedBy: r.target, steps: r.steps.map((s, i) => ({ ...s, id: `${i}` })) }} />
              {r.state === "failed" && r.error && <span className="mt-1 block break-words text-danger">{r.error}</span>}
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

const MEASURED = new Set<AlertEntry["kind"]>(["cpu", "memory", "disk"]);

/** Every section of an alert's card. */
function AlertDetail({ alert: a }: { alert: AlertEntry }) {
  const device = useApi<Device>(`/devices/${a.deviceId}`, undefined, { refetchInterval: 30_000 });
  return (
    <div className="flex flex-col gap-6">
      <Summary alert={a} device={device.data} />
      <WhyItOpened alert={a} device={device.data} />
      {MEASURED.has(a.kind) && <Measurements alert={a} />}
      {a.kind === "disk_health" && <DiskSection alert={a} />}
      {(a.kind === "remote_down" || a.kind === "agent_silent" || a.kind === "repair_failed") && <RepairsSection alert={a} />}
      <Times alert={a} />
      <Guide alert={a} />
      <History alert={a} />
      <RawDetails value={a} />
    </div>
  );
}

const STATUS: Record<AlertEntry["status"], { label: string; tone: "info" | "neutral" | "ok" }> = {
  open: { label: "Open", tone: "info" },
  acknowledged: { label: "Acknowledged", tone: "neutral" },
  resolved: { label: "Resolved", tone: "ok" },
};

function Summary({ alert: a, device }: { alert: AlertEntry; device?: Device }) {
  const status = STATUS[a.status] ?? { label: a.status, tone: "neutral" as const };
  return (
    <Section title="Summary">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={a.severity} />
        <Badge tone={status.tone}>{status.label}</Badge>
        <span className="text-sm text-muted">
          {KIND_NAMES[a.kind] ?? a.kind}
          {a.checkName && <> · {CHECK_NAMES[a.checkName] ?? a.checkName}</>}
        </span>
      </div>
      <KeyValueList
        narrow
        items={[
          [
            "Device",
            <span key="d">
              <Link to={`/devices/${a.deviceId}`} className={linkClass}>
                {a.deviceName}
              </Link>
              {device && <span className="text-muted">{device.online ? " · online now" : " · offline now"}</span>}
            </span>,
          ],
          [
            "Site",
            <Link key="s" to={`/sites/${a.siteId}`} className={linkClass}>
              {a.siteName}
            </Link>,
          ],
          [
            "Organization",
            <Link key="o" to={`/organizations/${a.organizationId}`} className={linkClass}>
              {a.organizationName}
            </Link>,
          ],
          ...(a.kind === "disk_health" ? ([["Disk", a.subjectLabel || muted("Not named")]] as [string, ReactNode][]) : []),
          ...(a.detail ? ([["What holds", a.detail]] as [string, ReactNode][]) : []),
        ]}
      />
    </Section>
  );
}

function WhyItOpened({ alert: a, device }: { alert: AlertEntry; device?: Device }) {
  const { can } = useAuth();
  const visible = a.policyId !== null && can("monitoring.view");
  const policy = useApi<AlertPolicy>(visible ? `/alert-policies/${a.policyId}` : null, undefined, { staleTime: 60_000 });
  const p = policy.data;
  const now = p ? conditionText(p) : null;
  const policyCell: ReactNode =
    a.policyId === null ? (
      muted("Deleted")
    ) : !visible ? (
      muted("Your role cannot see alert policies")
    ) : p ? (
      // The console has no page for one policy: the Policies tab lists them all.
      <span>
        <span className="font-medium break-words">{p.name}</span>
        <span className="text-muted">
          {" "}
          · {policyScope(p)}
          {!p.enabled && " · turned off"}
        </span>
      </span>
    ) : policy.isError ? (
      muted(policy.error instanceof ApiError && policy.error.status === 404 ? "No longer available" : "Could not be loaded")
    ) : (
      muted("Loading…")
    );
  const items: [string, ReactNode][] = [
    ["Condition", conditionText(a)],
    ["Policy", policyCell],
  ];
  // The alert keeps the condition it opened under; a policy changed since says so.
  if (now !== null && now !== conditionText(a)) items.push(["Policy now", now]);
  if (p?.description) items.push(["Description", <span key="desc" className="whitespace-pre-wrap">{p.description}</span>]);
  items.push(
    [
      "When it opened",
      <span key="opened">
        <span className="font-medium tabular-nums">{valueText({ kind: a.kind, checkName: a.checkName, lastValue: a.value })}</span>
        {", "}
        <When at={a.openedAt} />
      </span>,
    ],
    [a.status === "resolved" ? "Last value" : "Latest value", <span key="latest" className="font-medium tabular-nums">{valueText(a)}</span>],
  );
  if (a.kind === "offline" && device) items.push(["Last seen", device.lastSeenAt ? <When key="seen" at={device.lastSeenAt} /> : muted("Never")]);
  return (
    <Section title="Why it opened">
      <KeyValueList narrow items={items} />
    </Section>
  );
}

const METRIC_LABELS: Record<AlertMetrics["metric"], string> = { cpu: "Processor use", memory: "Memory use", disk: "Fullest disk use" };
const percent = (v: number) => `${Math.round(v)}%`;

function Measurements({ alert: a }: { alert: AlertEntry }) {
  const resolved = a.status === "resolved";
  const m = useApi<AlertMetrics>(`/alerts/${a.id}/metrics`, undefined, { refetchInterval: resolved ? false : 60_000 });
  const label = METRIC_LABELS[a.kind as AlertMetrics["metric"]] ?? KIND_NAMES[a.kind];
  const series: TimeSeries<AlertMetrics["samples"][number]>[] = [{ key: "value", label, color: "var(--series-1)", value: (p) => p.value }];
  return (
    <Section title="Measurements">
      {m.isPending ? (
        <Spinner />
      ) : m.isError ? (
        <ErrorState error={m.error} onRetry={() => void m.refetch()} compact />
      ) : (
        <>
          <TimeChart
            data={m.data.samples}
            series={series}
            from={m.data.from}
            to={m.data.to}
            stepSeconds={m.data.bucketSeconds}
            label={`${label} around this alert${m.data.threshold !== null ? `, threshold ${m.data.threshold}%` : ""}`}
            format={percent}
            height={180}
            reference={m.data.threshold !== null ? { value: m.data.threshold, label: `Threshold ${m.data.threshold}%` } : undefined}
            band={{ from: a.openedAt, to: a.resolvedAt, label: resolved ? "While the alert was open" : "Alert open" }}
          />
          {m.data.trimmed && (
            <p className="flex items-start gap-1.5 text-xs">
              <Info className="mt-px size-3.5 shrink-0 text-muted" aria-hidden />
              <span>
                Earlier measurements are no longer kept, so the chart starts at <time dateTime={m.data.from}>{formatDateTime(m.data.from)}</time>, after
                the alert&apos;s own start.
              </span>
            </p>
          )}
          <p className="text-xs text-muted">
            From {formatMinutes(a.minutes)} before the alert opened until {resolved ? "it resolved" : "now"}, with some time either side
            {m.data.trimmed ? ", as far as measurements are kept" : ""}.{" "}
            {m.data.bucketSeconds >= 120 ? `Each point is the average over ${formatDuration(m.data.bucketSeconds)}. ` : ""}
            {m.data.samples.length > 0 && "Gaps are periods the device sent no measurements."}
          </p>
        </>
      )}
    </Section>
  );
}

function DiskSection({ alert: a }: { alert: AlertEntry }) {
  const disk = useApi<DiskHealthDetail>(a.subject ? `/devices/${a.deviceId}/disks/${encodeURIComponent(a.subject)}` : null, undefined, {
    refetchInterval: 60_000,
  });
  const gone = disk.error instanceof ApiError && disk.error.status === 404;
  const d = disk.data;
  return (
    <>
      <Section
        title="The disk"
        actions={
          <Link to={`/devices/${a.deviceId}?tab=hardware`} className="text-xs text-accent hover:underline">
            The device's disks
          </Link>
        }
      >
        {!a.subject ? (
          <p className="text-sm text-muted">This alert names no disk.</p>
        ) : disk.isPending ? (
          <Spinner />
        ) : gone ? (
          <p className="text-sm text-muted">The device's disk readings no longer list this disk, or your role cannot see them.</p>
        ) : disk.isError ? (
          <ErrorState error={disk.error} onRetry={() => void disk.refetch()} compact />
        ) : (
          d && (
            <>
              <DiskState disk={d} />
              <KeyValueList
                narrow
                items={[
                  ["Name", d.name],
                  ["Model", d.model || muted("Not reported")],
                  ["Facts as of", d.factsAt ? <When key="f" at={d.factsAt} /> : muted("Never read")],
                  ...(d.missingSince ? ([["Missing since", <When key="m" at={d.missingSince} />]] as [string, ReactNode][]) : []),
                ]}
              />
            </>
          )
        )}
      </Section>
      {d && <DiskFacts facts={d.facts} />}
    </>
  );
}

function Times({ alert: a }: { alert: AlertEntry }) {
  const end = a.resolvedAt ? Date.parse(a.resolvedAt) : Date.now();
  const open = formatDuration((end - Date.parse(a.openedAt)) / 1000);
  return (
    <Section title="Times">
      <KeyValueList
        narrow
        items={[
          ["Opened", <When key="o" at={a.openedAt} />],
          [a.resolvedAt ? "Open for" : "Open so far", open],
          [
            "Acknowledged",
            a.acknowledgedAt ? (
              <span key="a">
                <When at={a.acknowledgedAt} />
                {a.acknowledgedBy && <> by {a.acknowledgedBy}</>}
              </span>
            ) : (
              muted("Not acknowledged")
            ),
          ],
          [
            "Resolved",
            a.resolvedAt ? (
              <span key="r">
                <When at={a.resolvedAt} />
                <span className="block">{resolutionText(a)}</span>
              </span>
            ) : (
              muted("Not yet")
            ),
          ],
        ]}
      />
    </Section>
  );
}

function Guide({ alert: a }: { alert: AlertEntry }) {
  const g = alertGuide(a);
  return (
    <>
      <Section title="What it means">
        <p className="text-sm">{g.means}</p>
      </Section>
      <Section title="What to do next">
        <ol className="list-decimal space-y-1 pl-5 text-sm marker:text-muted">
          {g.next.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
        <p className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          <span className="text-muted">On the device's page:</span>
          {g.tabs.map((t) => (
            <Link key={t.tab} to={`/devices/${a.deviceId}${t.tab === "overview" ? "" : `?tab=${t.tab}`}`} className="text-accent hover:underline">
              {t.label}
            </Link>
          ))}
        </p>
      </Section>
    </>
  );
}

/** How many of a policy's alerts on the device the card lists. */
const HISTORY_LIMIT = 20;

function History({ alert: a }: { alert: AlertEntry }) {
  const list = useList<AlertEntry>(
    a.policyId ? "/alerts" : null,
    { status: "all", deviceId: a.deviceId, policyId: a.policyId ?? undefined, subject: a.subject || undefined, limit: HISTORY_LIMIT },
    { refetchInterval: 60_000 },
  );
  const where = a.kind === "disk_health" ? "this disk" : "this device";
  const all = (
    <Link to={`/alerts?deviceId=${a.deviceId}&status=all`} className="text-xs text-accent hover:underline">
      All of the device's alerts
    </Link>
  );
  if (!a.policyId) {
    return (
      <Section title="History" actions={all}>
        <p className="text-sm text-muted">Its policy was deleted, so its other alerts can no longer be told apart.</p>
      </Section>
    );
  }
  const oldest = list.items.at(-1);
  return (
    <Section title="History" actions={all}>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : list.items.length <= 1 ? (
        <p className="text-sm text-muted">
          The only alert this policy has raised on {where} among the alerts kept. Resolved alerts are kept for 90 days unless the server is set
          otherwise.
        </p>
      ) : (
        <>
          <p className="text-sm">
            {list.next ? `The latest ${list.items.length} times` : plural(list.items.length, "time")} this policy opened an alert on {where}
            {oldest && <>, since {formatDate(oldest.openedAt)}</>}, newest first.
          </p>
          <ol className="divide-y divide-line rounded-lg border border-line">
            {list.items.map((x) => (
              <HistoryItem key={x.id} alert={x} current={x.id === a.id} />
            ))}
          </ol>
        </>
      )}
    </Section>
  );
}

function HistoryItem({ alert: x, current }: { alert: AlertEntry; current: boolean }) {
  const end = x.resolvedAt ? Date.parse(x.resolvedAt) : Date.now();
  const status = x.status === "resolved" ? resolutionText(x) : STATUS[x.status]?.label ?? x.status;
  const opened = `Opened ${formatDateTime(x.openedAt)}`;
  return (
    <li className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 px-3 py-2 text-sm">
      {current ? (
        <span className="font-medium" aria-current="true">
          {opened} <span className="font-normal text-muted">(this alert)</span>
        </span>
      ) : (
        <AlertLink id={x.id} className={linkClass}>
          {opened}
        </AlertLink>
      )}
      <span className="text-xs text-muted">
        <span className="tabular-nums">{valueText(x)}</span> · {x.resolvedAt ? "open for" : "open so far"} {formatDuration((end - Date.parse(x.openedAt)) / 1000)} ·{" "}
        {status}
      </span>
    </li>
  );
}
