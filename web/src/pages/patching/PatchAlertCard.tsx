// A patching alert's card, like an EasyRMM alert's (alerts/AlertDetail.tsx): everything the engine records about one
// alert. The engine has no endpoint for one alert, so the card is built from its row in Patching → Alerts, as the list
// last loaded it, and shows only what that row holds.
import { useId, type ReactNode } from "react";
import { Link } from "react-router";
import type { PatchAlert, PatchAlertRuleKind } from "../../api/types";
import { CodeBlock } from "../../components/Copy";
import { Dialog } from "../../components/Dialog";
import { Badge, Button, KeyValueList } from "../../components/ui";
import { formatDateTime, formatDuration, formatRelative } from "../../lib/format";
import { acknowledgedBy, PatchSeverityBadge, RULE_KINDS } from "./patchAlertText";

/** What to check for each type of rule, from docs/operations/patching.md. */
const NEXT: Record<PatchAlertRuleKind, string[]> = {
  EndpointOffline: [
    "Check that the device is turned on and connected to the network.",
    "Check that its EasyPatch agent is installed and running: a device's Patches tab shows the agent, its status and its version.",
    "The engine resolves the alert itself once the agent checks in again. An offline device raises no other patching alert.",
  ],
  InstallFailed: [
    "On the device's Patches tab, its update history and jobs show which update failed and why.",
    "Install it again with Install updates…, or, if it keeps failing, hold it from its page under Patching → Updates.",
    "The alert resolves once no failed update is left.",
  ],
  SecurityUpdateMissing: [
    "On the device's Patches tab, install the missing updates with Install updates….",
    "If scheduled installs should have covered it, check the device's patch policy (Patches tab → Policy) and whether the update is on hold.",
    "The engine resolves the alert itself once the update is no longer missing.",
  ],
  ScanStale: [
    "Check that the device is turned on and that its EasyPatch agent checks in: the device's Patches tab shows its status.",
    "How often a device scans, and when a scan counts as out of date, are in its patch policy (Patches tab → Policy).",
    "The alert clears after a successful scan.",
  ],
  RestartPending: [
    "Restart the device with Restart… on its Patches tab, at a time that suits its users. The tab lists what is waiting for the restart.",
    "Updates that need a restart finish installing at the next restart; the alert then resolves.",
  ],
  OsUnsupported: [
    "Plan an upgrade to a supported version of the operating system: once support ends, it gets no security updates.",
    "The end-of-support dates are under Settings → Patching → OS lifecycle.",
  ],
  KnownExploitedMissing: [
    "Install the update first: on the device's Patches tab, updates that fix an exploited vulnerability are marked Exploited in the wild.",
    "If the update is on hold, installing it by hand, on its page or on the device, still installs it.",
    "The engine resolves the alert itself once the update is no longer missing.",
  ],
  UpdateHeld: [
    "Patching → Updates shows each held update with the reason it is held.",
    "Release the hold once the update is safe to install: until then scheduled installs leave it out.",
    "The engine also holds an update itself when it fails on too many of the devices it was tried on; such holds say so.",
  ],
};

const STATE: Record<PatchAlert["status"], { label: string; tone: "accent" | "neutral" | "ok" }> = {
  Open: { label: "Open", tone: "accent" },
  Acknowledged: { label: "Acknowledged", tone: "neutral" },
  Resolved: { label: "Resolved", tone: "ok" },
};

const linkClass = "font-medium break-words text-accent hover:underline";
const muted = (text: string) => <span className="text-muted">{text}</span>;

function When({ at }: { at: string }) {
  return (
    <>
      <time dateTime={at}>{formatDateTime(at)}</time> <span className="text-muted">({formatRelative(at)})</span>
    </>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="flex min-w-0 flex-col gap-2">
      <h3 id={id} className="text-sm font-semibold">
        {title}
      </h3>
      {children}
    </section>
  );
}

/** Where the alert is: its device, an endpoint with no EasyRMM device, or the whole organization. */
function patchAlertWhere(a: PatchAlert): string {
  return a.deviceId ? (a.deviceName ?? a.hostname ?? "a device") : a.hostname ? a.hostname : `${a.organizationName}, the whole organization`;
}

/** The card for one patching alert; alert is the row as last loaded, kept while the card closes. */
export function PatchAlertCard({ alert: a, open, onClose, onAcknowledge, busy }: {
  alert: PatchAlert | null;
  open: boolean;
  onClose: () => void;
  onAcknowledge: () => void;
  busy: boolean;
}) {
  const kind = a ? RULE_KINDS[a.ruleType] : undefined;
  return (
    <Dialog
      open={open && a !== null}
      onClose={onClose}
      size="lg"
      title={a?.title ?? "Patching alert"}
      description={a ? `${kind?.label ?? a.ruleType} · ${patchAlertWhere(a)}` : undefined}
      footer={
        <>
          {a?.canAcknowledge && (
            <Button variant="primary" onClick={onAcknowledge} loading={busy} aria-label={`Acknowledge ${a.title}`}>
              Acknowledge
            </Button>
          )}
          <Button onClick={onClose}>Close</Button>
        </>
      }
    >
      {a && <Details alert={a} />}
    </Dialog>
  );
}

function Details({ alert: a }: { alert: PatchAlert }) {
  const kind = RULE_KINDS[a.ruleType];
  const state = STATE[a.status] ?? { label: a.status, tone: "neutral" as const };
  const end = a.resolvedAt ? Date.parse(a.resolvedAt) : Date.now();
  const where: [string, ReactNode][] = a.deviceId
    ? [
        [
          "Device",
          <Link key="d" to={`/devices/${a.deviceId}?tab=patches`} className={linkClass}>
            {a.deviceName ?? a.hostname ?? a.deviceId}
          </Link>,
        ],
      ]
    : a.hostname
      ? [["Endpoint", <span key="h">{a.hostname} {muted("· no EasyRMM device")}</span>]]
      : [["Covers", "The whole organization"]];
  const next = NEXT[a.ruleType] ?? ["Check the alert's details, and the device's Patches tab where it has one."];
  return (
    <div className="flex flex-col gap-6">
      <Section title="Summary">
        <div className="flex flex-wrap items-center gap-2">
          <PatchSeverityBadge severity={a.severity} />
          <Badge tone={state.tone}>{state.label}</Badge>
          <span className="text-sm text-muted">Patching alert · {kind?.label ?? a.ruleType}</span>
        </div>
        <KeyValueList
          narrow
          items={[
            ...where,
            [
              "Organization",
              <Link key="o" to={`/organizations/${a.organizationId}`} className={linkClass}>
                {a.organizationName}
              </Link>,
            ],
            ["Rule", a.ruleId === null ? muted("Deleted") : (a.ruleName ?? muted("Not named"))],
            ...(a.details ? ([["Details", <span key="x" className="whitespace-pre-line">{a.details}</span>]] as [string, ReactNode][]) : []),
          ]}
        />
      </Section>
      <Section title="Times">
        <KeyValueList
          narrow
          items={[
            ["Opened", <When key="o" at={a.openedAt} />],
            [a.resolvedAt ? "Open for" : "Open so far", formatDuration((end - Date.parse(a.openedAt)) / 1000)],
            ["Cause last found", <When key="l" at={a.lastSeenAt} />],
            [
              "Acknowledged",
              a.acknowledgedAt || a.acknowledgedBy ? (
                <span key="a">
                  {a.acknowledgedAt ? <When at={a.acknowledgedAt} /> : muted("Time not recorded")}
                  {a.acknowledgedBy && <> by {acknowledgedBy(a.acknowledgedBy)}</>}
                </span>
              ) : (
                muted("Not acknowledged")
              ),
            ],
            ["Resolved", a.resolvedAt ? <When key="r" at={a.resolvedAt} /> : muted("Not yet: the engine resolves it once its cause is gone")],
          ]}
        />
      </Section>
      <Section title="What it means">
        <p className="text-sm">{kind?.about ?? "EasyRMM does not know this type of rule; its details say what it found."}</p>
      </Section>
      <Section title="What to do next">
        <ol className="list-decimal space-y-1 pl-5 text-sm marker:text-muted">
          {next.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
        <p className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          {a.deviceId ? (
            <Link to={`/devices/${a.deviceId}?tab=patches`} className="text-accent hover:underline">
              The device&apos;s Patches tab
            </Link>
          ) : (
            <Link to={`/patching?tab=alerts&organizationId=${a.organizationId}`} className="text-accent hover:underline">
              {a.organizationName}&apos;s patching alerts
            </Link>
          )}
          {a.ruleType === "UpdateHeld" && (
            <Link to={`/patching?tab=updates&organizationId=${a.organizationId}`} className="text-accent hover:underline">
              Patching → Updates
            </Link>
          )}
        </p>
      </Section>
      <details className="group rounded-lg border border-line">
        <summary className="cursor-pointer px-3 py-2 text-sm font-medium select-none">Raw details (JSON)</summary>
        <div className="border-t border-line p-3">
          <CodeBlock code={JSON.stringify(a, null, 2)} />
        </div>
      </details>
    </div>
  );
}
