import type { ReactNode } from "react";
import type { Device, DevicePatching, PatchPolicy, PatchRestartSchedule, PatchWindowsUpdate } from "../../api/types";
import { Alert, Badge, Card, KeyValueList, TableWrap, type Tone } from "../../components/ui";
import { formatDateTime, plural } from "../../lib/format";
import { categoryLabel, EasyPatchLink, useEasyPatchConsole } from "../patching/patchText";

// A device's effective EasyPatch policy (one-product plan, C1): every value EasyPatch applies to it, and the layer
// that set it. Editing policies comes with the policy pages (C4); where EasyPatch has a console of its own, it links
// there.

const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** The layer a value comes from, keyed by its name: EasyPatch writes PascalCase keys ("MaintenanceWindow"). */
function sourceOf<T>(map: Record<string, T> | null | undefined, field: string): T | undefined {
  if (!map) return undefined;
  return map[field.charAt(0).toUpperCase() + field.slice(1)] ?? map[field.charAt(0).toLowerCase() + field.slice(1)];
}

const LAYERS: Record<string, { label: string; tone: Tone; title: string }> = {
  Global: { label: "Default", tone: "neutral", title: "EasyPatch's default policy, for every organization" },
  Organization: { label: "Organization", tone: "info", title: "The organization's policy" },
  Site: { label: "Site", tone: "accent", title: "The site's policy" },
  Endpoint: { label: "This device", tone: "warn", title: "This device's own policy" },
};

function Layer({ policy, field }: { policy: PatchPolicy; field: string }) {
  const layer = sourceOf(policy.sources, field);
  if (!layer) return null;
  if (layer === "Tag") {
    const tag = sourceOf(policy.sourceTags, field);
    return (
      <Badge tone="ok" title="A tag's policy">
        {tag ? `Tag: ${tag}` : "Tag"}
      </Badge>
    );
  }
  const l = LAYERS[layer] ?? { label: layer, tone: "neutral" as Tone, title: "" };
  return (
    <Badge tone={l.tone} title={l.title}>
      {l.label}
    </Badge>
  );
}

/** "3 hours", "1 hour 30 minutes", "45 minutes". */
export function minutesText(m: number): string {
  if (m >= 1440 && m % 1440 === 0) return plural(m / 1440, "day");
  const h = Math.floor(m / 60);
  const rest = m % 60;
  if (h === 0) return plural(rest, "minute");
  return rest === 0 ? plural(h, "hour") : `${plural(h, "hour")} ${plural(rest, "minute")}`;
}

function daysText(days: number[] | null | undefined): string {
  if (!days || days.length === 0) return "No days";
  if (days.length === 7) return "Every day";
  return [...days]
    .sort((a, b) => a - b)
    .map((d) => DAYS[d] ?? String(d))
    .join(", ");
}

/** "Saturday at 22:00 for 4 hours", or "None". */
export function windowText(p: PatchPolicy): string {
  if (!p.maintenanceStart || !p.maintenanceDays || p.maintenanceDays.length === 0) return "None";
  const length = p.maintenanceDurationMinutes ? ` for ${minutesText(p.maintenanceDurationMinutes)}` : "";
  return `${daysText(p.maintenanceDays)} at ${p.maintenanceStart.slice(0, 5)}${length}`;
}

/** "Sunday at 03:00, only when a restart is pending, ask users with a 4-hour deadline", or "None". */
export function restartScheduleText(s: PatchRestartSchedule | null | undefined): string {
  if (!s) return "None";
  if (!s.enabled) return "Off";
  const mode =
    s.mode === "PromptWithDeadline"
      ? `ask users, restart after ${minutesText(s.deadlineMinutes)} at the latest`
      : s.mode === "Countdown"
        ? `${plural(s.countdownMinutes, "minute")} countdown`
        : s.mode === "PromptNoDeadline"
          ? "ask users, no deadline"
          : "restart at once";
  return `${daysText(s.days)} at ${s.time.slice(0, 5)}, ${s.condition === "OnlyIfPending" ? "only when a restart is pending" : "always"}, ${mode}`;
}

const AUTO_UPDATE_MODES: Record<string, string> = {
  Disabled: "Automatic Updates off",
  NotifyDownload: "Notify before downloading and installing",
  AutoDownloadNotifyInstall: "Download automatically, notify to install",
  AutoDownloadScheduleInstall: "Download automatically, install on a schedule",
};
const INSTALL_DAYS = ["every day", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const hour = (h: number) => `${String(h).padStart(2, "0")}:00`;

const WU_GROUPS: { key: keyof PatchWindowsUpdate; group: string; label: string }[] = [
  { key: "automaticUpdates", group: "AutomaticUpdates", label: "Automatic Updates" },
  { key: "featureUpdates", group: "FeatureUpdates", label: "Feature updates" },
  { key: "qualityUpdates", group: "QualityUpdates", label: "Quality updates and pausing" },
  { key: "restartBehavior", group: "RestartBehavior", label: "Restart behaviour" },
];

function windowsUpdateText(w: PatchWindowsUpdate, key: keyof PatchWindowsUpdate): string {
  switch (key) {
    case "automaticUpdates": {
      const v = w.automaticUpdates;
      if (!v) return "Not managed";
      const mode = AUTO_UPDATE_MODES[v.mode] ?? v.mode;
      return v.mode === "AutoDownloadScheduleInstall" ? `${mode} (${INSTALL_DAYS[v.scheduledInstallDay] ?? "?"} at ${hour(v.scheduledInstallHour)})` : mode;
    }
    case "featureUpdates": {
      const v = w.featureUpdates;
      if (!v) return "Not managed";
      const parts = [v.deferDays !== null ? `Defer ${plural(v.deferDays, "day")}` : "No deferral"];
      if (v.targetProductVersion && v.targetReleaseVersion) parts.push(`stay on ${v.targetProductVersion} ${v.targetReleaseVersion}`);
      return parts.join(", ");
    }
    case "qualityUpdates": {
      const v = w.qualityUpdates;
      if (!v) return "Not managed";
      return [v.deferDays !== null ? `Defer ${plural(v.deferDays, "day")}` : "No deferral", v.disablePause ? "users cannot pause" : "users may pause"].join(", ");
    }
    case "restartBehavior": {
      const v = w.restartBehavior;
      if (!v) return "Not managed";
      const parts = [v.noAutoRestartWithSignedInUsers ? "No automatic restart while someone is signed in" : "Windows may restart while someone is signed in"];
      if (v.activeHoursStart !== null && v.activeHoursEnd !== null) parts.push(`active hours ${hour(v.activeHoursStart)}–${hour(v.activeHoursEnd)}`);
      return parts.join(", ");
    }
  }
}

const APPLIED: Record<string, { label: string; tone: Tone }> = {
  Applied: { label: "Applied", tone: "ok" },
  Conflict: { label: "Conflict", tone: "warn" },
  Error: { label: "Error", tone: "danger" },
  NotManaged: { label: "Not managed", tone: "neutral" },
};

function delayText(days: number): string {
  return days > 0 ? `${plural(days, "day")} after release` : "None";
}

function everyText(minutes: number): string {
  return `Every ${minutesText(minutes)}`;
}

/** The device's whole effective policy, value by value, each with the layer that set it. */
export function PolicyView({ patching: d, device }: { patching: DevicePatching; device: Device }) {
  const hasConsole = useEasyPatchConsole();
  const p = d.policy;
  if (!p) return null;
  const e = d.endpoint;
  const windows = device.platform === "windows";
  const row = (label: string, field: string, value: ReactNode): [ReactNode, ReactNode] => [
    label,
    <span key={field} className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <span className="min-w-0">{value}</span>
      <Layer policy={p} field={field} />
    </span>,
  ];
  const excluded = p.excludedKbs ?? [];
  const apps = p.applicationUpdates;
  const report = e?.windowsUpdatePolicy;
  const wu = p.windowsUpdate;
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted">
        {e?.hasOwnPolicy
          ? "This device has its own policy, which overrides its tags, site, organization and the default for the values it sets."
          : "This device follows its tags, site, organization and the default policy: the most specific one that sets a value wins, and excluded KBs add up."}
        {hasConsole && (
          <>
            {" "}
            <EasyPatchLink to={{ device: d.deviceId, tab: "policy" }}>Change in EasyPatch</EasyPatchLink>
          </>
        )}
      </p>
      <div className="grid grid-cols-1 items-start gap-4 2xl:grid-cols-2">
        <Card title="Installing">
          <KeyValueList
            items={[
              row(
                "Automatic installs",
                "autoInstallEnabled",
                p.autoInstallEnabled ? "On, inside the maintenance window. Installing never restarts the device." : "Off: updates install only when someone starts an install",
              ),
              row("Maintenance window", "maintenanceWindow", p.maintenanceStart ? `${windowText(p)} (${p.timeZone})` : "None"),
              ...(windows
                ? [row("Download ahead", "preDownloadHours", p.preDownloadHours > 0 ? `Up to ${plural(p.preDownloadHours, "hour")} before the window opens` : "Off")]
                : []),
              row("Categories", "allowedCategories", p.allowedCategories && p.allowedCategories.length > 0 ? p.allowedCategories.map(categoryLabel).join(", ") : "None"),
              row("Optional updates", "includeOptional", p.includeOptional ? "Installed" : "Left out"),
              row("License agreements", "acceptEulas", p.acceptEulas ? "Accepted" : "Not accepted: updates that need one are left out"),
              row(
                "Excluded KBs",
                "excludedKbs",
                excluded.length > 0 ? <span className="font-mono text-xs break-all">{excluded.join(", ")}</span> : "None",
              ),
              row("Delay for security updates", "securityInstallDelayDays", delayText(p.securityInstallDelayDays)),
              row("Delay for other updates", "installDelayDays", delayText(p.installDelayDays)),
              row("Exploited vulnerabilities", "knownExploitedSkipsDelay", p.knownExploitedSkipsDelay ? "Installed without the delay" : "Wait for the delay"),
              ...(windows
                ? [
                    row(
                      "Application updates",
                      "applicationUpdates",
                      !apps || !apps.enabled
                        ? "Off"
                        : (apps.approvedApps ?? []).length === 0
                          ? "On, but no application is approved"
                          : `winget, for ${(apps.approvedApps ?? []).join(", ")}`,
                    ),
                  ]
                : []),
            ]}
          />
        </Card>
        <div className="flex flex-col gap-4">
          <Card title="Restarts and users">
            <KeyValueList
              items={[
                row("Restart schedule", "restartSchedule", p.restartSchedule ? `${restartScheduleText(p.restartSchedule)} (${p.timeZone})` : "None"),
                ...(windows
                  ? [
                      row("EasyPatch icon", "trayIconEnabled", p.trayIconEnabled ? "Shown" : "Hidden, except for a message or a restart request"),
                      row("Install notifications", "installNotificationsEnabled", p.installNotificationsEnabled ? "On" : "Off"),
                    ]
                  : []),
                row("Agent updates", "agentAutoUpdateEnabled", p.agentAutoUpdateEnabled ? "Automatic" : "Manual"),
              ]}
            />
          </Card>
          <Card title="Agent schedule">
            <KeyValueList
              items={[
                row("Check-ins", "checkInIntervalSeconds", `Every ${plural(p.checkInIntervalSeconds, "second")}, ${p.jitterPercent}% jitter`),
                row("Scans", "scanIntervalMinutes", everyText(p.scanIntervalMinutes)),
                row("Inventory", "inventoryIntervalMinutes", everyText(p.inventoryIntervalMinutes)),
                row("Scan out of date after", "scanStaleAfterHours", plural(p.scanStaleAfterHours, "hour")),
                row("Installs at once, per site", "maxConcurrentInstallsPerSite", p.maxConcurrentInstallsPerSite.toLocaleString()),
              ]}
            />
          </Card>
        </div>
      </div>
      {windows && (
        <Card title="Windows Update settings" padded={false}>
          {report?.mdmUpdatePoliciesPresent && (
            <div className="px-4 pt-4">
              <Alert tone="info">Update policies from MDM, such as Intune, are on this device. Windows may apply those instead of these.</Alert>
            </div>
          )}
          <TableWrap className="rounded-none border-0">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Setting</th>
                  <th className="hidden md:table-cell">On the device</th>
                </tr>
              </thead>
              <tbody>
                {WU_GROUPS.map((g) => {
                  const status = report?.groups?.find((x) => x.group === g.group);
                  const a = status ? (APPLIED[status.state] ?? { label: status.state, tone: "neutral" as Tone }) : null;
                  return (
                    <tr key={g.key}>
                      <td className="align-top font-medium">{g.label}</td>
                      <td className="align-top">
                        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                          {wu ? windowsUpdateText(wu, g.key) : "Not managed"}
                          <Layer policy={p} field={`WindowsUpdate.${g.group}`} />
                        </span>
                      </td>
                      <td className="hidden align-top md:table-cell">
                        {a ? (
                          <>
                            <Badge tone={a.tone}>{a.label}</Badge>
                            {status?.message && <span className="mt-1 block max-w-xs text-xs text-muted">{status.message}</span>}
                            {status?.appliedAt && <span className="mt-1 block text-xs text-subtle">{formatDateTime(status.appliedAt)}</span>}
                          </>
                        ) : (
                          <span className="text-muted">Not reported</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        </Card>
      )}
    </div>
  );
}
