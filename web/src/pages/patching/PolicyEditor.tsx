import { useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { RotateCcw, Save, ShieldOff, X } from "lucide-react";
import { api, ApiError, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type {
  PatchGroupSetting,
  PatchPolicyLayer,
  PatchPolicyView,
  PatchRestartSchedule,
  PatchWindowsUpdate,
  PolicyLevel,
  RestartMode,
} from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, cx, EmptyState, ErrorState, IconButton, InlineError, Input, Segmented, Select, Spinner } from "../../components/ui";
import { formatDateTime, plural } from "../../lib/format";
import {
  AUTO_UPDATE_MODES,
  DAYS,
  delayText,
  everyText,
  INSTALL_DAYS,
  minutesText,
  restartScheduleText,
  windowsUpdateText,
  windowText,
  WU_GROUPS,
} from "../devices/PatchPolicyView";
import { COUNTDOWNS, DEADLINES, EXPIRIES, RESTART_MODES } from "./PatchDialogs";
import { categoryLabel } from "./patchText";

// EasyPatch's policy at one level (one-product plan, C4): the default policy, an organization, a site, a tag or a
// device. Each level sets some values and inherits the rest from the levels above it; the most specific level that sets
// a value wins, and excluded KBs add up. The server resolves what a level inherits and where each value comes from, and
// checks every value again; the checks here only say so sooner.

type Layer = PatchPolicyLayer;
type WuKey = keyof PatchWindowsUpdate;
type Groups = NonNullable<Layer["windowsUpdate"]>;

export function policyPath(level: PolicyLevel, id?: string): string {
  return level === "default" ? "/patching/policies/default" : `/patching/policies/${level}/${id ?? ""}`;
}

/** The categories a policy installs from (EasyPatch's; application updates are set apart). */
export const POLICY_CATEGORIES = ["Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Feature", "Driver", "Other"];

const NUMBERS = {
  checkInIntervalSeconds: { label: "Check-ins", hint: "How often the agent asks for work.", min: 15, max: 3600, unit: "seconds", what: "a check-in interval (seconds)", text: (v: number) => `Every ${plural(v, "second")}` },
  jitterPercent: { label: "Spread", hint: "Each agent's schedule moves by up to this much, so they do not all call at once.", min: 0, max: 50, unit: "%", what: "a spread (percent)", text: (v: number) => `${v}%` },
  scanIntervalMinutes: { label: "Scans", hint: "How often the agent looks for missing updates.", min: 30, max: 10080, unit: "minutes", what: "a scan interval (minutes)", text: everyText },
  inventoryIntervalMinutes: { label: "Inventory", hint: "How often the agent reports installed updates and software.", min: 60, max: 10080, unit: "minutes", what: "an inventory interval (minutes)", text: everyText },
  scanStaleAfterHours: { label: "Scan out of date after", hint: "A device whose last scan is older counts as not scanned.", min: 1, max: 720, unit: "hours", what: "hours", text: (v: number) => plural(v, "hour") },
  maxConcurrentInstallsPerSite: { label: "Installs at once, per site", hint: "How many devices of one site install at the same time.", min: 1, max: 1000, unit: "devices", what: "a limit", text: (v: number) => v.toLocaleString() },
  preDownloadHours: { label: "Download ahead", hint: "Windows agents download updates up to this many hours before the window opens; 0 is off.", min: 0, max: 24, unit: "hours", what: "hours ahead", text: (v: number) => (v > 0 ? `Up to ${plural(v, "hour")} before the window opens` : "Off") },
  installDelayDays: { label: "Delay for other updates", hint: "Days after its release before an update installs automatically.", min: 0, max: 365, unit: "days", what: "a delay (days)", text: delayText },
  securityInstallDelayDays: { label: "Delay for security updates", hint: "The same, for security and critical updates.", min: 0, max: 90, unit: "days", what: "a delay (days)", text: delayText },
} as const;
type NumberKey = keyof typeof NUMBERS;

const BOOLS = {
  autoInstallEnabled: {
    label: "Automatic installs",
    hint: "Inside the maintenance window only. Installing never restarts a device; the restart schedule does.",
    on: "On",
    off: "Off",
    text: (v: boolean) => (v ? "On, inside the maintenance window" : "Off: updates install only when someone starts an install"),
  },
  includeOptional: { label: "Optional updates", on: "Install", off: "Leave out", text: (v: boolean) => (v ? "Installed" : "Left out") },
  acceptEulas: {
    label: "License agreements",
    on: "Accept",
    off: "Don't accept",
    text: (v: boolean) => (v ? "Accepted" : "Not accepted: updates that need one are left out"),
  },
  knownExploitedSkipsDelay: {
    label: "Exploited vulnerabilities",
    hint: "Updates that fix a vulnerability on CISA's list of known exploited ones.",
    on: "Skip the delay",
    off: "Wait",
    text: (v: boolean) => (v ? "Installed without the delay" : "Wait for the delay"),
  },
  trayIconEnabled: {
    label: "EasyPatch icon",
    hint: "In the notification area, for the people signed in.",
    on: "Show",
    off: "Hide",
    text: (v: boolean) => (v ? "Shown" : "Hidden, except for a message or a restart request"),
  },
  installNotificationsEnabled: { label: "Install notifications", on: "On", off: "Off", text: (v: boolean) => (v ? "On" : "Off") },
  agentAutoUpdateEnabled: { label: "Agent updates", hint: "The EasyPatch agent updates itself.", on: "Automatic", off: "Manual", text: (v: boolean) => (v ? "Automatic" : "Manual") },
} as const;
type BoolKey = keyof typeof BOOLS;

const DEFAULT_SCHEDULE: PatchRestartSchedule = {
  enabled: true,
  days: [],
  time: "03:00",
  condition: "OnlyIfPending",
  mode: "PromptWithDeadline",
  countdownMinutes: 5,
  deadlineMinutes: 240,
  expiryMinutes: 120,
};

const DEFAULT_GROUPS: { [K in WuKey]: NonNullable<PatchWindowsUpdate[K]> } = {
  automaticUpdates: { mode: "AutoDownloadNotifyInstall", scheduledInstallDay: 0, scheduledInstallHour: 3 },
  featureUpdates: { deferDays: null, targetProductVersion: "", targetReleaseVersion: "" },
  qualityUpdates: { deferDays: null, disablePause: false },
  restartBehavior: { noAutoRestartWithSignedInUsers: true, activeHoursStart: null, activeHoursEnd: null },
};

const WINDOW_LENGTHS = [30, 60, 90, 120, 180, 240, 360, 480, 720, 1440];
const HOURS = Array.from({ length: 24 }, (_, h) => h);
const hourText = (h: number) => `${String(h).padStart(2, "0")}:00`;
const KB = /^KB\d{1,10}$/;
const WINGET = /^[A-Za-z0-9][A-Za-z0-9_+-]*(\.[A-Za-z0-9_+-]+)+$/;

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/** A layer as compared for unsaved changes: key order and a Windows Update block with nothing in it do not count. */
function canon(l: Layer): string {
  const wu = l.windowsUpdate && Object.values(l.windowsUpdate).some((g) => g !== null) ? l.windowsUpdate : null;
  return JSON.stringify({ ...l, windowsUpdate: wu, excludedKbs: l.excludedKbs ?? [] }, (_k, v: unknown) =>
    // A number being typed that is not one yet is a change, not the null JSON makes of it.
    typeof v === "number" && Number.isNaN(v)
      ? "NaN"
      : v && typeof v === "object" && !Array.isArray(v)
        ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : 1)))
        : v,
  );
}

/** "from the organization", "from the tag Pilot", "EasyPatch's default". */
export function fromText(source: string | undefined): string {
  if (!source) return "";
  if (source === "Default policy") return "from the default policy";
  if (source === "Organization") return "from the organization";
  if (source === "Site") return "from the site";
  if (source === "EasyPatch's defaults") return "EasyPatch's default";
  if (source.startsWith("Tag ")) return `from the tag ${source.slice(4)}`;
  return `from ${source}`;
}

function normalizeKb(text: string): string {
  const t = text.trim().toUpperCase();
  return /^\d+$/.test(t) ? `KB${t}` : t;
}

/** The checks the server makes, so the form can say so before saving. Keys are the server's field names. */
export function checkPolicy(form: Layer, level: PolicyLevel, inherited: Layer, windows: boolean): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const [k, spec] of Object.entries(NUMBERS) as [NumberKey, (typeof NUMBERS)[NumberKey]][]) {
    const v = form[k];
    if (v === null) continue;
    if (!Number.isInteger(v)) errors[k] = "Enter a whole number.";
    else if (v < spec.min || v > spec.max) errors[k] = `Choose ${spec.what} from ${spec.min} to ${spec.max}.`;
  }
  if (form.maintenanceDurationMinutes !== null && (form.maintenanceDurationMinutes < 15 || form.maintenanceDurationMinutes > 1440)) {
    errors.maintenanceDays = "Choose a window length from 15 to 1440 minutes.";
  }
  if (form.maintenanceStart !== null && !/^([01]\d|2[0-3]):[0-5]\d$/.test(form.maintenanceStart)) errors.maintenanceDays = "Give a time as in 02:00.";
  if (form.allowedCategories !== null && form.allowedCategories.length === 0) errors.allowedCategories = "Choose at least one category.";
  const autoInstall = form.autoInstallEnabled ?? inherited.autoInstallEnabled ?? false;
  const window = level === "tag" && form.maintenanceDays === null ? [0] : (form.maintenanceDays ?? inherited.maintenanceDays ?? []);
  if ((form.autoInstallEnabled !== null || form.maintenanceDays !== null) && autoInstall && window.length === 0) {
    errors.maintenanceDays = "Automatic installs happen only in the maintenance window: choose its days.";
  }
  const s = form.restartSchedule;
  if (s?.enabled && (s.days ?? []).length === 0) errors.restartSchedule = "Choose at least one day for the restart schedule.";
  if (s?.enabled && !/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time)) errors.restartSchedule = "Give the restart time as in 03:00.";
  if (windows) {
    const apps = form.applicationUpdates?.approvedApps ?? [];
    if (apps.length > 100) errors.applicationUpdates = "Approve at most 100 applications.";
    const g = form.windowsUpdate;
    const feature = g?.featureUpdates?.managed ? g.featureUpdates.value : null;
    if (feature) {
      if (feature.deferDays !== null && (!Number.isInteger(feature.deferDays) || feature.deferDays < 0 || feature.deferDays > 365)) {
        errors["windowsUpdate.featureUpdates"] = "Defer feature updates by 0 to 365 days.";
      } else if (!feature.targetProductVersion !== !feature.targetReleaseVersion.trim()) {
        errors["windowsUpdate.featureUpdates"] = "To keep a Windows version, give both the product and the version (for example 24H2).";
      } else if (feature.targetReleaseVersion.trim() && !/^\d{2}H\d$/i.test(feature.targetReleaseVersion.trim())) {
        errors["windowsUpdate.featureUpdates"] = "The version looks like 24H2.";
      }
    }
    const quality = g?.qualityUpdates?.managed ? g.qualityUpdates.value : null;
    if (quality && quality.deferDays !== null && (!Number.isInteger(quality.deferDays) || quality.deferDays < 0 || quality.deferDays > 30)) {
      errors["windowsUpdate.qualityUpdates"] = "Defer quality updates by 0 to 30 days.";
    }
    const restart = g?.restartBehavior?.managed ? g.restartBehavior.value : null;
    if (restart) {
      const { activeHoursStart: a, activeHoursEnd: b } = restart;
      if ((a === null) !== (b === null)) errors["windowsUpdate.restartBehavior"] = "Give both the start and the end of active hours.";
      else if (a !== null && b !== null && (a === b || (b - a + 24) % 24 > 18)) errors["windowsUpdate.restartBehavior"] = "Active hours span 1 to 18 hours.";
    }
  }
  return errors;
}

/** One level's policy, loaded and editable where the server says so. */
export function PolicyPanel({ level, id, intro }: { level: PolicyLevel; id?: string; intro?: ReactNode }) {
  const path = policyPath(level, id);
  const view = useApi<PatchPolicyView>(path);
  if (view.isPending) return <Spinner label="Loading the policy…" />;
  if (view.isError) {
    const code = view.error instanceof ApiError ? view.error.code : "";
    if (code === "easypatch_not_linked") {
      return (
        <EmptyState title="Not patched by EasyPatch" icon={<ShieldOff className="size-8" aria-hidden />}>
          This organization is not linked to an EasyPatch organization, so it has no patch policy. A super administrator links it under
          Settings → EasyPatch.
        </EmptyState>
      );
    }
    if (code === "easypatch_server_wide") {
      return (
        <EmptyState title="Managed in EasyPatch" icon={<ShieldOff className="size-8" aria-hidden />}>
          {view.error.message}
        </EmptyState>
      );
    }
    if (code === "easypatch_site_not_found") {
      return (
        <EmptyState title="No patch policy yet" icon={<ShieldOff className="size-8" aria-hidden />}>
          EasyPatch has no site for this site yet. It is created when the site's first device gets the EasyPatch agent; until then the
          site's devices follow the organization's policy.
        </EmptyState>
      );
    }
    return <ErrorState error={view.error} onRetry={() => void view.refetch()} />;
  }
  return <PolicyForm key={path} view={view.data} path={path} intro={intro} />;
}

const INTRO: Record<PolicyLevel, string> = {
  default:
    "Every organization starts from the default policy. Organizations, sites, tags and devices override the values they set.",
  organization:
    "Values set here apply to every site and device of the organization, over the default policy. Sites, tags and devices can override them.",
  site: "Values set here apply to the site's devices, over the organization's and the default policy. Tags and devices can override them.",
  tag: "Values set here apply to the devices with this tag, directly or through their site or organization, over their site's, organization's and the default policy. A device's own policy overrides them; when tags disagree, the higher priority wins.",
  device: "Values set here apply to this device only, over its tags, site, organization and the default policy.",
};

function PolicyForm({ view, path, intro }: { view: PatchPolicyView; path: string; intro?: ReactNode }) {
  const toast = useToast();
  const [form, setForm] = useState<Layer>(() => clone(view.own));
  const [base, setBase] = useState<Layer>(() => clone(view.own));
  const [resetting, setResetting] = useState(false);
  const level = view.level;
  const top = level === "default";
  const canEdit = view.canEdit;
  const windows = view.windows;
  const inherited = view.inherited;
  const errors = checkPolicy(form, level, inherited, windows);
  const dirty = canon(form) !== canon(base);
  const blocked = Object.keys(errors).length > 0;

  const done = (result: PatchPolicyView) => {
    setForm(clone(result.own));
    setBase(clone(result.own));
  };
  const save = useApiMutation((body: Layer) => api.put<PatchPolicyView>(path, body), {
    invalidate: ["/patching", "/audit"],
    onSuccess: (r) => {
      done(r);
      toast.success("Policy saved.");
    },
  });
  const reset = useApiMutation(() => api.del<PatchPolicyView>(path), {
    invalidate: ["/patching", "/audit"],
    onSuccess: (r) => {
      done(r);
      setResetting(false);
      toast.success(top ? "The default policy is EasyPatch's again." : "This policy inherits everything again.");
    },
  });

  const set = <K extends keyof Layer>(k: K, v: Layer[K]) => setForm((f) => ({ ...f, [k]: v }));
  const err = (field: string) => errors[field] ?? fieldError(save.error, field);
  const from = (field: string) => fromText(view.inheritedFrom[field]);
  // A value is set here when the level's own value is not null; the default policy sets every value.
  const inheritable = !top;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!dirty || blocked || !canEdit) return;
    save.mutate(form);
  }

  const numberRow = (k: NumberKey) => {
    const spec = NUMBERS[k];
    const own = form[k];
    return (
      <Row
        key={k}
        label={spec.label}
        hint={spec.hint}
        inheritable={inheritable}
        canEdit={canEdit}
        overriding={own !== null}
        onOverride={(on) => set(k, on ? (inherited[k] ?? spec.min) : null)}
        inherited={<Inherited text={inherited[k] !== null ? spec.text(inherited[k]) : "Not set"} from={from(k)} />}
        own={own !== null ? spec.text(own) : ""}
        error={err(k)}
      >
        <NumberInput label={spec.label} value={own} min={spec.min} max={spec.max} unit={spec.unit} onChange={(v) => set(k, v ?? Number.NaN)} />
      </Row>
    );
  };

  const boolRow = (k: BoolKey) => {
    const spec = BOOLS[k] as { label: string; hint?: string; on: string; off: string; text: (v: boolean) => string };
    const own = form[k];
    return (
      <Row
        key={k}
        label={spec.label}
        hint={spec.hint}
        inheritable={inheritable}
        canEdit={canEdit}
        overriding={own !== null}
        onOverride={(on) => set(k, on ? (inherited[k] ?? false) : null)}
        inherited={<Inherited text={spec.text(inherited[k] ?? false)} from={from(k)} />}
        own={own !== null ? spec.text(own) : ""}
        error={err(k)}
      >
        <Segmented
          label={spec.label}
          options={[
            { value: "on", label: spec.on },
            { value: "off", label: spec.off },
          ]}
          value={own ? "on" : "off"}
          onChange={(v) => set(k, v === "on")}
          className="self-start"
        />
      </Row>
    );
  };

  const windowOwn = form.maintenanceDays !== null;
  const schedule = form.restartSchedule;
  const apps = form.applicationUpdates;
  const groups: Groups = { automaticUpdates: null, featureUpdates: null, qualityUpdates: null, restartBehavior: null, ...form.windowsUpdate };
  // Each group's value is its own shape; WU_GROUPS and DEFAULT_GROUPS pair them.
  const setGroup = (k: WuKey, g: PatchGroupSetting<object> | null) => set("windowsUpdate", { ...groups, [k]: g } as Groups);
  const inheritedWu: PatchWindowsUpdate = {
    automaticUpdates: inherited.windowsUpdate?.automaticUpdates?.managed ? inherited.windowsUpdate.automaticUpdates.value : null,
    featureUpdates: inherited.windowsUpdate?.featureUpdates?.managed ? inherited.windowsUpdate.featureUpdates.value : null,
    qualityUpdates: inherited.windowsUpdate?.qualityUpdates?.managed ? inherited.windowsUpdate.qualityUpdates.value : null,
    restartBehavior: inherited.windowsUpdate?.restartBehavior?.managed ? inherited.windowsUpdate.restartBehavior.value : null,
  };
  const zone = view.timeZone ? ` (${view.timeZone})` : "";

  return (
    <form onSubmit={submit} className="flex flex-col gap-4" noValidate aria-label={`${view.name} patch policy`}>
      <div className="flex flex-col gap-2 text-sm text-muted">
        <p>
          {INTRO[level]}{" "}
          {view.timeZone
            ? `Times are in ${view.timeZone}.`
            : level === "default" || level === "organization" || level === "tag"
              ? "Times are in each device's site time zone."
              : null}
        </p>
        {intro}
      </div>
      {!canEdit && (
        <Alert tone="info">
          {view.readOnlyReason ??
            (top || level === "tag"
              ? "Only super administrators change the default policy and tags' policies."
              : "You can see this policy. Changing it needs permission to configure patching in this organization.")}
        </Alert>
      )}

      <Card title="Automatic installs" padded={false}>
        {boolRow("autoInstallEnabled")}
        <Row
          label="Maintenance window"
          hint="When automatic installs and scheduled jobs run."
          inheritable={inheritable}
          canEdit={canEdit}
          overriding={windowOwn}
          onOverride={(on) =>
            setForm((f) => ({
              ...f,
              maintenanceDays: on ? [...(inherited.maintenanceDays ?? [])] : null,
              maintenanceStart: on ? (inherited.maintenanceStart ?? "02:00") : null,
              maintenanceDurationMinutes: on ? (inherited.maintenanceDurationMinutes ?? 180) : null,
            }))
          }
          inherited={<Inherited text={`${windowText(inherited)}${windowText(inherited) === "None" ? "" : zone}`} from={from("maintenanceDays")} />}
          own={`${windowText(form)}${windowText(form) === "None" ? "" : zone}`}
          error={err("maintenanceDays") ?? err("maintenanceStart") ?? err("maintenanceDurationMinutes")}
        >
          <div className="flex flex-col gap-2.5">
            <DayPicker label="Window days" days={form.maintenanceDays ?? []} onChange={(d) => set("maintenanceDays", d)} />
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <label className="flex items-center gap-2">
                <span className="text-muted">Opens at</span>
                <Input type="time" className="w-32" value={form.maintenanceStart ?? ""} onChange={(e) => set("maintenanceStart", e.target.value)} />
              </label>
              <label className="flex items-center gap-2">
                <span className="text-muted">for</span>
                <Select
                  className="w-36"
                  value={form.maintenanceDurationMinutes ?? 180}
                  onChange={(e) => set("maintenanceDurationMinutes", Number(e.target.value))}
                >
                  {withCurrent(WINDOW_LENGTHS, form.maintenanceDurationMinutes).map((m) => (
                    <option key={m} value={m}>
                      {minutesText(m)}
                    </option>
                  ))}
                </Select>
              </label>
            </div>
            {(form.maintenanceDays ?? []).length === 0 && <p className="text-xs text-muted">No days: no maintenance window{top ? "" : " at this level"}.</p>}
          </div>
        </Row>
        {windows && numberRow("preDownloadHours")}
        {numberRow("securityInstallDelayDays")}
        {numberRow("installDelayDays")}
        {boolRow("knownExploitedSkipsDelay")}
      </Card>

      <Card title="What installs" padded={false}>
        <Row
          label="Categories"
          hint="Updates of these categories install, automatically or when someone installs all that are missing."
          inheritable={inheritable}
          canEdit={canEdit}
          overriding={form.allowedCategories !== null}
          onOverride={(on) => set("allowedCategories", on ? [...(inherited.allowedCategories ?? POLICY_CATEGORIES)] : null)}
          inherited={<Inherited text={(inherited.allowedCategories ?? []).map(categoryLabel).join(", ") || "None"} from={from("allowedCategories")} />}
          own={(form.allowedCategories ?? []).map(categoryLabel).join(", ")}
          error={err("allowedCategories")}
        >
          <fieldset className="grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-3">
            <legend className="sr-only">Categories</legend>
            {POLICY_CATEGORIES.map((c) => (
              <label key={c} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="size-4 accent-accent"
                  checked={(form.allowedCategories ?? []).includes(c)}
                  onChange={(e) => {
                    const now = new Set(form.allowedCategories ?? []);
                    if (e.target.checked) now.add(c);
                    else now.delete(c);
                    set(
                      "allowedCategories",
                      POLICY_CATEGORIES.filter((x) => now.has(x)),
                    );
                  }}
                />
                {categoryLabel(c)}
              </label>
            ))}
          </fieldset>
        </Row>
        {boolRow("includeOptional")}
        {boolRow("acceptEulas")}
        <ListRow
          label="Excluded KBs"
          hint={
            top
              ? "Never installed anywhere."
              : "Never installed here, with those excluded above: a level adds exclusions and cannot lift the ones it inherits."
          }
          canEdit={canEdit}
          items={form.excludedKbs ?? []}
          above={top ? [] : (inherited.excludedKbs ?? [])}
          placeholder="KB5044284"
          normalize={normalizeKb}
          check={(v) => (KB.test(v) ? null : `${v} is not a KB number such as KB5044284.`)}
          onChange={(v) => set("excludedKbs", v)}
          error={err("excludedKbs")}
          mono
        />
      </Card>

      {windows && (
        <Card title="Application updates" padded={false}>
          <Row
            label="Update approved applications"
            hint="With winget, inside the maintenance window, like the updates above."
            inheritable={inheritable}
            canEdit={canEdit}
            overriding={apps !== null}
            onOverride={(on) => set("applicationUpdates", on ? clone(inherited.applicationUpdates ?? { enabled: false, approvedApps: [] }) : null)}
            inherited={<Inherited text={appsText(inherited.applicationUpdates)} from={from("applicationUpdates")} />}
            own={appsText(apps)}
            error={err("applicationUpdates")}
          >
            <div className="flex flex-col gap-3">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="size-4 accent-accent"
                  checked={apps?.enabled ?? false}
                  onChange={(e) => set("applicationUpdates", { approvedApps: [], ...apps, enabled: e.target.checked })}
                />
                Keep the approved applications up to date
              </label>
              <ListRowControl
                label="Approved applications"
                items={apps?.approvedApps ?? []}
                placeholder="Mozilla.Firefox"
                normalize={(v) => v.trim()}
                check={(v) =>
                  WINGET.test(v) && v.length >= 3 && v.length <= 128 ? null : `${v} is not a winget package ID such as Mozilla.Firefox.`
                }
                onChange={(v) => set("applicationUpdates", { enabled: apps?.enabled ?? false, approvedApps: v })}
                mono
              />
            </div>
          </Row>
          <p className="border-t border-line px-4 py-3 text-xs text-muted">
            This is how EasyRMM keeps applications up to date on a schedule. To install, update or remove one application now, use{" "}
            {level === "device" ? "this device's" : "a device's"} <strong className="font-medium text-fg">Software</strong> tab, or{" "}
            <Link to="/jobs" className="text-accent hover:underline">
              Jobs
            </Link>{" "}
            → Install software for many devices; those run once and do not wait for the window.
          </p>
        </Card>
      )}

      <Card title="Restarts and users" padded={false}>
        <Row
          label="Restart schedule"
          hint="Installing never restarts a device. This restarts it at a set time, with the people signed in asked or warned."
          inheritable={inheritable}
          canEdit={canEdit}
          overriding={schedule !== null}
          onOverride={(on) => set("restartSchedule", on ? clone(inherited.restartSchedule ?? { ...DEFAULT_SCHEDULE, enabled: false }) : null)}
          inherited={
            <Inherited text={`${restartScheduleText(inherited.restartSchedule)}${inherited.restartSchedule?.enabled ? zone : ""}`} from={from("restartSchedule")} />
          }
          own={`${restartScheduleText(schedule)}${schedule?.enabled ? zone : ""}`}
          error={err("restartSchedule")}
        >
          <ScheduleControl
            value={schedule}
            onChange={(s) => set("restartSchedule", s)}
            off={() => set("restartSchedule", top && view.own.restartSchedule === null ? null : { ...(schedule ?? DEFAULT_SCHEDULE), enabled: false })}
          />
        </Row>
        {windows && boolRow("trayIconEnabled")}
        {windows && boolRow("installNotificationsEnabled")}
        {boolRow("agentAutoUpdateEnabled")}
      </Card>

      <Card title="Agent schedule" padded={false}>
        {numberRow("checkInIntervalSeconds")}
        {numberRow("jitterPercent")}
        {numberRow("scanIntervalMinutes")}
        {numberRow("inventoryIntervalMinutes")}
        {numberRow("scanStaleAfterHours")}
        {level !== "device" && level !== "tag" && numberRow("maxConcurrentInstallsPerSite")}
      </Card>

      {windows && (
        <Card title="Windows Update settings" padded={false}>
          <p className="border-b border-line px-4 py-3 text-xs text-muted">
            Windows Update's own settings, which EasyPatch writes on each device. A group EasyPatch does not manage is left as Windows,
            group policy or MDM set it.
          </p>
          {WU_GROUPS.map(({ key, label }) => {
            const g = groups[key];
            const state = g === null ? "inherit" : g.managed ? "override" : "off";
            const value = g?.managed ? g.value : null;
            return (
              <Row
                key={key}
                label={label}
                inheritable={inheritable}
                canEdit={canEdit}
                state={top && state === "inherit" ? "off" : state}
                options={[
                  ...(inheritable ? [{ value: "inherit" as const, label: "Inherit" }] : []),
                  { value: "off" as const, label: "Leave alone" },
                  { value: "override" as const, label: "Manage" },
                ]}
                onState={(s) => {
                  if (s === "inherit") setGroup(key, null);
                  else if (s === "off") setGroup(key, { managed: false, value: null });
                  else setGroup(key, { managed: true, value: clone(inheritedWu[key] ?? DEFAULT_GROUPS[key]) });
                }}
                inherited={<Inherited text={windowsUpdateText(inheritedWu, key)} from={from(`windowsUpdate.${key}`)} />}
                own={state === "off" ? "Not managed" : windowsUpdateText({ ...inheritedWu, [key]: value }, key)}
                offText="Not managed: Windows keeps its own settings for this group, even where a level above manages it."
                error={err(`windowsUpdate.${key}`)}
              >
                {value && <GroupControl group={key} value={value} onChange={(v) => setGroup(key, { managed: true, value: v })} />}
              </Row>
            );
          })}
        </Card>
      )}

      <InlineError
        error={save.error}
        fields={[...Object.keys(NUMBERS), ...Object.keys(BOOLS), "maintenanceDays", "maintenanceStart", "maintenanceDurationMinutes", "allowedCategories", "excludedKbs", "restartSchedule", "applicationUpdates", ...WU_GROUPS.map((g) => `windowsUpdate.${g.key}`)]}
      />

      {canEdit && (
        // The console's main area has py-5, inside which sticky elements stop; -bottom-5 and -mb-5 take the bar to its edge.
        <div className="sticky -bottom-5 z-10 -mx-1 -mb-5 flex flex-wrap items-center justify-end gap-2 border-t border-line bg-canvas/95 px-1 pt-3 pb-8 backdrop-blur-sm">
          <span className="mr-auto text-xs text-muted">
            {dirty
              ? blocked
                ? "Correct the values marked above to save."
                : "Unsaved changes."
              : view.updatedAt
                ? `Last changed ${formatDateTime(view.updatedAt)}`
                : top
                  ? "EasyPatch's defaults, never changed."
                  : "Nothing set here: everything is inherited."}
          </span>
          {(top || view.hasOwn) && (
            <Button variant="danger-ghost" icon={<RotateCcw className="size-4" aria-hidden />} onClick={() => setResetting(true)}>
              {top ? "Restore EasyPatch's defaults" : "Inherit everything"}
            </Button>
          )}
          <Button onClick={() => setForm(clone(base))} disabled={!dirty}>
            Discard changes
          </Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!dirty || blocked} icon={<Save className="size-4" aria-hidden />}>
            Save policy
          </Button>
        </div>
      )}

      <ConfirmDialog
        open={resetting}
        onClose={() => {
          setResetting(false);
          reset.reset();
        }}
        onConfirm={() => reset.mutate(undefined)}
        title={top ? "Restore EasyPatch's defaults" : "Inherit everything"}
        confirmLabel={top ? "Restore defaults" : "Inherit everything"}
        tone="danger"
        loading={reset.isPending}
        error={reset.error}
        confirmText={view.name}
      >
        <p>
          {top
            ? "Every value of the default policy goes back to EasyPatch's own, for every organization that does not set it. Excluded KBs are emptied."
            : `This removes ${view.name}'s own policy: every value comes from the levels above again, and its excluded KBs go.`}
        </p>
      </ConfirmDialog>
    </form>
  );
}

function appsText(a: Layer["applicationUpdates"]): string {
  if (!a || !a.enabled) return "Off";
  const list = a.approvedApps ?? [];
  return list.length === 0 ? "On, but no application is approved" : `On, for ${list.join(", ")}`;
}

function withCurrent(list: number[], current: number | null): number[] {
  return current === null || list.includes(current) ? list : [...list, current].sort((a, b) => a - b);
}

function Inherited({ text, from }: { text: ReactNode; from?: string }) {
  return (
    <span className="text-sm">
      {text}
      {from && <span className="text-muted"> · {from}</span>}
    </span>
  );
}

type RowState = "inherit" | "off" | "override";

/**
 * A value: its label, and either what it inherits (with where from) or this level's own value. Someone who may edit
 * chooses Inherit or Override; the default policy has nothing to inherit.
 */
function Row({
  label,
  hint,
  inheritable,
  canEdit,
  overriding,
  onOverride,
  state,
  options,
  onState,
  inherited,
  own,
  offText,
  error,
  children,
}: {
  label: string;
  hint?: ReactNode;
  inheritable: boolean;
  canEdit: boolean;
  overriding?: boolean;
  onOverride?: (on: boolean) => void;
  /** Instead of overriding, for a choice of more than two. */
  state?: RowState;
  options?: { value: RowState; label: string }[];
  onState?: (s: RowState) => void;
  inherited: ReactNode;
  own: ReactNode;
  offText?: string;
  error?: string | null;
  children?: ReactNode;
}) {
  // The default policy inherits nothing: what it does not set (no restart schedule) is still its own to set.
  const current: RowState = state ?? (overriding || !inheritable ? "override" : "inherit");
  const choices = options ?? (inheritable ? [{ value: "inherit" as const, label: "Inherit" }, { value: "override" as const, label: "Override" }] : null);
  return (
    <div className="grid gap-x-6 gap-y-2 border-b border-line px-4 py-3 last:border-b-0 md:grid-cols-[minmax(0,15rem)_minmax(0,1fr)]">
      <div className="min-w-0">
        <p className="text-sm font-medium">{label}</p>
        {hint && <p className="mt-0.5 text-xs text-muted">{hint}</p>}
      </div>
      <div className="flex min-w-0 flex-col items-start gap-2">
        {canEdit && choices && (
          <Segmented
            label={`${label}: where its value comes from`}
            options={choices}
            value={current}
            onChange={(v) => (onState ? onState(v) : onOverride?.(v === "override"))}
          />
        )}
        {current === "inherit" ? (
          inherited
        ) : current === "off" ? (
          <span className="text-sm">{offText}</span>
        ) : canEdit ? (
          <div className="w-full">{children}</div>
        ) : (
          <span className="text-sm">
            {own}
            {inheritable && <span className="text-muted"> · set here</span>}
          </span>
        )}
        {error && <p className="text-xs text-danger">{error}</p>}
      </div>
    </div>
  );
}

/** A whole number; empty is null when optional, otherwise not a number, which the checks refuse. */
function NumberInput({ label, value, min, max, unit, optional, onChange }: {
  label: string;
  value: number | null;
  min: number;
  max: number;
  unit: string;
  optional?: boolean;
  onChange: (v: number | null) => void;
}) {
  const display = (v: number | null) => (v === null || Number.isNaN(v) ? "" : String(v));
  const parse = (t: string) => (t.trim() === "" ? (optional ? null : Number.NaN) : Number(t.trim()));
  const [text, setText] = useState(display(value));
  const [last, setLast] = useState(value);
  // A value changed from outside (discarded, restored, inherited) replaces what was typed.
  if (!Object.is(value, last)) {
    setLast(value);
    if (!Object.is(value, parse(text))) setText(display(value));
  }
  return (
    <span className="flex items-center gap-2 text-sm">
      <Input
        type="number"
        inputMode="numeric"
        aria-label={label}
        className="w-28"
        min={min}
        max={max}
        value={text}
        placeholder={optional ? "None" : undefined}
        onChange={(e) => {
          setText(e.target.value);
          onChange(parse(e.target.value));
        }}
      />
      <span className="text-muted">{unit}</span>
    </span>
  );
}

function DayPicker({ label, days, onChange }: { label: string; days: number[]; onChange: (d: number[]) => void }) {
  return (
    <fieldset className="flex flex-wrap gap-1">
      <legend className="sr-only">{label}</legend>
      {DAYS.map((name, d) => {
        const on = days.includes(d);
        return (
          <label
            key={name}
            className={cx(
              "cursor-pointer rounded-md border px-2.5 py-1 text-xs font-medium select-none has-focus-visible:outline-2 has-focus-visible:outline-accent",
              on ? "border-accent bg-accent-soft text-accent" : "border-line text-muted hover:text-fg",
            )}
          >
            <input
              type="checkbox"
              className="sr-only"
              checked={on}
              onChange={(e) => onChange(e.target.checked ? [...days, d].sort((a, b) => a - b) : days.filter((x) => x !== d))}
            />
            <span aria-hidden>{name.slice(0, 3)}</span>
            <span className="sr-only">{name}</span>
          </label>
        );
      })}
    </fieldset>
  );
}

function ScheduleControl({ value, onChange, off }: { value: PatchRestartSchedule | null; onChange: (s: PatchRestartSchedule) => void; off: () => void }) {
  const s = value ?? { ...DEFAULT_SCHEDULE, enabled: false };
  const mode = RESTART_MODES.find((m) => m.value === s.mode);
  const put = (patch: Partial<PatchRestartSchedule>) => onChange({ ...s, ...patch });
  return (
    <div className="flex flex-col gap-3">
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          className="size-4 accent-accent"
          checked={s.enabled}
          onChange={(e) => (e.target.checked ? put({ enabled: true }) : off())}
        />
        Restart on a schedule
      </label>
      {s.enabled ? (
        <>
          <DayPicker label="Restart days" days={s.days ?? []} onChange={(d) => put({ days: d })} />
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <label className="flex items-center gap-2">
              <span className="text-muted">At</span>
              <Input type="time" className="w-32" value={s.time.slice(0, 5)} onChange={(e) => put({ time: e.target.value })} />
            </label>
            <Segmented
              label="When to restart"
              options={[
                { value: "OnlyIfPending", label: "Only when a restart is pending" },
                { value: "Always", label: "Always" },
              ]}
              value={s.condition === "Always" ? "Always" : "OnlyIfPending"}
              onChange={(v) => put({ condition: v })}
            />
          </div>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-xs font-medium text-muted">The people signed in</span>
            <Select className="max-w-sm" value={s.mode} onChange={(e) => put({ mode: e.target.value as RestartMode })}>
              {RESTART_MODES.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </Select>
            {mode && <span className="text-xs text-subtle">{mode.hint}</span>}
          </label>
          <div className="flex flex-wrap gap-3">
            {s.mode === "Countdown" && (
              <MinutesSelect label="Countdown" value={s.countdownMinutes} options={COUNTDOWNS} onChange={(v) => put({ countdownMinutes: v })} />
            )}
            {s.mode === "PromptWithDeadline" && (
              <MinutesSelect label="Deadline" value={s.deadlineMinutes} options={DEADLINES} onChange={(v) => put({ deadlineMinutes: v })} />
            )}
            <MinutesSelect label="An offline computer can wait" value={s.expiryMinutes} options={EXPIRIES} onChange={(v) => put({ expiryMinutes: v })} />
          </div>
        </>
      ) : (
        <p className="text-xs text-muted">No scheduled restarts. Restarts happen when someone asks for one.</p>
      )}
    </div>
  );
}

function MinutesSelect({ label, value, options, onChange }: { label: string; value: number; options: number[]; onChange: (v: number) => void }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-muted">{label}</span>
      <Select className="w-40" value={value} onChange={(e) => onChange(Number(e.target.value))}>
        {withCurrent(options, value).map((m) => (
          <option key={m} value={m}>
            {minutesText(m)}
          </option>
        ))}
      </Select>
    </label>
  );
}

function HourSelect({ label, value, optional, onChange }: { label: string; value: number | null; optional?: boolean; onChange: (v: number | null) => void }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-muted">{label}</span>
      <Select className="w-32" value={value ?? ""} onChange={(e) => onChange(e.target.value === "" ? null : Number(e.target.value))}>
        {optional && <option value="">Not set</option>}
        {HOURS.map((h) => (
          <option key={h} value={h}>
            {hourText(h)}
          </option>
        ))}
      </Select>
    </label>
  );
}

function GroupControl<K extends WuKey>({ group, value, onChange }: { group: K; value: NonNullable<PatchWindowsUpdate[K]>; onChange: (v: NonNullable<PatchWindowsUpdate[K]>) => void }) {
  const put = (patch: object) => onChange({ ...value, ...patch } as NonNullable<PatchWindowsUpdate[K]>);
  switch (group) {
    case "automaticUpdates": {
      const v = value as NonNullable<PatchWindowsUpdate["automaticUpdates"]>;
      return (
        <div className="flex flex-wrap gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-xs font-medium text-muted">Windows updates itself</span>
            <Select className="max-w-sm" value={v.mode} onChange={(e) => put({ mode: e.target.value })}>
              {Object.entries(AUTO_UPDATE_MODES).map(([m, text]) => (
                <option key={m} value={m}>
                  {text}
                </option>
              ))}
            </Select>
          </label>
          {v.mode === "AutoDownloadScheduleInstall" && (
            <>
              <label className="flex flex-col gap-1">
                <span className="text-xs font-medium text-muted">Install on</span>
                <Select className="w-36" value={v.scheduledInstallDay} onChange={(e) => put({ scheduledInstallDay: Number(e.target.value) })}>
                  {INSTALL_DAYS.map((d, i) => (
                    <option key={d} value={i}>
                      {i === 0 ? "Every day" : d}
                    </option>
                  ))}
                </Select>
              </label>
              <HourSelect label="At" value={v.scheduledInstallHour} onChange={(h) => put({ scheduledInstallHour: h ?? 0 })} />
            </>
          )}
        </div>
      );
    }
    case "featureUpdates": {
      const v = value as NonNullable<PatchWindowsUpdate["featureUpdates"]>;
      return (
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-xs font-medium text-muted">Defer by</span>
            <NumberInput label="Defer feature updates by" value={v.deferDays} min={0} max={365} unit="days" optional onChange={(d) => put({ deferDays: d })} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs font-medium text-muted">Stay on</span>
            <Select className="w-36" value={v.targetProductVersion} onChange={(e) => put({ targetProductVersion: e.target.value })}>
              <option value="">Any version</option>
              <option value="Windows 10">Windows 10</option>
              <option value="Windows 11">Windows 11</option>
            </Select>
          </label>
          {v.targetProductVersion && (
            <label className="flex flex-col gap-1">
              <span className="text-xs font-medium text-muted">Version</span>
              <Input className="w-28 font-mono" placeholder="24H2" value={v.targetReleaseVersion} onChange={(e) => put({ targetReleaseVersion: e.target.value.toUpperCase() })} />
            </label>
          )}
        </div>
      );
    }
    case "qualityUpdates": {
      const v = value as NonNullable<PatchWindowsUpdate["qualityUpdates"]>;
      return (
        <div className="flex flex-wrap items-end gap-4">
          <label className="flex flex-col gap-1">
            <span className="text-xs font-medium text-muted">Defer by</span>
            <NumberInput label="Defer quality updates by" value={v.deferDays} min={0} max={30} unit="days" optional onChange={(d) => put({ deferDays: d })} />
          </label>
          <label className="flex items-center gap-2 pb-2 text-sm">
            <input type="checkbox" className="size-4 accent-accent" checked={v.disablePause} onChange={(e) => put({ disablePause: e.target.checked })} />
            Users cannot pause updates
          </label>
        </div>
      );
    }
    default: {
      const v = value as NonNullable<PatchWindowsUpdate["restartBehavior"]>;
      return (
        <div className="flex flex-col gap-3">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4 accent-accent"
              checked={v.noAutoRestartWithSignedInUsers}
              onChange={(e) => put({ noAutoRestartWithSignedInUsers: e.target.checked })}
            />
            No automatic restart while someone is signed in
          </label>
          <div className="flex flex-wrap gap-3">
            <HourSelect label="Active hours from" value={v.activeHoursStart} optional onChange={(h) => put({ activeHoursStart: h })} />
            <HourSelect label="to" value={v.activeHoursEnd} optional onChange={(h) => put({ activeHoursEnd: h })} />
          </div>
        </div>
      );
    }
  }
}

/** Excluded KBs: this level's own, which can be removed, and those from above, which cannot. */
function ListRow({ label, hint, canEdit, items, above, error, ...control }: {
  label: string;
  hint: string;
  canEdit: boolean;
  items: string[];
  above: string[];
  error?: string | null;
} & Omit<Parameters<typeof ListRowControl>[0], "label" | "items">) {
  const fromAbove = above.filter((x) => !items.includes(x));
  return (
    <div className="grid gap-x-6 gap-y-2 border-b border-line px-4 py-3 last:border-b-0 md:grid-cols-[minmax(0,15rem)_minmax(0,1fr)]">
      <div className="min-w-0">
        <p className="text-sm font-medium">{label}</p>
        <p className="mt-0.5 text-xs text-muted">{hint}</p>
      </div>
      <div className="flex min-w-0 flex-col gap-2">
        {canEdit ? (
          <ListRowControl label={label} items={items} {...control} />
        ) : (
          <span className={cx("text-sm", control.mono && "font-mono text-xs")}>{items.length > 0 ? items.join(", ") : "None set here"}</span>
        )}
        {fromAbove.length > 0 && (
          <p className="text-xs text-muted">
            Also excluded above: <span className="font-mono">{fromAbove.join(", ")}</span>
          </p>
        )}
        {error && <p className="text-xs text-danger">{error}</p>}
      </div>
    </div>
  );
}

function ListRowControl({ label, items, placeholder, normalize, check, onChange, mono }: {
  label: string;
  items: string[];
  placeholder: string;
  normalize: (v: string) => string;
  check: (v: string) => string | null;
  onChange: (v: string[]) => void;
  mono?: boolean;
}) {
  const [text, setText] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  function add() {
    const values = text
      .split(/[\s,;]+/)
      .map(normalize)
      .filter(Boolean);
    if (values.length === 0) return;
    const bad = values.map(check).find(Boolean);
    if (bad) {
      setProblem(bad);
      return;
    }
    const next = [...items];
    for (const v of values) if (!next.some((x) => x.toLowerCase() === v.toLowerCase())) next.push(v);
    onChange(next);
    setText("");
    setProblem(null);
  }
  return (
    <div className="flex flex-col gap-2">
      {items.length > 0 && (
        <ul className="flex flex-wrap gap-1.5" aria-label={label}>
          {items.map((v) => (
            <li key={v} className={cx("inline-flex items-center gap-1 rounded-md bg-neutral-soft py-0.5 pr-0.5 pl-2 text-xs", mono && "font-mono")}>
              {v}
              <IconButton label={`Remove ${v}`} className="size-5" onClick={() => onChange(items.filter((x) => x !== v))}>
                <X className="size-3" aria-hidden />
              </IconButton>
            </li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Input
          aria-label={`Add to ${label.toLowerCase()}`}
          className={cx("w-56", mono && "font-mono")}
          placeholder={placeholder}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setProblem(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <Button size="sm" onClick={add} disabled={text.trim() === ""}>
          Add
        </Button>
      </div>
      {problem && <p className="text-xs text-danger">{problem}</p>}
    </div>
  );
}
