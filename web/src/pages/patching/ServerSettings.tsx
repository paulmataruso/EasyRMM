import { useState, type FormEvent, type ReactNode } from "react";
import { Save } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchServerSettings, PatchSettingsView, PatchVulnerabilityFeed } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, ErrorState, InlineError, Input, Spinner, TableWrap } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative, plural } from "../../lib/format";
import { NumberInput } from "./PolicyEditor";

// Settings → Patching → Server (one-product plan, C6): EasyPatch's own settings, the same for every organization. Super
// administrators change them with the bundled engine; with a connected server, its own console does.

type NumberKey = { [K in keyof PatchServerSettings]: PatchServerSettings[K] extends number ? K : never }[keyof PatchServerSettings];

/** Each number's bounds, as EasyPatch checks them, its unit and how it reads. */
const NUMBERS: Record<NumberKey, { label: string; hint?: string; min: number; max: number; unit: string; text: (v: number) => string }> = {
  globalMaxConcurrentInstalls: {
    label: "Installs at once",
    hint: "Across every organization. Each policy can also limit installs per site.",
    min: 1,
    max: 10_000,
    unit: "devices",
    text: (v) => plural(v, "device"),
  },
  jobDefaultExpiryHours: {
    label: "A job not started expires after",
    hint: "Jobs for devices that stay offline.",
    min: 1,
    max: 24 * 90,
    unit: "hours",
    text: (v) => plural(v, "hour"),
  },
  runningJobTimeoutHours: { label: "A running job fails after", min: 1, max: 168, unit: "hours", text: (v) => plural(v, "hour") },
  waitingForRebootExpiryDays: {
    label: "A job waiting for a restart ends after",
    hint: "The updates stay installed; the job stops waiting for the device to restart.",
    min: 1,
    max: 365,
    unit: "days",
    text: (v) => plural(v, "day"),
  },
  deliveryLeaseMinutes: {
    label: "An agent has to start a job within",
    hint: "Otherwise the job is offered to it again.",
    min: 2,
    max: 120,
    unit: "minutes",
    text: (v) => plural(v, "minute"),
  },
  maxDeliveryAttempts: { label: "Offers before a job fails", min: 1, max: 50, unit: "times", text: (v) => plural(v, "time") },
  offlineThresholdMinutes: {
    label: "A device is offline after",
    hint: "Without checking in.",
    min: 3,
    max: 1440,
    unit: "minutes",
    text: (v) => plural(v, "minute"),
  },
  credentialLifetimeDays: { label: "Agent credentials last", min: 30, max: 3650, unit: "days", text: (v) => plural(v, "day") },
  credentialRotateBeforeDays: {
    label: "Agents renew them",
    hint: "Before they expire. Less than how long they last.",
    min: 1,
    max: 180,
    unit: "days before",
    text: (v) => `${plural(v, "day")} before`,
  },
  retentionEventsDays: {
    label: "Device events, resolved alerts and notifications",
    min: 7,
    max: 3650,
    unit: "days",
    text: (v) => plural(v, "day"),
  },
  retentionAuditDays: {
    label: "EasyPatch's audit log",
    hint: "And the daily compliance records behind Reports → Patch compliance.",
    min: 30,
    max: 3650,
    unit: "days",
    text: (v) => plural(v, "day"),
  },
  retentionJobsDays: { label: "Finished jobs", min: 7, max: 3650, unit: "days", text: (v) => plural(v, "day") },
  retentionScansDays: { label: "Scan results", min: 7, max: 3650, unit: "days", text: (v) => plural(v, "day") },
  retentionHistoryDays: { label: "Devices' update history", min: 30, max: 3650, unit: "days", text: (v) => plural(v, "day") },
  retentionReportsMonths: { label: "Keep monthly reports for", min: 1, max: 120, unit: "months", text: (v) => plural(v, "month") },
  rolloutGuardMinFailedEndpoints: {
    label: "Failed on at least",
    min: 1,
    max: 1000,
    unit: "devices",
    text: (v) => plural(v, "device"),
  },
  rolloutGuardFailurePercent: {
    label: "And on at least",
    hint: "Of the devices that tried to install it.",
    min: 1,
    max: 100,
    unit: "%",
    text: (v) => `${v}%`,
  },
  rolloutGuardWindowDays: { label: "Within the last", min: 1, max: 90, unit: "days", text: (v) => plural(v, "day") },
};

const SECTIONS: { title: string; intro?: string; keys: NumberKey[] }[] = [
  { title: "Jobs", keys: ["globalMaxConcurrentInstalls", "jobDefaultExpiryHours", "runningJobTimeoutHours", "waitingForRebootExpiryDays", "deliveryLeaseMinutes", "maxDeliveryAttempts"] },
  { title: "Agents", keys: ["offlineThresholdMinutes", "credentialLifetimeDays", "credentialRotateBeforeDays"] },
  {
    title: "Keep for",
    intro: "EasyPatch deletes older records every 6 hours.",
    keys: ["retentionEventsDays", "retentionAuditDays", "retentionJobsDays", "retentionScansDays", "retentionHistoryDays"],
  },
];

const FEEDS: Record<string, { label: string; every: string }> = {
  kev: { label: "CISA known exploited vulnerabilities", every: "Every 6 hours" },
  msrc: { label: "Microsoft security updates", every: "Daily" },
  debian: { label: "Debian security tracker", every: "Daily" },
};

/** The brand line's text, as saved: trimmed, and null when empty. */
function brand(v: string | null): string | null {
  const t = (v ?? "").trim();
  return t === "" ? null : t;
}

function canon(s: PatchServerSettings): string {
  return JSON.stringify({ ...s, reportBrandName: brand(s.reportBrandName) });
}

/** What is wrong with a number, as EasyPatch would say it. */
function numberError(s: PatchServerSettings, key: NumberKey): string | null {
  const { min, max } = NUMBERS[key];
  const v = s[key];
  if (!Number.isInteger(v) || v < min || v > max) return `Choose from ${formatNumber(min)} to ${formatNumber(max)}.`;
  if (key === "credentialRotateBeforeDays" && v >= s.credentialLifetimeDays) return "Less than how long credentials last.";
  return null;
}

export function ServerSettingsPanel() {
  const view = useApi<PatchSettingsView>("/patching/settings");
  if (view.isPending) return <Spinner />;
  if (view.isError) return <ErrorState error={view.error} onRetry={() => void view.refetch()} />;
  // Remounted when the saved settings change, so the form starts from them.
  return <SettingsForm key={canon(view.data.settings)} view={view.data} />;
}

function SettingsForm({ view }: { view: PatchSettingsView }) {
  const toast = useToast();
  const { canEdit, readOnlyReason } = view;
  const base = view.settings;
  const [form, setForm] = useState<PatchServerSettings>(base);
  const save = useApiMutation((s: PatchServerSettings) => api.put<PatchSettingsView>("/patching/settings", s), {
    invalidate: ["/patching/settings"],
    onSuccess: () => toast.success("EasyPatch's settings saved."),
  });
  const dirty = canon(form) !== canon(base);
  const errors = Object.fromEntries((Object.keys(NUMBERS) as NumberKey[]).map((k) => [k, numberError(form, k)])) as Record<NumberKey, string | null>;
  const brandError = (form.reportBrandName ?? "").trim().length > 100 ? "At most 100 characters." : null;
  const blocked = Object.values(errors).some(Boolean) || brandError !== null;
  const set = (patch: Partial<PatchServerSettings>) => setForm((f) => ({ ...f, ...patch }));
  const err = (k: string) => fieldError(save.error, k);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!dirty || blocked || !canEdit) return;
    save.mutate({ ...form, reportBrandName: brand(form.reportBrandName) });
  }

  const number = (key: NumberKey) => (
    <SettingRow key={key} label={NUMBERS[key].label} hint={NUMBERS[key].hint} error={(dirty ? errors[key] : null) ?? err(key)}>
      {canEdit ? (
        <NumberInput
          label={NUMBERS[key].label}
          value={form[key]}
          min={NUMBERS[key].min}
          max={NUMBERS[key].max}
          unit={NUMBERS[key].unit}
          onChange={(v) => set({ [key]: v ?? Number.NaN })}
        />
      ) : (
        <span className="text-sm">{NUMBERS[key].text(base[key])}</span>
      )}
    </SettingRow>
  );
  const toggle = (key: "vulnerabilityFeedsEnabled" | "rolloutGuardEnabled", label: string, on: string, off: string) =>
    canEdit ? (
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" className="size-4 accent-accent" checked={form[key]} onChange={(e) => set({ [key]: e.target.checked })} />
        {label}
      </label>
    ) : (
      <span className="text-sm">{base[key] ? on : off}</span>
    );

  return (
    <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
      <p className="max-w-3xl text-sm text-muted">
        EasyPatch {view.version}. These settings are the same for every organization; patch policies set the rest, per organization,
        site, tag and device.
      </p>
      {readOnlyReason ? (
        <Alert tone="info">{readOnlyReason}</Alert>
      ) : (
        !canEdit && <Alert tone="info">Only super administrators change EasyPatch&apos;s server settings.</Alert>
      )}

      <Card title="Vulnerability data" padded={false}>
        <SettingRow
          label="Download vulnerability data"
          hint="To show which missing updates fix known and exploited vulnerabilities. Turn it off on a server without internet access."
          error={err("vulnerabilityFeedsEnabled")}
        >
          {toggle("vulnerabilityFeedsEnabled", "Download from Microsoft, CISA and Debian", "On", "Off")}
        </SettingRow>
        <Feeds feeds={view.feeds} enabled={base.vulnerabilityFeedsEnabled} />
      </Card>

      <Card title="Rollout guard" padded={false}>
        <p className="border-b border-line px-4 py-3 text-sm text-muted">
          Holds a Windows update for every organization when its installs fail too often, until someone releases the hold under
          Patching → Updates.
        </p>
        <SettingRow label="Hold failing updates" error={err("rolloutGuardEnabled")}>
          {toggle("rolloutGuardEnabled", "Hold a Windows update that fails", "On", "Off")}
        </SettingRow>
        {(canEdit ? form : base).rolloutGuardEnabled && (["rolloutGuardMinFailedEndpoints", "rolloutGuardFailurePercent", "rolloutGuardWindowDays"] as const).map(number)}
      </Card>

      <Card title="Monthly reports" padded={false}>
        <SettingRow label="Prepared by" hint="Your company's name on each monthly report. Leave it empty to leave the line out." error={brandError ?? err("reportBrandName")}>
          {canEdit ? (
            <Input
              aria-label="Prepared by"
              className="w-full max-w-sm"
              maxLength={100}
              value={form.reportBrandName ?? ""}
              placeholder="None"
              onChange={(e) => set({ reportBrandName: e.target.value })}
            />
          ) : (
            <span className="text-sm">{base.reportBrandName ?? <span className="text-subtle">None</span>}</span>
          )}
        </SettingRow>
        {number("retentionReportsMonths")}
      </Card>

      {SECTIONS.map((s) => (
        <Card key={s.title} title={s.title} padded={false}>
          {s.intro && <p className="border-b border-line px-4 py-3 text-sm text-muted">{s.intro}</p>}
          {s.keys.map(number)}
        </Card>
      ))}

      <InlineError error={save.error} fields={[...Object.keys(NUMBERS), "reportBrandName", "vulnerabilityFeedsEnabled", "rolloutGuardEnabled"]} />

      {canEdit && (
        // As the policy editor's: -bottom-5 and -mb-5 take the bar to the edge of the console's main area.
        <div className="sticky -bottom-5 z-10 -mx-1 -mb-5 flex flex-wrap items-center justify-end gap-2 border-t border-line bg-canvas/95 px-1 pt-3 pb-8 backdrop-blur-sm">
          <span className="mr-auto text-xs text-muted">
            {dirty ? (blocked ? "Correct the values marked above to save." : "Unsaved changes.") : "Saved."}
          </span>
          <Button onClick={() => setForm(base)} disabled={!dirty}>
            Discard changes
          </Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!dirty || blocked} icon={<Save className="size-4" aria-hidden />}>
            Save settings
          </Button>
        </div>
      )}
    </form>
  );
}

function SettingRow({ label, hint, error, children }: { label: string; hint?: ReactNode; error?: string | null; children: ReactNode }) {
  return (
    <div className="grid gap-x-6 gap-y-2 border-b border-line px-4 py-3 last:border-b-0 md:grid-cols-[minmax(0,17rem)_minmax(0,1fr)]">
      <div className="min-w-0">
        <p className="text-sm font-medium">{label}</p>
        {hint && <p className="mt-0.5 text-xs text-muted">{hint}</p>}
      </div>
      <div className="flex min-w-0 flex-col items-start gap-1 md:pt-0.5">
        {children}
        {error && <p className="text-xs text-danger">{error}</p>}
      </div>
    </div>
  );
}

function Feeds({ feeds, enabled }: { feeds: PatchVulnerabilityFeed[]; enabled: boolean }) {
  if (feeds.length === 0) {
    return (
      <p className="px-4 py-3 text-sm text-muted">
        {enabled ? "EasyPatch has not downloaded vulnerability data yet. Its worker starts within an hour." : "Nothing downloaded."}
      </p>
    );
  }
  return (
    <TableWrap className="rounded-none border-0">
      <table className="table-base">
        <caption className="sr-only">Vulnerability data downloads</caption>
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col">Last downloaded</th>
            <th scope="col" className="text-right">
              Entries
            </th>
            <th scope="col">State</th>
          </tr>
        </thead>
        <tbody>
          {feeds.map((f) => {
            const known = FEEDS[f.name];
            return (
              <tr key={f.name} className="align-top">
                <td>
                  {known?.label ?? f.name}
                  <span className="block text-xs text-muted">
                    {known?.every}
                    {f.version ? `${known ? ", " : ""}version ${f.version}` : ""}
                  </span>
                </td>
                <td className="whitespace-nowrap" title={f.lastSuccessAt ? formatDateTime(f.lastSuccessAt) : undefined}>
                  {f.lastSuccessAt ? formatRelative(f.lastSuccessAt) : <span className="text-subtle">Never</span>}
                </td>
                <td className="text-right tabular-nums">{formatNumber(f.itemCount)}</td>
                <td>
                  {f.lastError ? (
                    <>
                      <Badge tone="danger">Failed</Badge>
                      <span className="mt-1 block max-w-md text-xs break-words text-muted">
                        {f.lastAttemptAt ? `${formatRelative(f.lastAttemptAt)}: ` : ""}
                        {f.lastError}
                      </span>
                    </>
                  ) : !enabled ? (
                    <Badge tone="neutral">Off</Badge>
                  ) : f.lastSuccessAt ? (
                    <Badge tone="ok">Up to date</Badge>
                  ) : (
                    <Badge tone="neutral">Waiting</Badge>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableWrap>
  );
}
