import { useEffect, useId, useState, type FormEvent } from "react";
import { api, fieldError } from "../../api/client";
import { useApiMutation, useOrganizations, useSites } from "../../api/hooks";
import type { AlertKind, AlertPolicy, AlertPolicyInput, AlertSeverity, DiskCheck, ScriptLevel } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, cx, Field, InlineError, Input, KeyValueList, Segmented, Select, SelectField, TextareaField, TextField } from "../../components/ui";
import { plural } from "../../lib/format";
import { CHECK_NAMES, CHECKS, conditionText, KIND_NAMES, KINDS, policyScope, POLICY_LIMITS } from "./alertText";

const FIELDS = ["name", "description", "kind", "checkName", "threshold", "minutes", "severity", "organizationId", "siteId"];

const SEVERITIES: { value: AlertSeverity; label: string }[] = [
  { value: "warning", label: "Warning" },
  { value: "critical", label: "Critical" },
];

const DEFAULT_THRESHOLD: Record<AlertKind, number> = { offline: 0, cpu: 95, memory: 95, disk: 90, disk_health: 0 };

/** Each disk health check's threshold when chosen: the shared policies' defaults (ADR-0065, "Alerts"); 60 °C when a
 * temperature check is given one instead of each drive's own limit. */
const CHECK_THRESHOLD: Record<DiskCheck, number> = { failing: 0, errors: 1, pending: 1, wear: 90, temperature: 60 };

/** What a disk health check's threshold counts, beside its field. */
const CHECK_UNITS: Record<DiskCheck, string> = { failing: "", errors: "sectors and errors", pending: "sectors", wear: "% used", temperature: "°C" };

/** The server's words for a threshold out of range (monitoring/policies.go). */
const CHECK_RANGE: Record<DiskCheck, string> = {
  failing: "",
  errors: "Use a count from 1 to 100.",
  pending: "Use a count from 1 to 100.",
  wear: "Use a percentage from 1 to 100.",
  temperature: "Use 1 to 100 °C, or the drive's own limit.",
};

/** What a disk health check watches, and when its alert resolves. */
function checkHelp(check: DiskCheck, driveLimit: boolean): string {
  switch (check) {
    case "failing":
      return "The drive's own verdict: SMART status threshold exceeded, a pre-fail attribute at or below its threshold, or an NVMe critical warning about its spare, reliability, read-only media or volatile memory backup. One alert per disk; it resolves after two readings that are not failing.";
    case "errors":
      return "Reallocated sectors plus NVMe media errors, 1 to 100. These counts only rise, so the alert stays until the disk is replaced or the threshold is raised: acknowledge it rather than resolve it.";
    case "pending":
      return "Pending plus offline-uncorrectable sectors, 1 to 100. These fall again as the drive reallocates or reads them; the alert resolves after two readings below the threshold.";
    case "wear":
      return "The percentage of its rated endurance a disk has used, 1 to 100. Wear only rises, so the alert stays until the disk is replaced or the threshold is raised: acknowledge it rather than resolve it.";
    case "temperature":
      return driveLimit
        ? "Every reading in that time, at least two, at or over each drive's own temperature limit; a drive that reports no limit is not checked. It resolves after two readings 5 °C below the limit. Disks are read every 30 minutes: 30 to 1,440 minutes."
        : "Every reading in that time, at least two, at or above the temperature. It resolves after two readings 5 °C below it. Disks are read every 30 minutes: 30 to 1,440 minutes.";
  }
}

/** "a disk's own verdict is failing": a condition in the middle of a sentence, its units kept as they are. */
const lowerFirst = (s: string) => (s ? s[0]!.toLowerCase() + s.slice(1) : s);

/** Whether the caller can write policies somewhere, so the page offers "New policy". */
export function useCanWritePolicies(): boolean {
  const { can, session } = useAuth();
  return session?.isSuperAdmin === true || can("monitoring.manage");
}

/** Adds a policy, or edits or deletes one. */
export function PolicyDialog({ open, onClose, policy }: { open: boolean; onClose: () => void; policy?: AlertPolicy }) {
  const { session } = useAuth();
  const toast = useToast();
  const orgs = useOrganizations();
  const superAdmin = session?.isSuperAdmin === true;
  const levelId = useId();
  const thresholdId = useId();
  const minutesId = useId();
  const severityId = useId();

  const [level, setLevel] = useState<ScriptLevel>("organization");
  const [organizationId, setOrganizationId] = useState("");
  const [siteId, setSiteId] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [kind, setKind] = useState<AlertKind>("cpu");
  const [checkName, setCheckName] = useState<DiskCheck>("failing");
  // A temperature check without a threshold uses each drive's own limit.
  const [driveLimit, setDriveLimit] = useState(true);
  const [threshold, setThreshold] = useState("95");
  const [minutes, setMinutes] = useState("15");
  const [severity, setSeverity] = useState<AlertSeverity>("warning");
  const [enabled, setEnabled] = useState(true);
  const [missing, setMissing] = useState<Record<string, string>>({});
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLevel(superAdmin ? "shared" : "organization");
    setOrganizationId("");
    setSiteId("");
    setName(policy?.name ?? "");
    setDescription(policy?.description ?? "");
    const k = policy?.kind ?? "cpu";
    const check = policy?.checkName ?? "failing";
    setKind(k);
    setCheckName(check);
    setDriveLimit(k !== "disk_health" || check !== "temperature" || policy?.threshold === null);
    setThreshold(String(policy?.threshold ?? (k === "disk_health" ? CHECK_THRESHOLD[check] : DEFAULT_THRESHOLD[k])));
    setMinutes(String(policy?.minutes ?? 15));
    setSeverity(policy?.severity ?? "warning");
    setEnabled(policy?.enabled ?? true);
    setMissing({});
  }, [open, policy, superAdmin]);

  const sites = useSites(open && level === "site" && organizationId ? organizationId : null);
  const writableOrgs = orgs.items.filter((o) => level === "site" || o.canManage);
  const writableSites = sites.items.filter((s) => s.canManage);
  const noOrgLevel = !orgs.isPending && !orgs.items.some((o) => o.canManage);

  const save = useApiMutation(
    (input: AlertPolicyInput) =>
      policy
        ? api.patch<AlertPolicy>(`/alert-policies/${policy.id}`, {
            name: input.name,
            description: input.description,
            kind: input.kind,
            ...(input.kind === "disk_health" && { checkName: input.checkName }),
            threshold: input.threshold,
            // A change leaves out a null threshold, so the drive's own limit is asked for by name.
            ...(input.kind === "disk_health" && input.checkName === "temperature" && input.threshold === null && { driveLimit: true }),
            minutes: input.minutes,
            severity: input.severity,
            enabled: input.enabled,
          })
        : api.post<AlertPolicy>("/alert-policies", input),
    {
      invalidate: ["/alert-policies", "/alerts", "/audit"],
      onSuccess: (p) => {
        toast.success(policy ? `Saved ${p.name}.` : `Added ${p.name}. It is checked every minute.`);
        onClose();
      },
    },
  );
  const remove = useApiMutation(() => api.del(`/alert-policies/${policy?.id ?? ""}`), {
    invalidate: ["/alert-policies", "/alerts", "/audit"],
    onSuccess: () => {
      toast.success(`Deleted ${policy?.name ?? "the policy"}.`);
      setConfirmDelete(false);
      onClose();
    },
  });
  useEffect(() => {
    if (open) {
      save.reset();
      remove.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const edited = (field: string) =>
    setMissing((m) => {
      if (!(field in m)) return m;
      const { [field]: _gone, ...rest } = m;
      return rest;
    });
  const err = (field: string) => missing[field] ?? fieldError(save.error, field);

  const offline = kind === "offline";
  const diskHealth = kind === "disk_health";
  const temperature = diskHealth && checkName === "temperature";
  // Offline and the failing check take no threshold; a temperature check none when it uses each drive's own limit.
  const noThreshold = offline || (diskHealth && (checkName === "failing" || (temperature && driveLimit)));
  // Disk checks other than temperature take the reading interval as their minutes.
  const showMinutes = !diskHealth || temperature;
  const thresholdN = Number(threshold);
  const minutesN = Number(minutes);
  const minMinutes = offline ? POLICY_LIMITS.minOfflineMinutes : temperature ? POLICY_LIMITS.minDiskMinutes : 1;
  const validThreshold = noThreshold || (Number.isInteger(thresholdN) && thresholdN >= 1 && thresholdN <= 100);
  const validMinutes = !showMinutes || (Number.isInteger(minutesN) && minutesN >= minMinutes && minutesN <= POLICY_LIMITS.maxMinutes);
  const sentThreshold = noThreshold ? null : thresholdN;
  const sentMinutes = showMinutes ? minutesN : POLICY_LIMITS.minDiskMinutes;

  /** Chooses a disk health check, with its default threshold (and an hour for a temperature check). */
  function chooseCheck(c: DiskCheck) {
    setCheckName(c);
    setThreshold(String(CHECK_THRESHOLD[c]));
    if (c === "temperature") {
      setDriveLimit(true);
      if (!(Number(minutes) >= POLICY_LIMITS.minDiskMinutes)) setMinutes("60");
    }
    edited("checkName");
    edited("threshold");
    edited("minutes");
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    const m: Record<string, string> = {};
    if (!name.trim()) m.name = "Enter a name.";
    if (!validThreshold) m.threshold = diskHealth ? CHECK_RANGE[checkName] : "Use a whole percentage from 1 to 100.";
    if (!validMinutes) m.minutes = `Use ${minMinutes} to 1,440 minutes.`;
    if (!policy && level !== "shared" && !organizationId) m.organizationId = "Choose an organization.";
    if (!policy && level === "site" && !siteId) m.siteId = "Choose a site.";
    setMissing(m);
    if (Object.keys(m).length > 0) return;
    save.mutate({
      organizationId: level === "shared" ? null : organizationId,
      siteId: level === "site" ? siteId : null,
      name: name.trim(),
      description: description.trim(),
      kind,
      ...(diskHealth && { checkName }),
      threshold: sentThreshold,
      minutes: sentMinutes,
      severity,
      enabled,
    });
  }

  const thresholdField = (label: string, unit: string) => (
    <Field label={label} htmlFor={thresholdId} error={err("threshold")}>
      <div className="flex items-center gap-1.5">
        <Input
          id={thresholdId}
          type="number"
          inputMode="numeric"
          min={1}
          max={100}
          step={1}
          value={threshold}
          aria-invalid={err("threshold") ? true : undefined}
          onChange={(e) => {
            setThreshold(e.target.value);
            edited("threshold");
          }}
          className="w-20 tabular-nums"
        />
        <span className="text-sm whitespace-nowrap text-muted">{unit}</span>
      </div>
    </Field>
  );
  const minutesField = (
    <Field label={offline ? "Without a check-in for" : "For"} htmlFor={minutesId} error={err("minutes")}>
      <div className="flex items-center gap-1.5">
        <Input
          id={minutesId}
          type="number"
          inputMode="numeric"
          min={minMinutes}
          max={POLICY_LIMITS.maxMinutes}
          step={1}
          value={minutes}
          aria-invalid={err("minutes") ? true : undefined}
          onChange={(e) => {
            setMinutes(e.target.value);
            edited("minutes");
          }}
          className="w-20 tabular-nums"
        />
        <span className="text-sm text-muted">minutes</span>
      </div>
    </Field>
  );

  const scope = policy
    ? policyScope(policy)
    : level === "shared"
      ? "Every device"
      : (level === "site" ? sites.items.find((s) => s.id === siteId)?.name : orgs.items.find((o) => o.id === organizationId)?.name) ?? null;
  const summary =
    validThreshold && validMinutes
      ? `${enabled ? "Raises" : "Once turned on, raises"} a ${severity} alert ${scope ? `on ${scope === "Every device" ? "any device" : `a device in ${scope}`} ` : ""}when: ${lowerFirst(conditionText({ kind, checkName, threshold: sentThreshold, minutes: sentMinutes }))}.`
      : null;

  return (
    <>
      <Dialog
        open={open && !confirmDelete}
        onClose={onClose}
        title={policy ? `Edit ${policy.name}` : "New alert policy"}
        description={policy ? undefined : "Checked every minute against the devices it covers."}
      >
        <form onSubmit={submit} noValidate className="flex flex-col gap-3.5">
          <TextField
            label="Name"
            required
            value={name}
            maxLength={POLICY_LIMITS.name}
            onChange={(e) => {
              setName(e.target.value);
              edited("name");
            }}
            error={err("name")}
            autoFocus
          />
          {policy ? (
            <KeyValueList narrow items={[["Applies to", <span key="s">{policyScope(policy)}</span>]]} />
          ) : (
            <div className="flex flex-col gap-3">
              <Field label="Applies to" htmlFor={levelId}>
                <Select
                  id={levelId}
                  value={level}
                  onChange={(e) => {
                    setLevel(e.target.value as ScriptLevel);
                    setOrganizationId("");
                    setSiteId("");
                  }}
                >
                  {superAdmin && <option value="shared">Every device</option>}
                  <option value="organization" disabled={noOrgLevel}>
                    One organization's devices
                  </option>
                  <option value="site">One site's devices</option>
                </Select>
              </Field>
              {level !== "shared" && (
                <div className="flex flex-wrap gap-3">
                  <SelectField
                    label="Organization"
                    required
                    value={organizationId}
                    onChange={(e) => {
                      setOrganizationId(e.target.value);
                      setSiteId("");
                      edited("organizationId");
                    }}
                    error={err("organizationId")}
                    disabled={orgs.isPending}
                    className="min-w-44 flex-1"
                  >
                    <option value="">Choose…</option>
                    {writableOrgs.map((o) => (
                      <option key={o.id} value={o.id}>
                        {o.name}
                      </option>
                    ))}
                  </SelectField>
                  {level === "site" && (
                    <SelectField
                      label="Site"
                      required
                      value={siteId}
                      onChange={(e) => {
                        setSiteId(e.target.value);
                        edited("siteId");
                      }}
                      error={err("siteId")}
                      disabled={!organizationId || sites.isPending}
                      className="min-w-44 flex-1"
                    >
                      <option value="">{organizationId && !sites.isPending && writableSites.length === 0 ? "No sites you manage" : "Choose…"}</option>
                      {writableSites.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name}
                        </option>
                      ))}
                    </SelectField>
                  )}
                </div>
              )}
            </div>
          )}

          <div className={cx("grid grid-cols-1 gap-3", diskHealth ? "sm:grid-cols-2" : "sm:grid-cols-[minmax(0,1fr)_auto_auto]")}>
            <SelectField
              label="Watch for"
              value={kind}
              onChange={(e) => {
                const k = e.target.value as AlertKind;
                setKind(k);
                if (k === "disk_health") {
                  if (kind !== "disk_health") chooseCheck(checkName);
                } else if (kind === "offline" || kind === "disk_health") {
                  setThreshold(String(DEFAULT_THRESHOLD[k]));
                }
                edited("threshold");
                edited("minutes");
              }}
              error={err("kind")}
            >
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_NAMES[k]}
                </option>
              ))}
            </SelectField>
            {diskHealth ? (
              <SelectField label="Check" value={checkName} onChange={(e) => chooseCheck(e.target.value as DiskCheck)} error={err("checkName")}>
                {CHECKS.map((c) => (
                  <option key={c} value={c}>
                    {CHECK_NAMES[c]}
                  </option>
                ))}
              </SelectField>
            ) : (
              <>
                {!offline && thresholdField("At or above", "%")}
                {minutesField}
              </>
            )}
          </div>
          {diskHealth && checkName !== "failing" && (
            <div className="flex flex-wrap items-start gap-3">
              {temperature && (
                <SelectField
                  label="At or above"
                  value={driveLimit ? "limit" : "degrees"}
                  onChange={(e) => {
                    setDriveLimit(e.target.value === "limit");
                    edited("threshold");
                  }}
                >
                  <option value="limit">The drive's own limit</option>
                  <option value="degrees">A temperature</option>
                </SelectField>
              )}
              {!noThreshold && thresholdField(temperature ? "Temperature" : "At or above", CHECK_UNITS[checkName])}
              {temperature && minutesField}
            </div>
          )}
          <p className="-mt-1.5 text-xs text-muted">
            {offline
              ? "A device is checked in while its EasyRMM agent or MeshAgent is connected. 3 to 1,440 minutes."
              : diskHealth
                ? checkHelp(checkName, driveLimit)
                : `Every measurement in that time must reach the percentage${kind === "disk" ? " on the fullest filesystem" : ""}, and the alert resolves after 5 quiet minutes. 1 to 1,440 minutes.`}
          </p>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span id={severityId} className="text-sm font-medium">
                Severity
              </span>
              <Segmented label="Severity" options={SEVERITIES} value={severity} onChange={setSeverity} />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="size-4 accent-accent" />
              Turned on
            </label>
          </div>

          <TextareaField
            label="Description"
            value={description}
            maxLength={POLICY_LIMITS.description}
            onChange={(e) => setDescription(e.target.value)}
            error={err("description")}
            hint="What to check when it fires. Shown in the policy list."
            rows={2}
          />

          {summary && (
            <p className="rounded-md bg-raised px-3 py-2 text-sm text-fg" aria-live="polite">
              {summary}
            </p>
          )}

          <InlineError error={save.error} fields={FIELDS} />
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div>
              {policy?.canEdit && (
                <Button variant="danger-ghost" onClick={() => setConfirmDelete(true)}>
                  Delete policy
                </Button>
              )}
            </div>
            <div className="flex gap-2">
              <Button onClick={onClose}>Cancel</Button>
              <Button type="submit" variant="primary" loading={save.isPending}>
                {policy ? "Save changes" : "Add policy"}
              </Button>
            </div>
          </div>
        </form>
      </Dialog>
      {policy && (
        <ConfirmDialog
          open={open && confirmDelete}
          onClose={() => setConfirmDelete(false)}
          onConfirm={() => remove.mutate()}
          title={`Delete ${policy.name}?`}
          confirmLabel="Delete policy"
          tone="danger"
          loading={remove.isPending}
          error={remove.error}
        >
          {policy.activeAlerts > 0
            ? `Its ${plural(policy.activeAlerts, "active alert")} resolve now. Resolved alerts keep its name.`
            : "Alerts it raised before keep its name."}
        </ConfirmDialog>
      )}
    </>
  );
}
