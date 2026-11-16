import { useId, useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { Play } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation, useList } from "../../api/hooks";
import type { Device, Job, JobInput, Script } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, cx, Dot, EmptyState, ErrorState, Field, InlineError, Input, SelectField, Spinner, TextareaField } from "../../components/ui";
import { plural } from "../../lib/format";
import { TimeoutField } from "./parts";
import {
  cannotRunReason,
  formatSeconds,
  LIMITS,
  parseArgs,
  PLATFORM_NAMES,
  scriptCovers,
  SHELL_NAMES,
  SHELL_PLATFORM,
  utf8Length,
  WAIT_OPTIONS,
} from "./scriptText";

const FIELDS = ["scriptId", "deviceIds", "args", "timeoutSeconds", "waitHours"];

export interface RunPreset {
  deviceIds?: string[];
  args?: string[];
  timeoutSeconds?: number;
  /** The script's hash when the preset's job ran, to say when it has changed since. */
  sha256?: string;
}

/**
 * Starts a job. From a script page the script is fixed and devices are chosen; from a device page the device is fixed
 * and a script is chosen. A preset fills it in again from an earlier job.
 */
export function RunScriptDialog({ open, onClose, script, device, preset }: {
  open: boolean;
  onClose: () => void;
  script?: Script;
  device?: Device;
  preset?: RunPreset;
}) {
  // The dialog mounts its body only while open, so each opening starts a fresh form.
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="lg"
      title={script ? `Run ${script.name}` : "Run a script"}
      description={device ? `On ${device.name}.` : "Choose the devices to run it on."}
    >
      <RunForm onClose={onClose} script={script} device={device} preset={preset} />
    </Dialog>
  );
}

function RunForm({ onClose, script: fixedScript, device, preset }: { onClose: () => void; script?: Script; device?: Device; preset?: RunPreset }) {
  const navigate = useNavigate();
  const toast = useToast();
  const formId = useId();
  const scripts = useList<Script>(fixedScript ? null : "/scripts", device ? { deviceId: device.id } : undefined);
  const runnable = scripts.items.filter((s) => s.canRun);
  const [scriptId, setScriptId] = useState(fixedScript?.id ?? "");
  const script = fixedScript ?? runnable.find((s) => s.id === scriptId);

  const [deviceIds, setDeviceIds] = useState<Set<string>>(() => new Set(device ? [device.id] : (preset?.deviceIds ?? [])));
  const [argsText, setArgsText] = useState(() => (preset?.args ?? []).join("\n"));
  const [timeoutSeconds, setTimeoutSeconds] = useState(preset?.timeoutSeconds ?? fixedScript?.timeoutSeconds ?? 0);
  const [waitHours, setWaitHours] = useState(24);
  const [problems, setProblems] = useState<Record<string, string>>({});

  const run = useApiMutation((input: JobInput) => api.post<Job>("/jobs", input), {
    invalidate: ["/jobs", "/job-runs"],
    onSuccess: (job) => {
      toast.success(`Started ${job.scriptName} on ${plural(job.total, "device")}.`);
      onClose();
      navigate(`/jobs/${job.id}`);
    },
  });

  const args = parseArgs(argsText);
  const err = (field: string) => problems[field] ?? fieldError(run.error, field);
  /** A field's own complaint goes once it is edited. */
  const edited = (field: string) =>
    setProblems((p) => {
      if (!(field in p)) return p;
      const { [field]: _gone, ...rest } = p;
      return rest;
    });

  function submit(e: FormEvent) {
    e.preventDefault();
    const p: Record<string, string> = {};
    if (!script) p.scriptId = "Choose a script.";
    if (deviceIds.size === 0) p.deviceIds = "Choose at least one device.";
    if (deviceIds.size > LIMITS.devices) p.deviceIds = `Choose at most ${LIMITS.devices} devices for one job.`;
    if (args.length > LIMITS.args) p.args = `Use at most ${LIMITS.args} arguments.`;
    const long = args.findIndex((a) => utf8Length(a) > LIMITS.argBytes);
    if (long >= 0) p.args = `Argument ${long + 1} is longer than 1 KiB.`;
    if (timeoutSeconds < LIMITS.minTimeout || timeoutSeconds > LIMITS.maxTimeout) p.timeoutSeconds = "Use a timeout from 1 second to 4 hours.";
    setProblems(p);
    if (Object.keys(p).length > 0 || !script) return;
    run.mutate({ scriptId: script.id, deviceIds: [...deviceIds], args, timeoutSeconds, waitHours });
  }

  const changed = preset?.sha256 && script && preset.sha256 !== script.sha256;

  return (
    <form id={formId} onSubmit={submit} noValidate className="flex flex-col gap-3.5">
      {changed && (
        <Alert tone="info" title="The script has changed since that job">
          This runs the library&rsquo;s current version.
        </Alert>
      )}
      {!fixedScript &&
        (scripts.isPending ? (
          <Spinner label="Loading scripts…" className="py-4" />
        ) : scripts.isError ? (
          <ErrorState error={scripts.error} onRetry={() => void scripts.refetch()} compact />
        ) : runnable.length === 0 ? (
          <EmptyState title="No scripts can run here" compact>
            The library has no script you may run on this device.{" "}
            <Link to="/scripts" className="text-accent hover:underline">
              Open the library
            </Link>
          </EmptyState>
        ) : (
          <SelectField
            label="Script"
            required
            value={scriptId}
            error={err("scriptId")}
            onChange={(e) => {
              edited("scriptId");
              setScriptId(e.target.value);
              setTimeoutSeconds(runnable.find((s) => s.id === e.target.value)?.timeoutSeconds ?? 0);
            }}
            hint={script ? scriptSummary(script) : undefined}
          >
            <option value="">Choose…</option>
            {runnable.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </SelectField>
        ))}
      {fixedScript && fixedScript.description && <p className="text-sm text-muted">{fixedScript.description}</p>}

      {fixedScript && !device && <DevicePicker
          script={fixedScript}
          selected={deviceIds}
          onChange={(next) => {
            setDeviceIds(next);
            edited("deviceIds");
          }}
          error={err("deviceIds")}
        />}
      {device && err("deviceIds") && <p className="text-xs text-danger">{err("deviceIds")}</p>}

      {script && (
        <>
          <TextareaField
            label="Arguments"
            value={argsText}
            onChange={(e) => {
              setArgsText(e.target.value);
              edited("args");
            }}
            error={err("args")}
            rows={3}
            spellCheck={false}
            autoCapitalize="off"
            className="[&_textarea]:font-mono [&_textarea]:text-xs"
            hint="One per line, passed exactly as typed. Arguments are kept with the job and shown to everyone who can see it, so never use them for passwords."
          />
          <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
            <TimeoutField
              key={script.id}
              label="Timeout"
              value={timeoutSeconds || script.timeoutSeconds}
              onChange={(v) => {
                setTimeoutSeconds(v);
                edited("timeoutSeconds");
              }}
              error={err("timeoutSeconds")}
              hint={`The script's default is ${formatSeconds(script.timeoutSeconds)}.`}
            />
            <SelectField
              label="Wait for offline devices"
              value={String(waitHours)}
              onChange={(e) => setWaitHours(Number(e.target.value))}
              error={err("waitHours")}
              hint="A device that does not come online in time is marked expired."
            >
              {WAIT_OPTIONS.map(([h, label]) => (
                <option key={h} value={h}>
                  {label}
                </option>
              ))}
            </SelectField>
          </div>
        </>
      )}

      <InlineError error={run.error} fields={FIELDS} />
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-3">
        {fixedScript && !device && <span className="mr-auto text-sm text-muted tabular-nums">{plural(deviceIds.size, "device")} selected</span>}
        <Button onClick={onClose} disabled={run.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={run.isPending} icon={<Play className="size-4" aria-hidden />} disabled={!script}>
          {device ? "Run" : deviceIds.size > 0 ? `Run on ${plural(deviceIds.size, "device")}` : "Run"}
        </Button>
      </div>
    </form>
  );
}

function scriptSummary(s: Script): string {
  return [s.description, `${SHELL_NAMES[s.shell]}, stops after ${formatSeconds(s.timeoutSeconds)}.`].filter(Boolean).join(" ");
}

/** The devices a script can run on, to choose from. */
function DevicePicker({ script, selected, onChange, error }: {
  script: Script;
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  error: string | null;
}) {
  const devices = useList<Device>("/devices");
  const [query, setQuery] = useState("");
  const searchId = useId();
  const listId = useId();

  const { eligible, excluded } = useMemo(() => {
    const covered = devices.items.filter((d) => scriptCovers(script, d));
    return {
      eligible: covered.filter((d) => cannotRunReason(d, script.shell) === null),
      excluded: covered.filter((d) => cannotRunReason(d, script.shell) !== null).length,
    };
  }, [devices.items, script]);
  const q = query.trim().toLowerCase();
  const shown = q
    ? eligible.filter((d) => [d.name, d.hostname, d.organizationName, d.siteName].some((v) => v.toLowerCase().includes(q)))
    : eligible;
  const shownSelected = shown.filter((d) => selected.has(d.id)).length;
  const allShown = shown.length > 0 && shownSelected === shown.length;

  function toggle(id: string, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(id);
    else next.delete(id);
    onChange(next);
  }

  if (devices.isPending) return <Spinner label="Loading devices…" className="py-4" />;
  if (devices.isError) return <ErrorState error={devices.error} onRetry={() => void devices.refetch()} compact />;
  if (eligible.length === 0) {
    return (
      <EmptyState title="No devices can run this script" compact>
        It runs on {PLATFORM_NAMES[SHELL_PLATFORM[script.shell]]} devices with the EasyRMM agent
        {script.level === "shared" ? "" : ` in ${script.level === "site" ? "its site" : "its organization"}`}, where your role runs scripts.
      </EmptyState>
    );
  }

  return (
    <Field label="Devices" htmlFor={searchId} required error={error}>
      <div className={cx("rounded-md border bg-surface", error ? "border-danger" : "border-line")}>
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-2">
          <Input
            id={searchId}
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by name, organization or site"
            aria-controls={listId}
            className="min-w-48 flex-1"
          />
          <label className="flex items-center gap-2 px-1 text-sm whitespace-nowrap">
            <input
              type="checkbox"
              checked={allShown}
              ref={(el) => {
                if (el) el.indeterminate = shownSelected > 0 && !allShown;
              }}
              onChange={(e) => {
                const next = new Set(selected);
                for (const d of shown) {
                  if (e.target.checked) next.add(d.id);
                  else next.delete(d.id);
                }
                onChange(next);
              }}
              disabled={shown.length === 0}
            />
            {q ? `All ${shown.length.toLocaleString()} shown` : "All"}
          </label>
        </div>
        <ul id={listId} aria-label="Devices" className="max-h-64 divide-y divide-line overflow-y-auto">
          {shown.length === 0 && <li className="px-3 py-3 text-sm text-muted">No devices match “{query.trim()}”.</li>}
          {shown.map((d) => (
            <li key={d.id}>
              <label className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-hover">
                <input type="checkbox" checked={selected.has(d.id)} onChange={(e) => toggle(d.id, e.target.checked)} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{d.name}</span>
                  <span className="block truncate text-xs text-muted">
                    {d.organizationName} / {d.siteName}
                  </span>
                </span>
                <span className="flex shrink-0 items-center gap-1.5 text-xs text-muted">
                  <Dot tone={d.online ? "ok" : "neutral"} />
                  {d.online ? "Online" : "Offline"}
                </span>
              </label>
            </li>
          ))}
        </ul>
      </div>
      {excluded > 0 && (
        <p className="text-xs text-subtle">
          {plural(excluded, "other device")} where it could run {excluded === 1 ? "is" : "are"} not listed: no EasyRMM agent, not Linux, or your role does not run
          scripts there.
        </p>
      )}
    </Field>
  );
}
