import { useCallback, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { PackageMinus, PackagePlus, RefreshCw } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { Device, Job, SoftwareInput, SoftwareManager, SoftwareVerb } from "../../api/types";
import { DevicePicker, otherDevices } from "../../components/DevicePicker";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, InlineError, SelectField, TextField } from "../../components/ui";
import { plural } from "../../lib/format";
import { TimeoutField } from "../scripts/parts";
import { formatSeconds, LIMITS, PLATFORM_NAMES, WAIT_OPTIONS } from "../scripts/scriptText";
import { DEFAULT_SOFTWARE_TIMEOUT, MANAGER_ORDER, MANAGERS, managersFor, VERBS, VERSION_PATTERN } from "./softwareText";

const FIELDS = ["deviceIds", "action", "manager", "package", "version", "timeoutSeconds", "waitHours"];

export interface SoftwarePreset {
  deviceIds?: string[];
  action?: SoftwareVerb;
  manager?: SoftwareManager;
  package?: string;
  version?: string;
  timeoutSeconds?: number;
}

const ICONS: Record<SoftwareVerb, typeof PackagePlus> = { install: PackagePlus, upgrade: RefreshCw, uninstall: PackageMinus };

/**
 * Installs, updates or removes a package through a package manager
 * (ADR-0028). From a device page the device is fixed; elsewhere devices are
 * chosen. A preset fills it in, from a package row or an earlier job.
 */
export function SoftwareDialog({ open, onClose, device, preset }: {
  open: boolean;
  onClose: () => void;
  device?: Device;
  preset?: SoftwarePreset;
}) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="lg"
      title={preset?.action && preset.package ? `${VERBS[preset.action]} ${preset.package}` : "Install, update or remove software"}
      description={device ? `On ${device.name}, through its package manager.` : "Through each device's package manager. Choose the devices it runs on."}
    >
      <SoftwareForm onClose={onClose} device={device} preset={preset} />
    </Dialog>
  );
}

function SoftwareForm({ onClose, device, preset }: { onClose: () => void; device?: Device; preset?: SoftwarePreset }) {
  const navigate = useNavigate();
  const toast = useToast();
  const choices = device ? managersFor(device.platform) : MANAGER_ORDER;
  const [manager, setManager] = useState<SoftwareManager>(() => (preset?.manager && choices.includes(preset.manager) ? preset.manager : (choices[0] ?? "system")));
  const [action, setAction] = useState<SoftwareVerb>(preset?.action ?? "install");
  const [pkg, setPkg] = useState(preset?.package ?? "");
  const [version, setVersion] = useState(preset?.version ?? "");
  const [deviceIds, setDeviceIds] = useState<Set<string>>(() => new Set(device ? [device.id] : (preset?.deviceIds ?? [])));
  const [timeoutSeconds, setTimeoutSeconds] = useState(preset?.timeoutSeconds ?? DEFAULT_SOFTWARE_TIMEOUT);
  const [waitHours, setWaitHours] = useState(24);
  const [problems, setProblems] = useState<Record<string, string>>({});
  const info = MANAGERS[manager];

  const start = useApiMutation((input: SoftwareInput) => api.post<Job>("/jobs/software", input), {
    invalidate: ["/jobs", "/job-runs"],
    onSuccess: (job) => {
      toast.success(`Started ${job.scriptName} on ${plural(job.total, "device")}.`);
      onClose();
      navigate(`/jobs/${job.id}`);
    },
  });

  const err = (field: string) => problems[field] ?? fieldError(start.error, field);
  const edited = (field: string) =>
    setProblems((p) => {
      if (!(field in p)) return p;
      const { [field]: _gone, ...rest } = p;
      return rest;
    });

  const classify = useCallback((d: Device) => (d.platform === info.platform ? d.canManageSoftware : null), [info.platform]);

  function submit(e: FormEvent) {
    e.preventDefault();
    const name = pkg.trim();
    const ver = action === "install" ? version.trim() : "";
    const p: Record<string, string> = {};
    if (deviceIds.size === 0) p.deviceIds = "Choose at least one device.";
    if (deviceIds.size > LIMITS.devices) p.deviceIds = `Choose at most ${LIMITS.devices} devices for one job.`;
    if (name === "") p.package = "Enter the package's name.";
    else if (!info.pattern.test(name)) p.package = "Use the name exactly as the package manager writes it: letters, digits and punctuation such as . _ -, with no spaces.";
    if (ver !== "" && !VERSION_PATTERN.test(ver)) p.version = "Enter a version without spaces, such as 1.2.3.";
    if (timeoutSeconds < LIMITS.minTimeout || timeoutSeconds > LIMITS.maxTimeout) p.timeoutSeconds = "Use a timeout from 1 second to 4 hours.";
    setProblems(p);
    if (Object.keys(p).length > 0) return;
    start.mutate({ deviceIds: [...deviceIds], action, manager, package: name, ...(ver ? { version: ver } : {}), timeoutSeconds, waitHours });
  }

  const Icon = ICONS[action];
  const verb = VERBS[action];
  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-3.5">
      {choices.length > 1 && (
        <SelectField
          label="Package manager"
          value={manager}
          onChange={(e) => {
            const next = e.target.value as SoftwareManager;
            if (!device && MANAGERS[next].platform !== info.platform) setDeviceIds(new Set());
            setManager(next);
            edited("package");
            edited("deviceIds");
          }}
          error={err("manager")}
        >
          {choices.map((m) => (
            <option key={m} value={m}>
              {MANAGERS[m].label} ({PLATFORM_NAMES[MANAGERS[m].platform]})
            </option>
          ))}
        </SelectField>
      )}

      <fieldset>
        <legend className="mb-1.5 text-xs font-medium text-muted">Action</legend>
        <div className="flex flex-wrap gap-x-5 gap-y-2">
          {(Object.keys(VERBS) as SoftwareVerb[]).map((v) => (
            <label key={v} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="software-action"
                checked={action === v}
                onChange={() => {
                  setAction(v);
                  edited("version");
                }}
                className="size-4 accent-accent"
              />
              {VERBS[v]}
            </label>
          ))}
        </div>
        {err("action") && <p className="mt-1 text-xs text-danger">{err("action")}</p>}
      </fieldset>

      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-3">
        <TextField
          label="Package"
          required
          value={pkg}
          onChange={(e) => {
            setPkg(e.target.value);
            edited("package");
          }}
          error={err("package")}
          placeholder={info.example}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          className={action === "install" ? "sm:col-span-2 [&_input]:font-mono" : "sm:col-span-3 [&_input]:font-mono"}
          hint={info.hint}
        />
        {action === "install" && (
          <TextField
            label="Version"
            value={version}
            onChange={(e) => {
              setVersion(e.target.value);
              edited("version");
            }}
            error={err("version")}
            placeholder="Newest"
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            className="[&_input]:font-mono"
            hint="Leave empty for the newest."
          />
        )}
      </div>

      {!device && (
        <DevicePicker
          classify={classify}
          selected={deviceIds}
          onChange={(next) => {
            setDeviceIds(next);
            edited("deviceIds");
          }}
          error={err("deviceIds")}
          empty={{
            title: `No ${PLATFORM_NAMES[info.platform]} devices to choose from`,
            body: `${info.label} runs on ${PLATFORM_NAMES[info.platform]} devices with the EasyRMM agent, where your role manages software.`,
          }}
          excluded={(n) => {
            const o = otherDevices(n);
            return `${o.devices} running ${PLATFORM_NAMES[info.platform]} ${o.is} not listed: no EasyRMM agent, or your role does not manage software there.`;
          }}
        />
      )}
      {device && err("deviceIds") && <p className="text-xs text-danger">{err("deviceIds")}</p>}

      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
        <TimeoutField
          label="Timeout"
          value={timeoutSeconds}
          onChange={(v) => {
            setTimeoutSeconds(v);
            edited("timeoutSeconds");
          }}
          error={err("timeoutSeconds")}
          hint={`Large installers take a while; the default is ${formatSeconds(DEFAULT_SOFTWARE_TIMEOUT)}.`}
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

      <InlineError error={start.error} fields={FIELDS} />
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-3">
        {!device && <span className="mr-auto text-sm text-muted tabular-nums">{plural(deviceIds.size, "device")} selected</span>}
        <Button onClick={onClose} disabled={start.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant={action === "uninstall" ? "danger" : "primary"} loading={start.isPending} icon={<Icon className="size-4" aria-hidden />}>
          {!device && deviceIds.size > 0 ? `${verb} on ${plural(deviceIds.size, "device")}` : verb}
        </Button>
      </div>
    </form>
  );
}
