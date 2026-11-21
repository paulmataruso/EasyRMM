import { useState, type FormEvent } from "react";
import { ScanSearch } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { Device, HardeningInput, Job } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, InlineError, SelectField } from "../../components/ui";
import { WAIT_OPTIONS } from "../scripts/scriptText";
import { ModuleChooser } from "./hardeningParts";
import { MODULES, RECOMMENDED } from "./hardeningText";

const FIELDS = ["modules", "waitHours"];

/**
 * Checks a device's hardening (ADR-0051): the chosen modules report what is in place and what applying them would
 * change. A check changes nothing. The recommended modules are chosen to begin with.
 */
export function HardeningCheckDialog({ open, onClose, device }: { open: boolean; onClose: () => void; device: Device }) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="lg"
      title="Check hardening"
      description={`On ${device.name}. A check changes nothing: it reports what is in place, and what applying each module would change.`}
    >
      <CheckForm onClose={onClose} device={device} />
    </Dialog>
  );
}

function CheckForm({ onClose, device }: { onClose: () => void; device: Device }) {
  const toast = useToast();
  const [modules, setModules] = useState<Set<string>>(() => new Set(RECOMMENDED));
  const [waitHours, setWaitHours] = useState(24);
  const [problem, setProblem] = useState<string | null>(null);
  const start = useApiMutation((input: HardeningInput) => api.post<Job>("/jobs/hardening", input), {
    invalidate: ["/jobs", "/job-runs"],
    onSuccess: () => {
      toast.success(`Checking hardening on ${device.name}. The findings show here when the agent reports.`);
      onClose();
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (modules.size === 0) {
      setProblem("Choose at least one module.");
      return;
    }
    // In the order the script runs them, as the server keeps them.
    const chosen = MODULES.filter((m) => modules.has(m.id)).map((m) => m.id);
    start.mutate({ deviceIds: [device.id], mode: "check", modules: chosen, options: {}, waitHours });
  }

  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-3.5">
      <ModuleChooser
        selected={modules}
        onChange={(next) => {
          setModules(next);
          setProblem(null);
        }}
        error={problem ?? fieldError(start.error, "modules")}
        optionalHint="Checking them is as safe as checking the others: a check changes nothing. Their risk is in applying them."
      />
      <SelectField
        label="Wait for the device"
        value={String(waitHours)}
        onChange={(e) => setWaitHours(Number(e.target.value))}
        error={fieldError(start.error, "waitHours")}
        hint="If the device is offline, the check waits this long for it, then is marked expired."
        className="sm:max-w-xs"
      >
        {WAIT_OPTIONS.map(([h, label]) => (
          <option key={h} value={h}>
            {label}
          </option>
        ))}
      </SelectField>
      <InlineError error={start.error} fields={FIELDS} />
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-3">
        <span className="mr-auto text-sm text-muted tabular-nums">
          {modules.size} of {MODULES.length} modules
        </span>
        <Button onClick={onClose} disabled={start.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={start.isPending} icon={<ScanSearch className="size-4" aria-hidden />}>
          Run check
        </Button>
      </div>
    </form>
  );
}
