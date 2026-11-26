import { useMemo, useState, type FormEvent } from "react";
import { ScanSearch, ShieldCheck, Undo2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { Device, HardeningInput, HardeningOptions, Job, WindowsCatalogModule } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, InlineError, TextField } from "../../components/ui";
import { tierMeta, windowsModule } from "./windowsText";

/** What the dialog is about: a check, or a change by modules or by single settings. */
export interface WindowsChange {
  mode: "check" | "apply" | "undo";
  /** The modules, or for single settings the modules left empty with the settings' IDs. */
  modules?: string[];
  settings?: string[];
}

const FIELDS = ["confirm.agreed", "confirm.typed", "deviceIds", "modules", "settings", "options"];

/** The highest tier of what the change touches, as the server judges it (jobs.Hardening.windowsTier). */
export function changeTier(catalog: WindowsCatalogModule[], change: WindowsChange): number {
  let tier = 0;
  for (const m of catalog) {
    for (const s of m.settings) {
      const chosen = change.settings ? change.settings.includes(s.id) : change.modules?.includes(m.id);
      if (chosen) tier = Math.max(tier, s.tier);
    }
  }
  return tier;
}

/**
 * Checks, applies or undoes Windows hardening on one computer (ADR-0054, W3). An apply or undo needs the person's
 * agreement; a change that can cut access also needs the computer's name typed, and the server then asks for a second
 * factor (the console's step-up dialog), which is why that is not asked here. After an apply the computer undoes the
 * change by itself unless the agent confirms within ten minutes.
 */
export function WindowsChangeDialog({ change, device, catalog, onClose }: {
  change: WindowsChange | null;
  device: Device;
  catalog: WindowsCatalogModule[];
  onClose: () => void;
}) {
  const title = change?.mode === "check" ? "Check hardening" : change?.mode === "undo" ? "Undo hardening" : "Apply hardening";
  return (
    <Dialog open={change !== null} onClose={onClose} size="lg" title={title} description={`On ${device.name}.`}>
      {change && <Form change={change} device={device} catalog={catalog} onClose={onClose} />}
    </Dialog>
  );
}

function Form({ change, device, catalog, onClose }: { change: WindowsChange; device: Device; catalog: WindowsCatalogModule[]; onClose: () => void }) {
  const toast = useToast();
  const [agreed, setAgreed] = useState(false);
  const [typed, setTyped] = useState("");
  const [options, setOptions] = useState<HardeningOptions>({});
  const tier = useMemo(() => changeTier(catalog, change), [catalog, change]);
  const touched = useMemo(() => {
    const ids = change.settings ? new Set(catalog.filter((m) => m.settings.some((s) => change.settings!.includes(s.id))).map((m) => m.id)) : new Set(change.modules);
    return catalog.filter((m) => ids.has(m.id)).map((m) => m.id);
  }, [catalog, change]);
  const isChange = change.mode !== "check";
  const dangerous = tier === 3;
  const start = useApiMutation((input: HardeningInput) => api.post<Job>("/jobs/hardening", input), {
    invalidate: ["/jobs", "/job-runs", `/devices/${device.id}/hardening`],
    onSuccess: () => {
      toast.success(
        change.mode === "check"
          ? `Checking hardening on ${device.name}. The findings show here when the agent reports.`
          : `${change.mode === "apply" ? "Applying" : "Undoing"} on ${device.name}. The result shows here when the agent reports.`,
      );
      onClose();
    },
  });

  const optionList = touched.flatMap((id) => (isChange ? (windowsModule(id).options ?? []) : []));
  const canSubmit = !isChange || (agreed && (!dangerous || typed.trim() !== ""));

  function submit(e: FormEvent) {
    e.preventDefault();
    const input: HardeningInput = {
      deviceIds: [device.id],
      platform: "windows",
      mode: change.mode,
      modules: change.settings ? [] : (change.modules ?? []),
      ...(change.settings ? { settings: change.settings } : {}),
      options: isChange ? options : {},
      // A change on an offline computer should not wait a day to start: the guard's clock starts at the apply.
      waitHours: change.mode === "check" ? 24 : 1,
      ...(isChange ? { confirm: { agreed, ...(dangerous ? { typed: typed.trim() } : {}) } } : {}),
    };
    start.mutate(input);
  }

  const what = change.settings ? `${change.settings.length} setting${change.settings.length === 1 ? "" : "s"}` : `${touched.length} module${touched.length === 1 ? "" : "s"}`;
  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-3.5">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">{what}</span>
        {isChange && (
          <Badge tone={tierMeta(tier).tone} title={tierMeta(tier).title}>
            {tierMeta(tier).label}
          </Badge>
        )}
      </div>
      <ul className="divide-y divide-line rounded-md border border-line">
        {touched.map((id) => {
          const m = windowsModule(id);
          return (
            <li key={id} className="px-3 py-2 text-sm">
              <span className="font-medium">{m.name}</span>
              {change.settings && <span className="ml-2 font-mono text-xs text-muted">{change.settings.filter((s) => catalog.find((c) => c.id === id)?.settings.some((x) => x.id === s)).join(", ")}</span>}
              <span className="block text-muted">{m.does}</span>
              {isChange && change.mode === "apply" && m.risk && <span className="block text-warn">Can break: {m.risk}</span>}
            </li>
          );
        })}
      </ul>

      {optionList.length > 0 && (
        <fieldset className="flex flex-col gap-1.5">
          <legend className="text-sm font-medium">Options</legend>
          {optionList.map((o) => (
            <label key={o.field} className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 size-4 accent-accent"
                checked={options[o.field] === true}
                onChange={(e) => setOptions({ ...options, [o.field]: e.target.checked })}
              />
              <span>{o.label}</span>
            </label>
          ))}
        </fieldset>
      )}

      {isChange && (
        <>
          {change.mode === "apply" ? (
            <Alert tone="warn" title="The computer undoes this by itself unless the agent confirms">
              After the change, the computer starts a ten-minute timer. If the EasyRMM agent cannot be reached and confirm that the change left the computer
              working, the computer puts the settings back by itself. The console shows the countdown, and a Keep button to confirm sooner.
            </Alert>
          ) : (
            <Alert tone="info" title="Undo restores what EasyRMM changed">
              A setting someone else changed since is left as it is, and reported.
            </Alert>
          )}
          {dangerous && (
            <>
              <Alert tone="danger" title="This can cut access to the computer">
                One computer at a time, with its name typed here. You will then be asked for a second factor.
              </Alert>
              <TextField
                label={`Type ${device.name} to confirm`}
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                error={fieldError(start.error, "confirm.typed")}
              />
            </>
          )}
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-0.5 size-4 accent-accent" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
            <span>I have read what this change does{change.mode === "apply" ? " and what it can break" : ""}.</span>
          </label>
        </>
      )}
      <InlineError error={start.error} fields={FIELDS} />
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onClose} disabled={start.isPending}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant={change.mode === "check" ? "primary" : change.mode === "apply" ? "danger" : "secondary"}
          disabled={!canSubmit}
          loading={start.isPending}
          icon={change.mode === "check" ? <ScanSearch className="size-4" aria-hidden /> : change.mode === "undo" ? <Undo2 className="size-4" aria-hidden /> : <ShieldCheck className="size-4" aria-hidden />}
        >
          {change.mode === "check" ? "Run check" : change.mode === "apply" ? "Apply" : "Undo"}
        </Button>
      </div>
    </form>
  );
}
