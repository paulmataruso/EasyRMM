// Pieces shared by the script, job and device pages (ADR-0017).
import { useId, useMemo, useState } from "react";
import { Link } from "react-router";
import { useApi } from "../../api/hooks";
import type { Job, PatchStatus, RunStatus, Script, Shell } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { CopyButton } from "../../components/Copy";
import { Alert, Badge, cx, Dot, Field, Input, Select } from "../../components/ui";
import { jobState, RUN_STATUS, STATUS_ORDER } from "./scriptText";
import { selfPatching } from "./selfPatching";

export function RunStatusBadge({ status, cancelRequested = false }: { status: RunStatus; cancelRequested?: boolean }) {
  const s = RUN_STATUS[status] ?? { label: status, tone: "neutral" as const, title: "" };
  if (cancelRequested && status === "running") {
    return (
      <Badge tone="warn" title="Cancel was requested; the device stops the script the next time it checks in." icon={<Dot tone="warn" />}>
        Canceling
      </Badge>
    );
  }
  return (
    <Badge tone={s.tone} title={s.title} icon={status === "running" ? <Dot tone="info" /> : undefined}>
      {s.label}
    </Badge>
  );
}

export function JobStateBadge({ job }: { job: Pick<Job, "counts" | "total" | "finished"> }) {
  const s = jobState(job);
  return (
    <Badge tone={s.tone} title={s.title}>
      {s.label}
    </Badge>
  );
}

/** "2 succeeded · 1 failed · 3 queued", with the status dots. */
export function StatusBreakdown({ job, className }: { job: Pick<Job, "counts">; className?: string }) {
  const parts = STATUS_ORDER.filter((s) => (job.counts[s] ?? 0) > 0);
  if (parts.length === 0) return <span className="text-muted">No devices you can see</span>;
  return (
    <span className={cx("inline-flex flex-wrap items-center gap-x-3 gap-y-0.5", className)}>
      {parts.map((s) => (
        <span key={s} className="inline-flex items-center gap-1.5 whitespace-nowrap" title={RUN_STATUS[s].title}>
          <Dot tone={RUN_STATUS[s].tone} />
          <span className="tabular-nums">{job.counts[s]}</span>
          <span className="text-muted">{RUN_STATUS[s].label.toLowerCase()}</span>
        </span>
      ))}
    </span>
  );
}

type Unit = "seconds" | "minutes" | "hours";
const UNIT_SECONDS: Record<Unit, number> = { seconds: 1, minutes: 60, hours: 3600 };

function unitFor(seconds: number): Unit {
  if (seconds >= 3600 && seconds % 3600 === 0) return "hours";
  if (seconds >= 60 && seconds % 60 === 0) return "minutes";
  return "seconds";
}

/**
 * A duration typed as a number and a unit, reported in whole seconds (0 while the number is not valid).
 * It starts from `value`; give it a new `key` to reset it.
 */
export function TimeoutField({ label, value, onChange, error, hint, className }: {
  label: string;
  value: number;
  onChange: (seconds: number) => void;
  error?: string | null;
  hint?: string;
  className?: string;
}) {
  const id = useId();
  const [unit, setUnit] = useState<Unit>(() => unitFor(value));
  const [text, setText] = useState(() => String(value / UNIT_SECONDS[unitFor(value)]));
  const report = (t: string, u: Unit) => {
    const n = Number(t);
    onChange(t.trim() !== "" && Number.isFinite(n) && n > 0 ? Math.round(n * UNIT_SECONDS[u]) : 0);
  };
  return (
    <Field label={label} htmlFor={id} error={error} hint={hint} className={className}>
      <div className="flex gap-2">
        <Input
          id={id}
          type="number"
          inputMode="decimal"
          min={0}
          step="any"
          value={text}
          aria-invalid={error ? true : undefined}
          onChange={(e) => {
            setText(e.target.value);
            report(e.target.value, unit);
          }}
          className="w-24"
        />
        <Select
          aria-label={`${label} unit`}
          value={unit}
          onChange={(e) => {
            const u = e.target.value as Unit;
            setUnit(u);
            report(text, u);
          }}
          className="w-32"
        >
          <option value="seconds">seconds</option>
          <option value="minutes">minutes</option>
          <option value="hours">hours</option>
        </Select>
      </div>
    </Field>
  );
}

/** A script with line numbers, scrolling sideways rather than wrapping, with a copy button. */
export function CodeView({ code, label, className }: { code: string; label: string; className?: string }) {
  const lines = code.replace(/\n$/, "").split("\n");
  return (
    <div className={cx("relative rounded-md border border-line bg-raised", className)}>
      <pre aria-label={label} tabIndex={0} className="max-h-[36rem] overflow-auto py-2.5 font-mono text-xs leading-relaxed text-fg">
        <code className="table min-w-full">
          {lines.map((line, i) => (
            <span key={i} className="table-row">
              <span aria-hidden className="table-cell w-px pr-3 pl-3 text-right text-subtle tabular-nums select-none">
                {i + 1}
              </span>
              <span className="table-cell pr-20 whitespace-pre">{line || " "}</span>
            </span>
          ))}
        </code>
      </pre>
      <div className="absolute top-1.5 right-1.5">
        <CopyButton text={code} />
      </div>
    </div>
  );
}

/** One output stream of a run. */
export function OutputView({ title, text, truncated, emptyLabel }: { title: string; text: string | undefined; truncated: boolean; emptyLabel: string }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="min-w-0">
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <h3 id={id} className="text-xs font-medium text-muted">
          {title}
        </h3>
        {text ? <CopyButton text={text} /> : null}
      </div>
      {text ? (
        <pre
          tabIndex={0}
          aria-labelledby={id}
          className="max-h-[32rem] overflow-auto rounded-md border border-line bg-raised px-3 py-2.5 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-fg"
        >
          {text}
        </pre>
      ) : (
        <p className="rounded-md border border-dashed border-line px-3 py-2.5 text-sm text-muted">{emptyLabel}</p>
      )}
      {truncated && (
        <p className="mt-1 text-xs text-muted">The output was longer than 256 KiB, so its middle was left out. The first and last 128 KiB are kept.</p>
      )}
    </section>
  );
}

/**
 * Warns that a script installs operating-system updates itself while EasyPatch patches devices
 * (docs/integrations/easypatch.md). Shown only when EasyPatch is set up and the user can see patching. Pass the body,
 * or the script's id to read it when a list gave the script without one.
 */
export function SelfPatchingWarning({ shell, body, scriptId, className }: { shell: Shell; body?: string; scriptId?: string; className?: string }) {
  const { can } = useAuth();
  const status = useApi<PatchStatus>(can("patch.view") ? "/patching" : null, undefined, { staleTime: 60_000 });
  const configured = status.data?.configured === true;
  const full = useApi<Script>(configured && body === undefined && scriptId ? `/scripts/${scriptId}` : null);
  const text = body ?? full.data?.body;
  const lines = useMemo(() => (configured && text ? selfPatching(shell, text) : []), [configured, shell, text]);
  if (lines.length === 0) return null;
  const shown = lines.slice(0, 5);
  return (
    <Alert tone="warn" title="This script installs system updates itself" className={className}>
      <p>
        Where EasyPatch patches a device, updates a script installs skip EasyPatch&apos;s policies, maintenance windows and exclusions, and
        EasyPatch sees them only at its next scan. Install updates from{" "}
        <Link to="/patching" className="font-medium text-accent hover:underline">
          Patching
        </Link>{" "}
        instead.
      </p>
      <ul className="mt-1.5 space-y-1">
        {shown.map((l) => (
          <li key={l.line}>
            Line {l.line} {l.what}: <code className="font-mono text-xs break-words">{l.text}</code>
          </li>
        ))}
      </ul>
      {lines.length > shown.length && <p className="mt-1">And {lines.length - shown.length} more lines like these.</p>}
    </Alert>
  );
}
