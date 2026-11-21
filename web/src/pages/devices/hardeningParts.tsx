// Pieces of hardening Linux computers (ADR-0051) shared by the device's Hardening tab, its dialogs and the Devices list.
import { useId } from "react";
import type { Device, HardeningState } from "../../api/types";
import { Badge, cx } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { MODULES, stateMeta, summarize, type ModuleInfo } from "./hardeningText";

export function HardeningStateBadge({ state }: { state: HardeningState }) {
  const s = stateMeta(state);
  return (
    <Badge tone={s.tone} title={s.title}>
      {s.label}
    </Badge>
  );
}

/** The Devices list's hardening column: the latest findings in a few words, or why there are none. */
export function HardeningCell({ device: d }: { device: Pick<Device, "hardening" | "platform" | "agent"> }) {
  if (d.hardening) {
    const s = summarize(d.hardening);
    return (
      <>
        <Badge tone={s.tone} title={s.title} className="tabular-nums">
          {s.label}
        </Badge>
        <span className="block text-xs text-muted" title={formatDateTime(d.hardening.checkedAt)}>
          {formatRelative(d.hardening.checkedAt)}
        </span>
      </>
    );
  }
  if (d.platform === "linux" && d.agent) return <span className="text-muted">Not checked</span>;
  return (
    <span className="text-muted" title="Hardening covers Linux devices with the EasyRMM agent.">
      —
    </span>
  );
}

/**
 * The modules to run, each with what it does. Recommended ones come first; the others are chosen one by one, with
 * what applying them can break beside them.
 */
export function ModuleChooser({ selected, onChange, error, optionalHint }: {
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  error?: string | null;
  /** Under the optional modules' heading. */
  optionalHint: string;
}) {
  const errorId = useId();
  const recommended = MODULES.filter((m) => m.recommended);
  const optional = MODULES.filter((m) => !m.recommended);
  const chosen = recommended.filter((m) => selected.has(m.id)).length;
  const toggle = (id: string, on: boolean) => {
    const next = new Set(selected);
    if (on) next.add(id);
    else next.delete(id);
    onChange(next);
  };
  return (
    <fieldset className="flex flex-col gap-3" aria-describedby={error ? errorId : undefined}>
      <legend className="sr-only">Modules</legend>
      <div className="rounded-md border border-line">
        <label className="flex items-center gap-2 border-b border-line bg-raised px-3 py-2 text-sm font-medium">
          <input
            type="checkbox"
            className="size-4 accent-accent"
            checked={chosen === recommended.length}
            ref={(el) => {
              if (el) el.indeterminate = chosen > 0 && chosen < recommended.length;
            }}
            onChange={(e) => {
              const next = new Set(selected);
              for (const m of recommended) {
                if (e.target.checked) next.add(m.id);
                else next.delete(m.id);
              }
              onChange(next);
            }}
          />
          Recommended
          <span className="ml-auto text-xs font-normal text-muted tabular-nums">
            {chosen} of {recommended.length}
          </span>
        </label>
        <ul className="divide-y divide-line">
          {recommended.map((m) => (
            <ModuleRow key={m.id} module={m} checked={selected.has(m.id)} onToggle={toggle} />
          ))}
        </ul>
      </div>
      <div className="rounded-md border border-line">
        <div className="border-b border-line bg-raised px-3 py-2">
          <p className="text-sm font-medium">Optional</p>
          <p className="text-xs text-muted">{optionalHint}</p>
        </div>
        <ul className="divide-y divide-line">
          {optional.map((m) => (
            <ModuleRow key={m.id} module={m} checked={selected.has(m.id)} onToggle={toggle} />
          ))}
        </ul>
      </div>
      {error && (
        <p id={errorId} className="text-xs text-danger">
          {error}
        </p>
      )}
    </fieldset>
  );
}

function ModuleRow({ module: m, checked, onToggle }: { module: ModuleInfo; checked: boolean; onToggle: (id: string, on: boolean) => void }) {
  const id = useId();
  return (
    <li className={cx("flex gap-2.5 px-3 py-2", checked && "bg-accent-soft/40")}>
      <input id={id} type="checkbox" className="mt-0.5 size-4 shrink-0 accent-accent" checked={checked} onChange={(e) => onToggle(m.id, e.target.checked)} />
      <label htmlFor={id} className="min-w-0 text-sm">
        <span className="font-medium">{m.name}</span>
        <span className="block text-xs text-muted">{m.does}</span>
        {m.risk && <span className="mt-0.5 block text-xs text-warn">When applied: {m.risk}</span>}
      </label>
    </li>
  );
}
