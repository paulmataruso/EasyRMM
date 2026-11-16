import { useEffect, useId, useRef, useState } from "react";
import { Search, X } from "lucide-react";
import { useApi, useOrganizations, useSites } from "../api/hooks";
import type { Device } from "../api/types";
import { Field, Input, Select, cx } from "./ui";

/**
 * Search box. `delay` debounces server-side searches; 0 filters on every keystroke.
 * Pressing "/" anywhere outside a text field focuses it.
 */
export function SearchInput({ value, onChange, placeholder = "Search…", label = "Search", className, delay = 300, readout }: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  label?: string;
  className?: string;
  delay?: number;
  /** Shown under the box, e.g. "3 of 12 organizations". */
  readout?: string | null;
}) {
  const [text, setText] = useState(value);
  const id = useId();
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => setText(value), [value]);
  useEffect(() => {
    if (text.trim() === value) return;
    if (delay === 0) {
      onChange(text.trim());
      return;
    }
    const t = window.setTimeout(() => onChange(text.trim()), delay);
    return () => window.clearTimeout(t);
  }, [text, value, onChange, delay]);
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target)) return;
      e.preventDefault();
      ref.current?.focus();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <Field label={label} htmlFor={id} className={cx("min-w-48 flex-1", className)} hint={readout ?? undefined}>
      <div className="relative">
        <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-subtle" aria-hidden />
        <Input
          ref={ref}
          id={id}
          type="search"
          value={text}
          placeholder={placeholder}
          onChange={(e) => setText(e.target.value)}
          className="pl-8"
          aria-keyshortcuts="/"
        />
      </div>
    </Field>
  );
}

export function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

/** Narrows a list to one site, of the chosen organization when there is one. */
export function SiteSelect({ organizationId, value, onChange }: { organizationId: string; value: string; onChange: (v: string) => void }) {
  const sites = useSites(organizationId || null);
  const id = useId();
  return (
    <Field label="Site" htmlFor={id} className="min-w-40">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} disabled={sites.isPending}>
        <option value="">All sites</option>
        {sites.items.map((s) => (
          <option key={s.id} value={s.id}>
            {organizationId ? s.name : `${s.organizationName} / ${s.name}`}
          </option>
        ))}
      </Select>
    </Field>
  );
}

/** A list narrowed to one device: its name, and a button that widens the list again. */
export function DeviceScope({ deviceId, onClear, clearLabel }: { deviceId: string; onClear: () => void; clearLabel: string }) {
  const device = useApi<Device>(`/devices/${encodeURIComponent(deviceId)}`);
  return (
    <span className="mb-1 inline-flex items-center gap-1 self-end rounded-full bg-accent-soft py-1 pr-1 pl-3 text-sm text-accent">
      {device.data?.name ?? "One device"}
      <button type="button" className="rounded-full p-0.5 hover:bg-accent/15" aria-label={clearLabel} onClick={onClear}>
        <X className="size-3.5" aria-hidden />
      </button>
    </span>
  );
}

export function OrganizationSelect({ value, onChange, label = "Organization", allLabel = "All organizations", className, disabled }: {
  value: string;
  onChange: (value: string) => void;
  label?: string;
  allLabel?: string;
  className?: string;
  disabled?: boolean;
}) {
  const orgs = useOrganizations();
  const id = useId();
  return (
    <Field label={label} htmlFor={id} className={cx("min-w-44", className)}>
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled || orgs.isPending}>
        <option value="">{allLabel}</option>
        {orgs.items.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name}
          </option>
        ))}
      </Select>
    </Field>
  );
}
