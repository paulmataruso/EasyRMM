import { useEffect, useId, useRef, useState } from "react";
import { Search } from "lucide-react";
import { useOrganizations } from "../api/hooks";
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
