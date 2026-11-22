import { useId, useMemo, useState, type ReactNode } from "react";
import { useList } from "../api/hooks";
import type { Device } from "../api/types";
import { plural } from "../lib/format";
import { cx, Dot, EmptyState, ErrorState, Field, Input, Spinner } from "./ui";

/**
 * Devices to choose from for a job: a filterable checklist. classify says
 * which devices can be chosen (true), which could be but not by this caller
 * or not now (false, counted under the list), and which are beside the
 * point (null, not mentioned).
 */
export function DevicePicker({ classify, selected, onChange, error, empty, excluded, note }: {
  classify: (d: Device) => boolean | null;
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  error: string | null;
  /** What to say when no device can be chosen. */
  empty: { title: string; body: ReactNode };
  /** The note under the list for devices left out. */
  excluded: (count: number) => ReactNode;
  /** A warning about the chosen devices, shown under the list. */
  note?: (chosen: Device[]) => ReactNode;
}) {
  const devices = useList<Device>("/devices");
  const [query, setQuery] = useState("");
  const searchId = useId();
  const listId = useId();

  const { eligible, left } = useMemo(() => {
    const eligible: Device[] = [];
    let left = 0;
    for (const d of devices.items) {
      const c = classify(d);
      if (c) eligible.push(d);
      else if (c === false) left++;
    }
    return { eligible, left };
  }, [devices.items, classify]);
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
      <EmptyState title={empty.title} compact>
        {empty.body}
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
      {note && <ChosenNote note={note} chosen={eligible.filter((d) => selected.has(d.id))} />}
      {left > 0 && <p className="text-xs text-subtle">{excluded(left)}</p>}
    </Field>
  );
}

function ChosenNote({ note, chosen }: { note: (chosen: Device[]) => ReactNode; chosen: Device[] }) {
  const text = note(chosen);
  return text ? <p className="text-xs text-warn">{text}</p> : null;
}

/** "1 other device … is" / "3 other devices … are". */
export function otherDevices(n: number): { devices: string; is: string } {
  return { devices: plural(n, "other device"), is: n === 1 ? "is" : "are" };
}
