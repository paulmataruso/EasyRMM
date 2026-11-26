import { useEffect, useState } from "react";
import { Button, Select } from "../../../../components/ui";
import type { OuItem, OuTree } from "./types";
import { useWinmod } from "./useWinmod";

/** Picks an organizational unit by walking the tree one level at a time (the tree is read-only; nothing is created). */
export function OuPicker({ deviceId, value, onChange }: { deviceId: string; value: string; onChange: (dn: string) => void }) {
  const run = useWinmod(deviceId);
  const [level, setLevel] = useState<string | null>(null);
  const [items, setItems] = useState<OuItem[]>([]);
  const [trail, setTrail] = useState<string[]>([]);
  const [problem, setProblem] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    void run<OuTree>("ou_tree", level ? { parent: level } : {})
      .then((r) => {
        if (!live) return;
        if (r.ok && r.data) {
          setItems(r.data.items.filter((i) => i.writable));
          setProblem(null);
          if (!level) onChange(r.data.parent);
        } else setProblem(r.failure?.message ?? "The tree could not be read.");
      })
      .catch(() => live && setProblem("The tree could not be read."));
    return () => {
      live = false;
    };
    // onChange is the caller's setter; the walk restarts only when the level changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run, level]);
  return (
    <div className="flex flex-col gap-2 text-sm">
      <div>
        <span className="text-xs text-muted">Container: </span>
        <span className="font-mono text-xs break-all">{value || "…"}</span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" disabled={trail.length === 0} onClick={() => { const t = trail.slice(0, -1); setTrail(t); setLevel(t.at(-1) ?? null); onChange(t.at(-1) ?? value); }}>
          Up
        </Button>
        <Select aria-label="Containers here" value="" onChange={(e) => { const dn = e.target.value; if (dn) { setTrail([...trail, dn]); setLevel(dn); onChange(dn); } }} className="w-auto">
          <option value="">{items.length ? "Open a container…" : "No containers here"}</option>
          {items.map((i) => (
            <option key={i.dn} value={i.dn}>
              {i.name}
            </option>
          ))}
        </Select>
      </div>
      {problem && <p className="text-xs text-danger">{problem}</p>}
    </div>
  );
}
