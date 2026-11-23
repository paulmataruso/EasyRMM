import { useEffect, useId, useMemo, useState } from "react";
import { FolderTree, MapPin } from "lucide-react";
import { useApi, useOrganizations, useSites } from "../api/hooks";
import type { DeviceTreeData } from "../api/types";
import { Dialog } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { Alert, Button, InlineError, Spinner } from "../components/ui";
import { plural } from "../lib/format";
import { consequences, moveKind, movedText, useMoveDevices, widest, type Movable, type MoveTarget } from "./move";

/**
 * Move to…: the tree as a picker, the keyboard and screen-reader equivalent of dragging devices onto a site or a
 * group (ADR-0069). Choosing a place shows what follows when it is another site or organization.
 */
export function MoveDialog({
  devices,
  open,
  onClose,
  organizationId,
  onMoved,
}: {
  devices: Movable[];
  open: boolean;
  onClose: () => void;
  /** Opens with this organization's sites in view (a device dropped on an organization). */
  organizationId?: string;
  onMoved?: () => void;
}) {
  const toast = useToast();
  const filterId = useId();
  const orgs = useOrganizations();
  const sites = useSites();
  const tree = useApi<DeviceTreeData>(open ? "/device-tree" : null);
  const [choice, setChoice] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const move = useMoveDevices((r, req) => {
    toast.success(movedText(r, req));
    onMoved?.();
    onClose();
  });
  useEffect(() => {
    if (open) {
      setChoice(null);
      setQuery("");
      move.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const places = useMemo(() => {
    const out: (MoveTarget & { key: string; level: 1 | 2 })[] = [];
    for (const o of [...orgs.items].sort((a, b) => a.name.localeCompare(b.name))) {
      if (organizationId && o.id !== organizationId) continue;
      for (const s of sites.items.filter((x) => x.organizationId === o.id).sort((a, b) => a.name.localeCompare(b.name))) {
        const base = { organizationId: o.id, organizationName: o.name, siteId: s.id, siteName: s.name };
        out.push({ ...base, key: `s:${s.id}`, groupId: null, groupName: "", level: 1 });
        for (const g of (tree.data?.groups ?? []).filter((x) => x.siteId === s.id).sort((a, b) => a.name.localeCompare(b.name))) {
          out.push({ ...base, key: `g:${g.id}`, groupId: g.id, groupName: g.name, level: 2 });
        }
      }
    }
    const q = query.trim().toLowerCase();
    return q ? out.filter((p) => `${p.organizationName} ${p.siteName} ${p.groupName}`.toLowerCase().includes(q)) : out;
  }, [orgs.items, sites.items, tree.data, query, organizationId]);

  const target = places.find((p) => p.key === choice) ?? null;
  const kind = target ? widest(devices, target) : "none";
  const notes = target ? consequences(devices, target) : [];
  const unchanged = target !== null && devices.every((d) => moveKind(d, target) === "none");
  const loading = orgs.isPending || sites.isPending || tree.isPending;
  const title = devices.length === 1 ? `Move ${devices[0]?.name ?? "device"} to…` : `Move ${plural(devices.length, "device")} to…`;
  let lastOrg = "";

  return (
    <Dialog open={open} onClose={onClose} title={title} description="Choose a site, or one of its device groups." size="md">
      <div className="flex flex-col gap-3">
        <div>
          <label htmlFor={filterId} className="sr-only">
            Filter the places
          </label>
          <input
            id={filterId}
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by organization, site or group"
            className="h-9 w-full rounded-md border border-line bg-surface px-3 text-sm focus:border-accent focus:ring-2 focus:ring-accent/30 focus:outline-none"
          />
        </div>
        {loading ? (
          <Spinner />
        ) : places.length === 0 ? (
          <p className="py-4 text-center text-sm text-muted">No place matches.</p>
        ) : (
          <div role="radiogroup" aria-label="Where to move" className="max-h-72 overflow-y-auto rounded-md border border-line p-1">
            {places.map((p) => {
              const heading = p.organizationName !== lastOrg;
              lastOrg = p.organizationName;
              const current = devices.length === 1 && moveKind(devices[0]!, p) === "none";
              return (
                <div key={p.key}>
                  {heading && <p className="px-2 pt-2 pb-1 text-xs font-semibold tracking-wide text-muted uppercase">{p.organizationName}</p>}
                  <label className={`flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-accent-soft ${p.level === 2 ? "pl-8" : ""}`}>
                    <input type="radio" name="move-target" checked={choice === p.key} onChange={() => setChoice(p.key)} />
                    {p.level === 1 ? <MapPin className="size-3.5 text-muted" aria-hidden /> : <FolderTree className="size-3.5 text-muted" aria-hidden />}
                    <span className="min-w-0 flex-1 truncate">{p.level === 1 ? `${p.siteName}, no group` : `${p.siteName} / ${p.groupName}`}</span>
                    {current && <span className="text-xs text-muted">now here</span>}
                  </label>
                </div>
              );
            })}
          </div>
        )}
        {target && unchanged && <p className="text-sm text-muted">{devices.length === 1 ? "The device is" : "The devices are"} already there.</p>}
        {notes.length > 0 && (
          <Alert tone="warn" title={kind === "organization" ? `Moving to ${target?.organizationName} changes who sees ${devices.length === 1 ? "this device" : "these devices"}` : `Moving to ${target?.siteName}`}>
            <ul className="list-disc space-y-1 pl-5">
              {notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </Alert>
        )}
        <InlineError error={move.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={move.isPending}
            disabled={!target || unchanged}
            onClick={() => target && move.mutate({ devices, target })}
          >
            {target ? `Move to ${target.groupName ? target.groupName : target.siteName}` : "Move"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
