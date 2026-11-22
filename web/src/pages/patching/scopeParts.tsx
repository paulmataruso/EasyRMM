import { useEffect, useState } from "react";
import { Link } from "react-router";
import type { UseQueryResult } from "@tanstack/react-query";
import { useApi } from "../../api/hooks";
import type { PatchAvailablePlan, PatchScope, PatchScopeSkip, PatchTargets, Platform } from "../../api/types";
import { Alert, ErrorState, Spinner } from "../../components/ui";
import { plural } from "../../lib/format";
import { platformName } from "../devices/platform";
import { categoryLabel } from "./patchText";

// Patch all (ADR-0030): the pieces an install or restart of every device of an organization, or one of its sites, is
// made of. The server reads the devices when the request runs; these show what it would reach as it stands now.

/** An organization, or one of its sites, that an action reaches whole. */
export interface ScopeTarget {
  organizationId: string;
  siteId?: string;
  /** Its name, as the person chose it: "Northwind Traders", or "Head office (Northwind Traders)". */
  label: string;
}

/** The scope's name for buttons and titles. */
export function scopeLabel(organizationName: string, siteName?: string): string {
  return siteName ? `${siteName} (${organizationName})` : organizationName;
}

/** What an action on all of an organization or site would reach, for those who may patch somewhere. */
export function usePatchScope(target: { organizationId: string; siteId?: string } | null) {
  return useApi<PatchScope>(
    target?.organizationId ? "/patching/scope" : null,
    target?.organizationId ? { organizationId: target.organizationId, siteId: target.siteId || undefined } : undefined,
    { staleTime: 15_000 },
  );
}

const SKIPS: Record<PatchScopeSkip, (n: number) => string> = {
  not_permitted: (n) => `${plural(n, "device")} you may not patch`,
  stopped: (n) => `${plural(n, "device")} with patching stopped`,
  no_agent: (n) => `${plural(n, "device")} with no EasyPatch agent`,
  not_linked: (n) => `${plural(n, "device")} whose EasyPatch agent is not linked yet`,
  platform: (n) => `${plural(n, "device")} on platforms not chosen`,
};

/** "3 devices with no EasyPatch agent". */
function skipText(reason: PatchScopeSkip, count: number): string {
  return (SKIPS[reason] ?? ((n: number) => `${plural(n, "device")} (${reason})`))(count);
}

/** The devices left out of a scope, and why, as a list; nothing when none are. */
export function SkippedList({ skipped, intro = "Left out:" }: { skipped: PatchScope["skipped"]; intro?: string }) {
  if (skipped.length === 0) return null;
  return (
    <div className="text-sm">
      <p className="text-muted">{intro}</p>
      <ul className="mt-0.5 list-disc space-y-0.5 pl-5 text-muted">
        {skipped.map((s) => (
          <li key={s.reason}>{skipText(s.reason, s.count)}</li>
        ))}
      </ul>
    </div>
  );
}

/** Which platforms of a scope are chosen, with Windows always on at first; others as `others` says. */
export function usePlatforms(scope: PatchScope | undefined, open: boolean, others: boolean) {
  // Null until chosen for this opening, so nothing is checked with the server for a choice nobody made.
  const [chosen, setChosen] = useState<Set<Platform> | null>(null);
  const loaded = scope !== undefined;
  const all = scope?.byPlatform.map((p) => p.platform).join(",") ?? "";
  useEffect(() => {
    if (!open) {
      setChosen(null);
      return;
    }
    if (!scope) return;
    setChosen(new Set(scope.byPlatform.filter((p) => p.platform === "windows" || others).map((p) => p.platform)));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- choose again when the dialog opens or the platforms change
  }, [open, loaded, all, others]);
  const byPlatform = scope?.byPlatform ?? [];
  const has = (p: Platform) => chosen?.has(p) ?? false;
  const count = byPlatform.filter((p) => has(p.platform)).reduce((n, p) => n + p.count, 0);
  const every = byPlatform.length > 0 && byPlatform.every((p) => has(p.platform));
  return {
    /** The platforms are chosen for this opening. */
    ready: chosen !== null && loaded,
    chosen: chosen ?? new Set<Platform>(),
    setChosen: (next: Set<Platform>) => setChosen(next),
    /** Devices on the chosen platforms. */
    count,
    /**
     * The platforms to send: none when every platform is chosen and others start ticked, so devices enrolled since are
     * included; otherwise each one, so a device enrolled since on a platform left unticked at first cannot slip in.
     */
    platforms: every && others ? undefined : byPlatform.filter((p) => has(p.platform)).map((p) => p.platform),
    /**
     * Ticks are worth showing: more than one platform, or one that starts unticked. That stays so once it is ticked,
     * so it can be unticked again.
     */
    show: byPlatform.length > 1 || (!others && byPlatform.some((p) => p.platform !== "windows")),
  };
}

/** One tick per platform of a scope, with how many devices run it. */
function PlatformTicks({ scope, chosen, onChange }: { scope: PatchScope; chosen: Set<Platform>; onChange: (next: Set<Platform>) => void }) {
  return (
    <fieldset className="space-y-1.5">
      <legend className="mb-1 text-xs font-medium text-muted">Platforms</legend>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {scope.byPlatform.map((p) => (
          <label key={p.platform} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={chosen.has(p.platform)}
              onChange={(e) => {
                const next = new Set(chosen);
                if (e.target.checked) next.add(p.platform);
                else next.delete(p.platform);
                onChange(next);
              }}
              className="size-4 accent-accent"
            />
            {platformName(p.platform)} ({p.count.toLocaleString()})
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/**
 * What an action on all of an organization or site reaches: how many devices, those left out and why, and a tick per
 * platform when there is a choice.
 */
export function ScopeSummary({ target, q, plat, verb }: {
  target: ScopeTarget;
  q: UseQueryResult<PatchScope>;
  plat: ReturnType<typeof usePlatforms>;
  /** What the devices do: "install", "can restart". */
  verb: string;
}) {
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />;
  if (q.isPending || !plat.ready) return <Spinner label="Counting the devices…" />;
  const s = q.data;
  const name = scopeLabel(s.organizationName, s.siteName) || target.label;
  return (
    <section aria-label="Devices" className="space-y-3">
      {s.devices === 0 ? (
        <Alert tone="warn" title="No device here can be patched from EasyRMM">
          <SkippedList skipped={s.skipped} intro="Every device is left out:" />
        </Alert>
      ) : (
        <>
          <p className="text-sm">
            <span className="font-medium">{plural(plat.count, "device")}</span> in {name} {verb}
            {plat.count < s.devices ? `, of the ${s.devices.toLocaleString()} you may patch there` : ""}.
          </p>
          <SkippedList skipped={s.skipped} />
          {plat.show && <PlatformTicks scope={s} chosen={plat.chosen} onChange={plat.setChosen} />}
        </>
      )}
    </section>
  );
}

/** The targets of an action on every chosen device of a scope. */
export function scopeTargets(t: ScopeTarget, platforms: Platform[] | undefined): PatchTargets {
  return { all: true, organizationId: t.organizationId, siteId: t.siteId || undefined, platforms };
}

/** What installing every available update would do, summed over the devices, with what is left out and why. */
export function AvailablePlanView({ plan, onRetry, skipDelayed }: {
  plan: { isPending: boolean; isIdle: boolean; isError: boolean; error: Error | null; data: PatchAvailablePlan | undefined };
  onRetry: () => void;
  /** The updates still in the rollout delay are left out. */
  skipDelayed: boolean;
}) {
  if (plan.isPending || plan.isIdle) return <Spinner label="Checking what would be installed…" />;
  if (plan.isError) return <ErrorState error={plan.error} onRetry={onRetry} compact />;
  const p = plan.data;
  if (!p) return null;
  return (
    <section aria-label="What would be installed" className="space-y-3 text-sm">
      {p.updates === 0 ? (
        <Alert tone="info" title="Nothing to install">
          {p.upToDate > 0 ? `${plural(p.upToDate, "device")} ${p.upToDate === 1 ? "has" : "have"} no update to install.` : "No device has an update to install."}
        </Alert>
      ) : (
        <div>
          <p className="font-medium">
            {plural(p.updates, "update")} on {plural(p.devices, "device")}
            {p.upToDate > 0 && <span className="font-normal text-muted">; {plural(p.upToDate, "device")} already up to date</span>}
          </p>
          {p.categories.length > 0 && (
            <ul className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-muted">
              {p.categories.map((c) => (
                <li key={c.category}>
                  {categoryLabel(c.category)}: <span className="text-fg tabular-nums">{c.count.toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {(p.features > 0 || p.excluded.count > 0 || p.held > 0 || p.notApproved > 0 || (skipDelayed && p.deferred > 0)) && (
        <div>
          <p className="font-medium">Left out</p>
          <ul className="mt-0.5 list-disc space-y-0.5 pl-5 text-muted">
            {p.features > 0 && <li>{plural(p.features, "feature upgrade")}, unless you tick them above</li>}
            {p.excluded.count > 0 && <li>{plural(p.excluded.count, "update")} excluded on their devices</li>}
            {p.held > 0 && <li>{plural(p.held, "update")} on hold</li>}
            {p.notApproved > 0 && <li>{plural(p.notApproved, "application update")} the patch policy does not approve</li>}
            {skipDelayed && p.deferred > 0 && <li>{plural(p.deferred, "update")} still in the rollout delay, as chosen above</li>}
          </ul>
        </div>
      )}
      {p.excluded.devices.length > 0 && (
        <div>
          <p className="text-xs font-medium text-muted">Exclusions, by device</p>
          <ul className="mt-0.5 max-h-32 space-y-0.5 overflow-y-auto">
            {p.excluded.devices.map((d) => (
              <li key={d.deviceId}>
                <Link to={`/devices/${d.deviceId}?tab=patches&patches=available`} className="hover:text-accent">
                  {d.deviceName}
                </Link>{" "}
                <span className="text-xs text-muted">{plural(d.count, "update")} excluded</span>
              </li>
            ))}
          </ul>
          {p.excluded.devices.length >= 50 && (
            <p className="text-xs text-subtle">The first {p.excluded.devices.length.toLocaleString()} devices are listed.</p>
          )}
        </div>
      )}
      {!skipDelayed && p.deferred > 0 && (
        <p className="text-muted">
          {plural(p.deferred, "update")} {p.deferred === 1 ? "is" : "are"} still in the rollout delay; installing now installs{" "}
          {p.deferred === 1 ? "it" : "them"} anyway.
        </p>
      )}
      {p.errors.length > 0 && (
        <Alert tone="warn" title={`The updates of ${plural(p.errors.length, "device")} could not be read`}>
          <ul className="space-y-0.5">
            {p.errors.map((e) => (
              <li key={e.deviceId}>
                <span className="font-medium">{e.deviceName}</span>: {e.message}
              </li>
            ))}
          </ul>
          <p className="mt-1 text-xs">The patching engine checks these devices again when it installs.</p>
        </Alert>
      )}
    </section>
  );
}
