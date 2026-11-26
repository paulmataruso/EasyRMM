import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { ChevronDown, ChevronRight, ScanSearch, ShieldCheck, Timer, Undo2 } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import { keyFor, useApi, useApiMutation, useList } from "../../api/hooks";
import type {
  Device,
  DeviceHardening,
  HardeningGuard,
  HardeningModule,
  HardeningRelated,
  HardeningSettingFinding,
  JobRun,
  List,
  WindowsCatalogModule,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, KeyValueList, Spinner, TableWrap } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { RunStatusBadge } from "../scripts/parts";
import { isOpen } from "../scripts/scriptText";
import { HardeningStateBadge } from "../devices/hardeningParts";
import { summarize } from "../devices/hardeningText";
import { WindowsChangeDialog, type WindowsChange } from "./WindowsChangeDialog";
import { CITE, countdown, GUARD_STATES, OUTCOMES, settingState, tierMeta, windowsModule, WINDOWS_MODULES } from "./windowsText";

const SHOWN_RUNS = 8;

function When({ at }: { at: string }) {
  return <span title={formatDateTime(at)}>{formatRelative(at)}</span>;
}

/**
 * A Windows computer's hardening (ADR-0054, W3): the last check module by module and setting by setting, apply and undo
 * with the tier's confirmation, the guard that undoes a change the agent does not confirm, and the history. Viewing
 * needs device.view, checking script.run, changing device.harden, each checked where the computer is (canAt).
 */
export function WindowsHardeningPanel({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const at = { organizationId: device.organizationId, siteId: device.siteId };
  const hasAgent = device.agent !== null;
  const canCheck = hasAgent && canAt("script.run", at);
  const canChange = hasAgent && canAt("device.harden", at);
  const viewJobs = canAt("job.view", at);
  const [change, setChange] = useState<WindowsChange | null>(null);
  const [modules, setModules] = useState<Set<string>>(new Set());
  const [settings, setSettings] = useState<Set<string>>(new Set());

  const catalog = useApi<List<WindowsCatalogModule>>("/hardening/windows/catalog", undefined, { staleTime: Infinity });
  const runs = useList<JobRun>(viewJobs ? "/job-runs" : null, { deviceId: device.id, kind: "hardening" }, {
    refetchInterval: (data) => (data?.items.some((r) => isOpen(r.status)) ? 4_000 : 30_000),
  });
  const running = runs.items.some((r) => isOpen(r.status));
  const path = `/devices/${device.id}/hardening`;
  const h = useApi<DeviceHardening>(path, undefined, { refetchInterval: 60_000 });
  const guardsPath = `${path}/guards`;
  const guards = useList<HardeningGuard>(guardsPath, undefined, {
    refetchInterval: (data) => (data?.items.some((g) => g.state === "armed") ? 5_000 : 60_000),
  });
  const watched = useMemo(() => [path, guardsPath], [path, guardsPath]);
  useReadAgainWhenRunsChange(runs.items.map((r) => `${r.id}:${r.status}`).join(","), watched);

  if (h.isPending || catalog.isPending) return <Spinner />;
  if (h.isError) return <ErrorState error={h.error} onRetry={() => void h.refetch()} />;
  if (catalog.isError) return <ErrorState error={catalog.error} onRetry={() => void catalog.refetch()} />;
  const d = h.data;
  const cat = catalog.data.items;
  const tierOf = new Map(cat.map((m) => [m.id, m]));
  const armed = guards.items.find((g) => g.state === "armed");
  const checkButton = (variant: "primary" | "secondary") =>
    canCheck && (
      <Button variant={variant} icon={<ScanSearch className="size-4" aria-hidden />} onClick={() => setChange({ mode: "check", modules: WINDOWS_MODULES.map((m) => m.id) })}>
        Run check…
      </Button>
    );
  const selecting = modules.size > 0 || settings.size > 0;
  const chosen = (): { modules: string[] } | { settings: string[] } =>
    settings.size > 0 ? { settings: [...settings] } : { modules: WINDOWS_MODULES.filter((m) => modules.has(m.id)).map((m) => m.id) };
  const changeButtons = canChange && selecting && (
    <>
      <Button variant="danger" icon={<ShieldCheck className="size-4" aria-hidden />} onClick={() => setChange({ mode: "apply", ...chosen() } as WindowsChange)}>
        Apply…
      </Button>
      <Button icon={<Undo2 className="size-4" aria-hidden />} onClick={() => setChange({ mode: "undo", ...chosen() } as WindowsChange)}>
        Undo…
      </Button>
    </>
  );
  const showRuns = viewJobs && (runs.isError || runs.items.length > 0);

  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <div className="flex min-w-0 flex-col gap-4 xl:col-span-2">
        {armed && <GuardCard guard={armed} device={device} canKeep={canChange} />}
        {d.checkedAt && d.modules.length > 0 ? (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <Overview modules={d.modules} checkedAt={d.checkedAt} />
              <div className="flex flex-wrap items-center gap-2">
                {changeButtons}
                {checkButton("secondary")}
              </div>
            </div>
            {canChange && (
              <p className="text-xs text-muted">
                {selecting
                  ? `${settings.size > 0 ? `${settings.size} setting${settings.size === 1 ? "" : "s"}` : `${modules.size} module${modules.size === 1 ? "" : "s"}`} chosen. A change takes modules or single settings, not both.`
                  : "Tick modules, or single settings under a module, to apply or undo them."}
              </p>
            )}
            <Modules
              hardening={d}
              catalog={tierOf}
              canChange={canChange}
              modules={modules}
              settings={settings}
              onModules={setModules}
              onSettings={setSettings}
              viewJobs={viewJobs}
            />
          </>
        ) : (
          <Card>
            <EmptyState title={running ? "Checking hardening" : "Not checked yet"} icon={<ShieldCheck className="size-8" aria-hidden />} action={!running && checkButton("primary")}>
              {running
                ? "The EasyRMM agent is running the check. Its findings show here, module by module, when it reports."
                : `A check reads this computer's accounts, firewall, Defender and other settings through the EasyRMM agent, and changes nothing.${
                    canCheck ? "" : " Someone who runs scripts on this computer can start one."
                  }`}
            </EmptyState>
          </Card>
        )}
      </div>
      <div className="flex min-w-0 flex-col gap-5">
        {d.platform && d.checkedAt && <LastCheck hardening={d} checkedAt={d.checkedAt} />}
        <History guards={guards.items} runs={runs} show={showRuns} deviceId={device.id} />
        {d.controlSources && d.controlSources.length > 0 && <Sources sources={d.controlSources} />}
      </div>
      <WindowsChangeDialog change={change} device={device} catalog={cat} onClose={() => setChange(null)} />
    </div>
  );
}

/**
 * A check's findings, an apply's guard and a guard's end are recorded after the run: whenever a hardening run of the
 * device changes (starts, ends, or another is queued behind it), they are read again. The first look reads nothing.
 */
function useReadAgainWhenRunsChange(signature: string, paths: string[]) {
  const client = useQueryClient();
  const last = useRef(signature);
  useEffect(() => {
    if (last.current !== signature) for (const p of paths) void client.invalidateQueries({ queryKey: keyFor(p) });
    last.current = signature;
  }, [signature, paths, client]);
}

function Overview({ modules, checkedAt }: { modules: HardeningModule[]; checkedAt: string }) {
  const states: Partial<Record<HardeningModule["state"], number>> = {};
  for (const m of modules) states[m.state] = (states[m.state] ?? 0) + 1;
  const s = summarize({ checkedAt, states });
  return (
    <p className="flex flex-wrap items-center gap-2 text-sm text-muted">
      <Badge tone={s.tone} title={s.title} className="tabular-nums">
        {s.label}
      </Badge>
      <span>
        Checked <When at={checkedAt} />
      </span>
    </p>
  );
}

/** The guard of an apply that waits for the agent's confirmation, with the time left and a Keep button. */
function GuardCard({ guard, device, canKeep }: { guard: HardeningGuard; device: Device; canKeep: boolean }) {
  const toast = useToast();
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const keep = useApiMutation((_: void) => api.post<HardeningGuard>(`/devices/${device.id}/hardening/guard/keep`, {}), {
    invalidate: [`/devices/${device.id}/hardening`],
    onSuccess: () => toast.success("Asked the agent to confirm now."),
  });
  const left = countdown(guard.rollbackAt, now);
  const over = Date.parse(guard.rollbackAt) <= now;
  return (
    <Alert tone={over ? "danger" : "warn"} title={over ? "The computer is undoing the change" : `The computer undoes the change in ${left}`}>
      <div className="flex flex-col gap-2">
        <p>
          {over
            ? "The agent did not confirm in time. The next check shows whether the computer put the settings back."
            : "It does so unless the agent confirms that the computer still works. The server has asked it to; the confirmation arrives when the agent answers."}
        </p>
        <p className="font-mono text-xs break-words">{guard.settings.join(", ")}</p>
        {guard.keepRequestedAt && !over && <p className="text-xs">Keep was asked <When at={guard.keepRequestedAt} />, and waits for the agent.</p>}
        {canKeep && !over && (
          <div>
            <Button icon={<Timer className="size-4" aria-hidden />} loading={keep.isPending} onClick={() => keep.mutate()}>
              Keep the change
            </Button>
          </div>
        )}
        <InlineError error={keep.error} />
      </div>
    </Alert>
  );
}

function Modules({ hardening: d, catalog, canChange, modules, settings, onModules, onSettings, viewJobs }: {
  hardening: DeviceHardening;
  catalog: Map<string, WindowsCatalogModule>;
  canChange: boolean;
  modules: Set<string>;
  settings: Set<string>;
  onModules: (s: Set<string>) => void;
  onSettings: (s: Set<string>) => void;
  viewJobs: boolean;
}) {
  const checked = new Set(d.modules.map((m) => m.module));
  const unchecked = WINDOWS_MODULES.filter((m) => !checked.has(m.id));
  return (
    <Card title="Modules" padded={false}>
      <ul className="divide-y divide-line">
        {d.modules.map((m) => (
          <ModuleItem
            key={m.module}
            module={m}
            tier={catalog.get(m.module)}
            canChange={canChange}
            moduleChosen={modules.has(m.module)}
            chosenSettings={settings}
            blockModules={settings.size > 0}
            blockSettings={modules.size > 0}
            onModule={(on) => {
              const next = new Set(modules);
              if (on) next.add(m.module);
              else next.delete(m.module);
              onModules(next);
            }}
            onSetting={(id, on) => {
              const next = new Set(settings);
              if (on) next.add(id);
              else next.delete(id);
              onSettings(next);
            }}
            earlier={Date.parse(m.checkedAt) < Date.parse(d.checkedAt ?? m.checkedAt)}
            viewJobs={viewJobs}
          />
        ))}
      </ul>
      {unchecked.length > 0 && <p className="border-t border-line px-4 py-2.5 text-xs text-muted">Not checked yet: {unchecked.map((m) => m.name).join(", ")}.</p>}
    </Card>
  );
}

function ModuleItem({ module: m, tier, canChange, moduleChosen, chosenSettings, blockModules, blockSettings, onModule, onSetting, earlier, viewJobs }: {
  module: HardeningModule;
  tier: WindowsCatalogModule | undefined;
  canChange: boolean;
  moduleChosen: boolean;
  chosenSettings: Set<string>;
  blockModules: boolean;
  blockSettings: boolean;
  onModule: (on: boolean) => void;
  onSetting: (id: string, on: boolean) => void;
  earlier: boolean;
  viewJobs: boolean;
}) {
  const [open, setOpen] = useState(false);
  const info = windowsModule(m.module);
  const t = tierMeta(tier?.tier ?? 2);
  const reportOnly = tier?.tier === 0;
  const findings = m.settings ?? [];
  const catalogSettings = new Map((tier?.settings ?? []).map((s) => [s.id, s]));
  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
        <div className="flex min-w-0 items-start gap-2">
          {canChange && !reportOnly && (
            <input
              type="checkbox"
              aria-label={`Choose ${info.name}`}
              className="mt-1 size-4 accent-accent"
              checked={moduleChosen}
              disabled={blockModules}
              onChange={(e) => onModule(e.target.checked)}
            />
          )}
          <button
            type="button"
            aria-expanded={open}
            aria-label={`${info.name}, ${open ? "hide" : "show"} its settings`}
            className="flex min-w-0 items-center gap-1 text-left"
            onClick={() => setOpen(!open)}
          >
            {open ? <ChevronDown className="size-4 shrink-0" aria-hidden /> : <ChevronRight className="size-4 shrink-0" aria-hidden />}
            <h3 className="text-sm font-medium">{info.name}</h3>
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge tone={t.tone} title={t.title}>
            {t.label}
          </Badge>
          {m.restart && <Badge tone="warn" title="A change waits for a restart of the computer to take effect.">Restart needed</Badge>}
          <HardeningStateBadge state={m.state} />
        </div>
      </div>
      {m.reason && <p className="mt-1 text-sm break-words text-muted">{m.reason}</p>}
      {m.outcome && (
        <p className="mt-1 text-sm break-words text-muted">
          Last change: {OUTCOMES[m.outcome] ?? m.outcome}
          {m.outcomeReason ? `. ${m.outcomeReason}` : ""}
        </p>
      )}
      {open && (
        <div className="mt-3 flex flex-col gap-3">
          <p className="text-sm text-muted">{info.does}</p>
          {info.risk && <p className="text-sm text-warn">Can break: {info.risk}</p>}
          {m.settingsOmitted && (
            <p className="text-xs text-muted">
              {m.settingsOmitted === "all"
                ? "The result was too large to list the settings; the module's state is as reported."
                : "The result was too large to list the settings that are in place."}
            </p>
          )}
          {findings.length > 0 ? (
            <SettingsTable findings={findings} catalog={catalogSettings} canChange={canChange && !reportOnly} chosen={chosenSettings} blocked={blockSettings} onChoose={onSetting} />
          ) : (
            m.settingsOmitted === undefined && <p className="text-sm text-muted">No per-setting findings were reported for this module.</p>
          )}
          {(m.managed ?? []).length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted">Held by another owner</h4>
              <ul className="mt-1 list-disc space-y-0.5 pl-4 text-sm break-words marker:text-subtle">
                {m.managed!.map((x, i) => (
                  <li key={i}>
                    <span className="font-mono text-xs">{x.id}</span> by {x.owner}: {x.policy} = {x.value}.{" "}
                    {x.state === "in_place" ? "As strict as EasyRMM wants, so it counts as in place." : "EasyRMM leaves it alone."}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {(m.notes ?? []).length > 0 && (
            <ul className="list-disc space-y-0.5 pl-4 text-sm break-words marker:text-subtle">
              {m.notes!.map((n, i) => (
                <li key={i}>{n}</li>
              ))}
            </ul>
          )}
          {m.related && <Related related={m.related} />}
        </div>
      )}
      {earlier && (
        <p className="mt-2 text-xs text-muted">
          From an earlier check, <When at={m.checkedAt} />
          {viewJobs && m.jobId && (
            <>
              {" · "}
              <Link to={`/jobs/${m.jobId}`} className="text-accent hover:underline">
                View the job
              </Link>
            </>
          )}
        </p>
      )}
    </li>
  );
}

function SettingsTable({ findings, catalog, canChange, chosen, blocked, onChoose }: {
  findings: HardeningSettingFinding[];
  catalog: Map<string, WindowsCatalogModule["settings"][number]>;
  canChange: boolean;
  chosen: Set<string>;
  blocked: boolean;
  onChoose: (id: string, on: boolean) => void;
}) {
  return (
    <TableWrap>
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="text-xs text-muted">
            {canChange && <th className="w-8 px-2 py-1.5" />}
            <th className="px-2 py-1.5 font-medium">Setting</th>
            <th className="px-2 py-1.5 font-medium">State</th>
            <th className="px-2 py-1.5 font-medium">Value now</th>
            <th className="px-2 py-1.5 font-medium">Wanted</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {findings.map((s, i) => {
            const meta = catalog.get(s.id);
            const st = settingState(s.state);
            const cite = meta ? CITE[meta.cite] : undefined;
            const changeable = s.state === "not_in_place" || s.state === "in_place";
            return (
              <tr key={`${s.id}-${s.item ?? ""}-${i}`} className="align-top">
                {canChange && (
                  <td className="px-2 py-1.5">
                    {meta && meta.tier > 0 && changeable && (
                      <input
                        type="checkbox"
                        aria-label={`Choose ${s.id}`}
                        className="size-4 accent-accent"
                        checked={chosen.has(s.id)}
                        disabled={blocked}
                        onChange={(e) => onChoose(s.id, e.target.checked)}
                      />
                    )}
                  </td>
                )}
                <td className="px-2 py-1.5">
                  <span className="block font-mono text-xs break-all">{s.id}</span>
                  {meta && <span className="block text-xs text-muted">{meta.what}</span>}
                  {s.item && <span className="block text-xs text-muted">{s.item}</span>}
                  {meta && (
                    <span className="mt-0.5 flex flex-wrap gap-1">
                      <Badge tone={tierMeta(meta.tier).tone} title={tierMeta(meta.tier).title}>
                        {tierMeta(meta.tier).label}
                      </Badge>
                      {cite && (
                        <Badge title={cite.title}>
                          {cite.label}
                        </Badge>
                      )}
                    </span>
                  )}
                </td>
                <td className="px-2 py-1.5">
                  <Badge tone={st.tone} title={st.title}>
                    {st.label}
                  </Badge>
                  {s.reasons && s.reasons.length > 0 && <span className="mt-0.5 block text-xs text-muted">{s.reasons.join(", ")}</span>}
                  {s.outcome && <span className="mt-0.5 block text-xs text-muted">{OUTCOMES[s.outcome] ?? s.outcome}</span>}
                </td>
                <td className="px-2 py-1.5 font-mono text-xs break-all">
                  {s.value ?? "—"}
                  {s.before !== undefined && s.before !== "" && <span className="block text-muted">was {s.before}</span>}
                </td>
                <td className="px-2 py-1.5 font-mono text-xs break-all">
                  {s.want ?? "—"}
                  {s.note && <span className="block font-sans text-muted">{s.note}</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableWrap>
  );
}

/** The controls a module's settings relate to. They say what a setting is mapped to, not that a computer complies. */
function Related({ related }: { related: HardeningRelated }) {
  const none = related.sp80053R5.length + related.sp800171R2.length + related.sp800171R3.length + related.iso27001.length === 0;
  if (none) return null;
  const line = (label: string, items: string[]) =>
    items.length > 0 && (
      <div>
        <dt className="text-xs font-medium text-muted">{label}</dt>
        <dd className="text-xs break-words">{items.join(", ")}</dd>
      </div>
    );
  return (
    <section aria-label="Related controls" className="rounded-md border border-line p-3">
      <h4 className="text-xs font-medium text-muted">Related controls</h4>
      <p className="mt-0.5 text-xs text-muted">Where published mappings relate this module's settings. This is not a statement that the computer complies.</p>
      <dl className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
        {line("NIST SP 800-53 Rev. 5", related.sp80053R5.map((c) => `${c.id} ${c.title}`))}
        {line("NIST SP 800-171 Rev. 2", related.sp800171R2)}
        {line("NIST SP 800-171 Rev. 3", related.sp800171R3)}
        {line("ISO/IEC 27001:2022 Annex A", related.iso27001)}
      </dl>
    </section>
  );
}

const ROLES: Record<string, string> = {
  workstation: "Workstation",
  member_server: "Member server",
  standalone_server: "Standalone server",
  domain_controller: "Domain controller",
  unknown: "Not reported",
};
const JOINED: Record<string, string> = { none: "Workgroup", domain: "Domain", entra: "Entra ID", domain_entra: "Domain and Entra ID", unknown: "Not reported" };

/** When the latest check ran, the computer as it read it, and who else holds settings on it. */
function LastCheck({ hardening: d, checkedAt }: { hardening: DeviceHardening; checkedAt: string }) {
  const w = d.platform?.windows;
  const items: [ReactNode, ReactNode][] = [["Checked", <When key="c" at={checkedAt} />]];
  if (w) {
    items.push(["Windows", `${w.edition}, ${w.displayVersion} (build ${w.build})`], ["Role", ROLES[w.role] ?? w.role], ["Joined to", JOINED[w.joined] ?? w.joined]);
    const owners = w.owners;
    if (owners) {
      const held = [
        owners.groupPolicyRecord === "read" && "Group Policy",
        owners.mdm && "MDM",
        owners.defenderForEndpoint && "Defender for Endpoint",
        owners.configMgr && "Configuration Manager",
        owners.dsc && "DSC",
        owners.azureMachineConfiguration && "Azure machine configuration",
      ].filter(Boolean);
      items.push(["Other owners", held.length > 0 ? held.join(", ") : "None found"]);
      if (owners.tamperProtected) items.push(["Tamper Protection", "On: Defender's own settings cannot be changed here"]);
    }
  }
  return (
    <Card title="Last check">
      <KeyValueList narrow items={items} />
      {w && w.checkOnlyReasons && w.checkOnlyReasons.length > 0 && (
        <p className="mt-2 text-xs text-muted">Apply is check only here: {w.checkOnlyReasons.join("; ")}.</p>
      )}
      {w && w.notes && w.notes.length > 0 && (
        <ul className="mt-2 list-disc space-y-0.5 pl-4 text-xs text-muted marker:text-subtle">
          {w.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** What changed and when: each guard (kept, waiting, undone by the computer), and the hardening runs. */
function History({ guards, runs, show, deviceId }: { guards: HardeningGuard[]; runs: ReturnType<typeof useList<JobRun>>; show: boolean; deviceId: string }) {
  if (guards.length === 0 && !show) return null;
  return (
    <Card
      title="History"
      padded={false}
      actions={
        show && (
          <Link to={`/jobs?kind=hardening&deviceId=${encodeURIComponent(deviceId)}`} className="text-xs text-accent hover:underline">
            All hardening jobs
          </Link>
        )
      }
    >
      <ul className="divide-y divide-line" aria-label="Hardening history">
        {guards.slice(0, SHOWN_RUNS).map((g) => {
          const s = GUARD_STATES[g.state];
          return (
            <li key={g.applyJobId} className="px-4 py-2.5 text-sm">
              <span className="flex items-center justify-between gap-2">
                <span className="font-medium">
                  Change of {g.settings.length} setting{g.settings.length === 1 ? "" : "s"}
                </span>
                <Badge tone={s.tone} title={s.title}>
                  {s.label}
                </Badge>
              </span>
              <span className="block text-xs text-muted">
                <When at={g.armedAt} />
                {g.decidedAt && <> · decided {formatRelative(g.decidedAt)}</>}
              </span>
              <span className="block font-mono text-xs break-words text-muted">{g.settings.join(", ")}</span>
            </li>
          );
        })}
        {show && runs.isError && <li><ErrorState error={runs.error} onRetry={() => void runs.refetch()} compact /></li>}
        {show &&
          runs.items.slice(0, SHOWN_RUNS).map((r) => (
            <li key={r.id}>
              <Link to={`/jobs/${r.jobId}/runs/${r.id}`} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm hover:bg-hover">
                <span className="min-w-0">
                  <span className="block truncate font-medium" title={r.scriptName}>
                    {r.scriptName}
                  </span>
                  <span className="text-xs text-muted">
                    <When at={r.createdAt} />
                  </span>
                  {r.error && <span className="line-clamp-2 block text-xs break-words text-danger">{r.error}</span>}
                </span>
                <RunStatusBadge status={r.status} cancelRequested={r.cancelRequested} />
              </Link>
            </li>
          ))}
      </ul>
    </Card>
  );
}

function Sources({ sources }: { sources: NonNullable<DeviceHardening["controlSources"]> }) {
  return (
    <Card title="Where the related controls come from">
      <ul className="space-y-1 text-xs text-muted">
        {sources.map((s) => (
          <li key={s.name}>
            {s.name} {s.version} ({s.date})
          </li>
        ))}
      </ul>
    </Card>
  );
}
