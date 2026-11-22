import { useEffect, useId, useState } from "react";
import { api } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { AfterInstallRestart, PatchTargets, RestartCheck, RestartCondition, RestartMode, RestartPlan } from "../../api/types";
import { Alert, ErrorState, Field, Select, Spinner } from "../../components/ui";
import { plural } from "../../lib/format";

// The pieces a restart is made of, shared by the restart dialog and a restart asked for with an install: how signed-in
// users are treated, how long an offline device is waited for, the servers ticked by name, and what the plan check found.

export const RESTART_MODES: { value: RestartMode; label: string; hint: string }[] = [
  { value: "Countdown", label: "Count down, then restart", hint: "Signed-in users see the countdown and can only restart sooner." },
  {
    value: "PromptWithDeadline",
    label: "Ask users, with a deadline",
    hint: "Users restart when it suits them or postpone, never past the deadline; then a five-minute countdown.",
  },
  { value: "PromptNoDeadline", label: "Ask users, no deadline", hint: "Users choose when. The restart fails if nobody agrees within 7 days." },
  { value: "Immediate", label: "Restart at once", hint: "No warning, even with users signed in." },
];

export const COUNTDOWNS = [1, 5, 10, 15, 30, 60];
export const DEADLINES = [15, 30, 60, 120, 240, 480, 1440, 3 * 1440, 7 * 1440];
export const EXPIRIES = [15, 30, 60, 120, 240, 480, 1440];

/** At most this many devices restart whether or not a restart is pending (the server says the same). */
export const MAX_ALWAYS = 100;

/** At most this many devices in one restart only where one is pending, or one install of every available update. */
export const MAX_BULK = 1000;

/** "15 minutes", "4 hours", "3 days". */
export function minutesText(m: number): string {
  if (m % 1440 === 0) return plural(m / 1440, "day");
  if (m % 60 === 0) return plural(m / 60, "hour");
  return plural(m, "minute");
}

/** A datetime-local value for a time, in the browser's zone. */
export function localInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Tonight at 22:00, or tomorrow's if that has passed. */
export function tonight(now = new Date()): Date {
  const d = new Date(now);
  d.setHours(22, 0, 0, 0);
  if (d.getTime() - now.getTime() < 15 * 60_000) d.setDate(d.getDate() + 1);
  return d;
}

/** How the people signed in are treated: the four ways, the countdown or deadline, and what the choice means. */
export function RestartModeFields({ mode, onMode, countdown, onCountdown, deadline, onDeadline }: {
  mode: RestartMode;
  onMode: (m: RestartMode) => void;
  countdown: number;
  onCountdown: (n: number) => void;
  deadline: number;
  onDeadline: (n: number) => void;
}) {
  const modeId = useId();
  // Unique per dialog: closed dialogs stay in the page, and radios that shared a name would share one choice.
  const name = useId();
  const hint = RESTART_MODES.find((m) => m.value === mode)!.hint;
  return (
    <fieldset className="space-y-2" aria-describedby={modeId}>
      <legend className="text-xs font-medium text-muted">Signed-in users</legend>
      {RESTART_MODES.map((m) => (
        <div key={m.value} className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <label className="flex items-center gap-2 text-sm">
            <input type="radio" name={name} checked={mode === m.value} onChange={() => onMode(m.value)} className="size-4 accent-accent" />
            {m.label}
          </label>
          {m.value === "Countdown" && mode === "Countdown" && (
            <Select aria-label="Countdown" value={countdown} onChange={(e) => onCountdown(Number(e.target.value))} className="w-auto">
              {COUNTDOWNS.map((n) => (
                <option key={n} value={n}>
                  {minutesText(n)}
                </option>
              ))}
            </Select>
          )}
          {m.value === "PromptWithDeadline" && mode === "PromptWithDeadline" && (
            <Select aria-label="Deadline" value={deadline} onChange={(e) => onDeadline(Number(e.target.value))} className="w-auto">
              {DEADLINES.map((n) => (
                <option key={n} value={n}>
                  within {minutesText(n)}
                </option>
              ))}
            </Select>
          )}
        </div>
      ))}
      <p id={modeId} className="text-xs text-muted">
        {hint}
      </p>
      {mode !== "Immediate" && (
        <p className="text-xs text-subtle">
          Nobody signed in: the device restarts at once. Without the EasyPatch icon (Linux, macOS, or Windows where it is not running), users get
          the system&apos;s shutdown warning, and asking waits for the deadline, or for the icon when there is none.
        </p>
      )}
    </fieldset>
  );
}

/** How long a restart waits for a device that is offline. */
export function ExpiryField({ value, onChange }: { value: number; onChange: (n: number) => void }) {
  const id = useId();
  return (
    <Field
      label="If a device is offline, wait for it"
      htmlFor={id}
      hint="If it does not come back in time, the patching engine drops its restart."
      className="w-fit"
    >
      <Select id={id} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-auto">
        {EXPIRIES.map((n) => (
          <option key={n} value={n}>
            {minutesText(n)}
          </option>
        ))}
      </Select>
    </Field>
  );
}

/** The servers a restart would reach, each restarted only once ticked by name. */
export function ServerTicks({ servers, confirmed, onChange, note }: {
  servers: RestartCheck[];
  confirmed: Set<string>;
  onChange: (next: Set<string>) => void;
  /** What happens to a server left unticked. */
  note: string;
}) {
  if (servers.length === 0) return null;
  const chosen = servers.filter((c) => confirmed.has(c.deviceId));
  const all = chosen.length === servers.length;
  const tick = (id: string, on: boolean) => {
    const next = new Set(confirmed);
    if (on) next.add(id);
    else next.delete(id);
    onChange(next);
  };
  return (
    <fieldset className="space-y-2">
      <legend className="mb-1 text-sm font-medium">Servers restart only when you tick them</legend>
      <p className="text-xs text-muted">{note}</p>
      <ul className="max-h-48 divide-y divide-line overflow-y-auto rounded-md border border-line">
        {servers.length > 1 && (
          <li className="px-3 py-2">
            <label className="flex items-center gap-2 text-sm font-medium">
              <input
                type="checkbox"
                checked={all}
                ref={(el) => {
                  if (el) el.indeterminate = chosen.length > 0 && !all;
                }}
                onChange={(e) => onChange(e.target.checked ? new Set(servers.map((c) => c.deviceId)) : new Set())}
                className="size-4 accent-accent"
              />
              {`All ${servers.length.toLocaleString()}`}
            </label>
          </li>
        )}
        {servers.map((c) => (
          <li key={c.deviceId} className="px-3 py-2">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={confirmed.has(c.deviceId)} onChange={(e) => tick(c.deviceId, e.target.checked)} className="size-4 accent-accent" />
              <span className="min-w-0 break-words">Restart {c.deviceName}</span>
              {!c.online && <span className="ml-auto shrink-0 text-xs text-muted">Offline</span>}
            </label>
          </li>
        ))}
      </ul>
    </fieldset>
  );
}

/** The devices that restart without being ticked, and those that will not restart, with why. */
export function PlanLists({ servers, others, skipped, restartsLabel = "Restarts" }: {
  servers: RestartCheck[];
  others: RestartCheck[];
  skipped: RestartCheck[];
  /** The heading over the devices that restart, when no server is listed above them. */
  restartsLabel?: string;
}) {
  return (
    <>
      {others.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-xs font-medium text-muted">{servers.length > 0 ? "Also restarts" : restartsLabel}</h3>
          <ul className="max-h-40 space-y-0.5 overflow-y-auto text-sm">
            {others.map((c) => (
              <li key={c.deviceId} className="flex items-baseline gap-2">
                <span className="min-w-0 break-words">{c.deviceName}</span>
                {!c.online && <span className="text-xs text-muted">Offline</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {skipped.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-xs font-medium text-muted">{servers.length + others.length > 0 ? "Not restarted" : "Nothing to restart"}</h3>
          <ul className="max-h-40 divide-y divide-line overflow-y-auto rounded-md border border-line">
            {skipped.map((c) => (
              <li key={c.deviceId} className="px-3 py-2 text-sm">
                <span className="font-medium">{c.deviceName}</span>
                <p className="text-muted">{c.reason}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

/** Whether devices restart once their install has finished: not at all, if the updates need it, or whatever they need. */
export type RestartChoice = "none" | RestartCondition;

/** Splits a restart plan into the servers to tick, the other devices that restart, and those that will not. */
export function splitPlan(plan: RestartPlan | undefined) {
  const checks = plan?.devices ?? [];
  return {
    servers: checks.filter((c) => c.restart && c.server),
    others: checks.filter((c) => c.restart && !c.server),
    skipped: checks.filter((c) => !c.restart),
  };
}

/**
 * The restart an install may ask for: the choice, how signed-in users are treated, how long an offline device is
 * waited for, and the servers ticked by name, checked with the server before anything is sent. Back to `initial` once
 * the dialog closes.
 */
export function useInstallRestart({ open, targets, count, initial }: {
  open: boolean;
  /** The install's devices; null while they are not known yet. */
  targets: PatchTargets | null;
  /** How many devices the install reaches. */
  count: number;
  initial: RestartChoice;
}) {
  const [choice, setChoice] = useState<RestartChoice>(initial);
  const [mode, setMode] = useState<RestartMode>("Countdown");
  const [countdown, setCountdown] = useState(5);
  const [deadline, setDeadline] = useState(240);
  const [expiry, setExpiry] = useState(120);
  const [confirmed, setConfirmed] = useState<Set<string>>(new Set());
  const name = useId();
  const plan = useApiMutation((body: PatchTargets & { condition: RestartCondition; afterInstall: true }) =>
    api.post<RestartPlan>("/patching/restart/plan", body),
  );
  const limit = choice === "Always" ? MAX_ALWAYS : MAX_BULK;
  const tooMany = choice !== "none" && count > limit;
  const key = targets ? JSON.stringify(targets) : "";
  const check = () => {
    if (choice === "none" || !key || tooMany) return;
    setConfirmed(new Set());
    plan.mutate({ ...(JSON.parse(key) as PatchTargets), condition: choice, afterInstall: true });
  };
  useEffect(() => {
    if (open) return;
    setChoice(initial);
    setMode("Countdown");
    setCountdown(5);
    setDeadline(240);
    setExpiry(120);
    setConfirmed(new Set());
    plan.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- back to the defaults when the dialog closes
  }, [open, initial]);
  useEffect(() => {
    if (open) check();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- check again when the choice or the devices change
  }, [open, choice, key, tooMany]);

  const { servers, others, skipped } = splitPlan(plan.data);
  const chosenServers = servers.filter((c) => confirmed.has(c.deviceId));
  const asked = choice !== "none";
  const restart: AfterInstallRestart | undefined = asked
    ? {
        condition: choice,
        mode,
        countdownMinutes: mode === "Countdown" ? countdown : undefined,
        deadlineMinutes: mode === "PromptWithDeadline" ? deadline : undefined,
        expiresAfterMinutes: expiry,
      }
    : undefined;
  const hint =
    choice === "none"
      ? "Updates that need a restart finish at the next one, which the device's patch policy may schedule."
      : choice === "OnlyIfPending"
        ? "Once its updates are installed, each device restarts if they need it to finish."
        : `Once its updates are installed, each device restarts whatever they need. At most ${MAX_ALWAYS.toLocaleString()} devices at once.`;
  const options: [RestartChoice, string][] = [
    ["none", "Don't restart"],
    ["OnlyIfPending", "Restart if the updates need it"],
    ["Always", "Restart when done"],
  ];

  const element = (
    <div className="space-y-4">
      <fieldset className="space-y-2">
        <legend className="text-xs font-medium text-muted">Afterwards</legend>
        {options.map(([value, label]) => (
          <label key={value} className="flex items-center gap-2 text-sm">
            <input type="radio" name={name} checked={choice === value} onChange={() => setChoice(value)} className="size-4 accent-accent" />
            {label}
          </label>
        ))}
        <p className="text-xs text-subtle">{hint}</p>
      </fieldset>
      {asked &&
        (tooMany ? (
          <Alert tone="warn" title={`At most ${limit.toLocaleString()} devices can restart after an install`}>
            {choice === "Always"
              ? `This install reaches ${plural(count, "device")}. Choose fewer, or restart only if the updates need it.`
              : `This install reaches ${plural(count, "device")}. Choose fewer, or don't restart.`}
          </Alert>
        ) : plan.isPending || plan.isIdle ? (
          <Spinner label="Checking which devices can restart…" />
        ) : plan.isError ? (
          <ErrorState error={plan.error} onRetry={check} compact />
        ) : (
          <>
            <ServerTicks
              servers={servers}
              confirmed={confirmed}
              onChange={setConfirmed}
              note="A restart interrupts everyone using the server. Servers you leave unticked still install their updates; they do not restart."
            />
            <PlanLists servers={servers} others={others} skipped={skipped} restartsLabel="Restarts after its install" />
            {servers.length + others.length > 0 && (
              <>
                <RestartModeFields
                  mode={mode}
                  onMode={setMode}
                  countdown={countdown}
                  onCountdown={setCountdown}
                  deadline={deadline}
                  onDeadline={setDeadline}
                />
                <ExpiryField value={expiry} onChange={setExpiry} />
              </>
            )}
          </>
        ))}
    </div>
  );

  return {
    choice,
    /** Nothing to wait for: no restart, or the check is back and the devices are not too many. */
    ready: !asked || (!tooMany && plan.isSuccess),
    /** What the install sends for the restart. */
    body: {
      restart,
      confirmServers: asked && chosenServers.length > 0 ? chosenServers.map((c) => c.deviceId) : undefined,
    },
    element,
  };
}
