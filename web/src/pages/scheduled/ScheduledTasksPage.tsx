import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { CalendarClock, Pause, Pencil, Play, Plus, History, XCircle } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList, useOrganizations, useSites } from "../../api/hooks";
import type {
  MaintenanceWindow,
  MissedRunRule,
  ScheduleKind,
  ScheduledRunState,
  ScheduledTask,
  ScheduledTaskInput,
  ScheduledTaskRun,
  ScheduledTaskState,
  Script,
  TaskSchedule,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import {
  Alert,
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Field,
  IconButton,
  InlineError,
  PageHeader,
  Select,
  Spinner,
  TableWrap,
  TextField,
  Toolbar,
  type Tone,
} from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";

const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const STATE_TONE: Record<ScheduledTaskState, Tone> = { active: "ok", paused: "warn", cancelled: "neutral", completed: "neutral" };
const RUN_TONE: Record<ScheduledRunState, Tone> = { pending: "info", running: "info", succeeded: "ok", failed: "danger", skipped: "neutral" };

/** One line saying when a task runs, in the zone of its site or organization. */
export function describeSchedule(s: TaskSchedule, timezone: string): string {
  const at = s.at ?? "";
  switch (s.kind) {
    case "once":
      return `Once, ${s.date} ${at} (${timezone})`;
    case "daily":
      return `Every day at ${at} (${timezone})`;
    case "weekly":
      return `${(s.days ?? []).map((d) => DAY_NAMES[d]).join(", ")} at ${at} (${timezone})`;
    case "monthly":
      return `Day ${s.dayOfMonth} of each month at ${at} (${timezone})`;
    case "interval": {
      const m = s.everyMinutes ?? 0;
      return m % 1440 === 0 ? `Every ${m / 1440} day(s)` : m % 60 === 0 ? `Every ${m / 60} hour(s)` : `Every ${m} minutes`;
    }
  }
}

export function useCanSchedule(): boolean {
  const { can, session } = useAuth();
  return session?.isSuperAdmin === true || can("script.run");
}

export function ScheduledTasksPage() {
  const url = useUrlState();
  const toast = useToast();
  const canSchedule = useCanSchedule();
  const state = url.get("state");
  const list = useList<ScheduledTask>("/scheduled-tasks", { state: state || undefined }, { keepPrevious: true });
  const [editing, setEditing] = useState<ScheduledTask | "new" | null>(null);
  const [cancelling, setCancelling] = useState<ScheduledTask | null>(null);
  const [history, setHistory] = useState<ScheduledTask | null>(null);

  const act = useApiMutation((v: { id: string; action: "pause" | "resume" | "cancel" }) => api.post<ScheduledTask>(`/scheduled-tasks/${v.id}/${v.action}`), {
    invalidate: ["/scheduled-tasks"],
    onSuccess: (t, v) => {
      toast.success(`${v.action === "pause" ? "Paused" : v.action === "resume" ? "Resumed" : "Cancelled"} ${t.name}.`);
      setCancelling(null);
    },
  });

  const newButton = (
    <Button variant="primary" onClick={() => setEditing("new")}>
      <Plus className="size-4" aria-hidden />
      New scheduled task
    </Button>
  );

  return (
    <>
      <PageHeader
        title="Scheduled tasks"
        subtitle="Run a library script on a schedule, in the time zone of the site or organization. The script is pinned by its SHA-256: if it changes, runs stop until you review and save the task again."
        actions={canSchedule ? newButton : undefined}
      />
      <Toolbar>
        <Select aria-label="State" value={state} onChange={(e) => url.set({ state: e.target.value })} className="max-w-[12rem]">
          <option value="">Every state</option>
          <option value="active">Active</option>
          <option value="paused">Paused</option>
          <option value="completed">Completed</option>
          <option value="cancelled">Cancelled</option>
        </Select>
      </Toolbar>

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.items.length === 0 ? (
        <EmptyState title="No scheduled tasks" icon={<CalendarClock className="size-8" aria-hidden />} action={canSchedule && !state ? newButton : undefined}>
          Schedule a script once, daily, weekly, monthly or on an interval.
        </EmptyState>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Name</th>
                <th className="hidden md:table-cell">Where</th>
                <th>Schedule</th>
                <th>Next run</th>
                <th>State</th>
                <th className="w-0">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((t) => (
                <tr key={t.id}>
                  <td>
                    <div className="font-medium text-fg">{t.name}</div>
                    <div className="text-xs text-muted">
                      <Link to={`/scripts/${t.scriptId}`} className="hover:text-fg">
                        {t.scriptName || "Script removed"}
                      </Link>{" "}
                      · owner {t.ownerEmail || "unknown"}
                    </div>
                    {t.scriptChanged && t.state !== "cancelled" && (
                      <Badge tone="danger" className="mt-1" title="The library script no longer matches the pinned SHA-256; runs fail until the task is saved again.">
                        Script changed
                      </Badge>
                    )}
                  </td>
                  <td className="hidden md:table-cell">{t.siteName ? `${t.organizationName} / ${t.siteName}` : t.organizationName}</td>
                  <td className="text-sm">{describeSchedule(t.schedule, t.timezone)}</td>
                  <td title={formatDateTime(t.nextRunAt)}>{t.nextRunAt ? formatRelative(t.nextRunAt) : "—"}</td>
                  <td>
                    <Badge tone={STATE_TONE[t.state]}>{t.state}</Badge>
                  </td>
                  <td>
                    <div className="flex gap-1">
                      <IconButton label={`History of ${t.name}`} onClick={() => setHistory(t)}>
                        <History className="size-4" aria-hidden />
                      </IconButton>
                      {t.canEdit && t.state === "active" && (
                        <IconButton label={`Pause ${t.name}`} onClick={() => act.mutate({ id: t.id, action: "pause" })}>
                          <Pause className="size-4" aria-hidden />
                        </IconButton>
                      )}
                      {t.canEdit && t.state === "paused" && (
                        <IconButton label={`Resume ${t.name}`} onClick={() => act.mutate({ id: t.id, action: "resume" })}>
                          <Play className="size-4" aria-hidden />
                        </IconButton>
                      )}
                      {t.canEdit && (t.state === "active" || t.state === "paused") && (
                        <>
                          <IconButton label={`Edit ${t.name}`} onClick={() => setEditing(t)}>
                            <Pencil className="size-4" aria-hidden />
                          </IconButton>
                          <IconButton label={`Cancel ${t.name}`} onClick={() => setCancelling(t)}>
                            <XCircle className="size-4" aria-hidden />
                          </IconButton>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {act.isError && <InlineError error={act.error} />}

      {editing && <TaskDialog task={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      {history && <HistoryDialog task={history} onClose={() => setHistory(null)} />}
      <ConfirmDialog
        open={cancelling !== null}
        onClose={() => setCancelling(null)}
        onConfirm={() => cancelling && act.mutate({ id: cancelling.id, action: "cancel" })}
        title="Cancel this task?"
        confirmLabel="Cancel task"
        tone="danger"
        loading={act.isPending}
        error={act.error}
      >
        {cancelling?.name} will not run again. Its history stays. Cancelling cannot be undone; pause the task to keep it.
      </ConfirmDialog>
    </>
  );
}

function HistoryDialog({ task, onClose }: { task: ScheduledTask; onClose: () => void }) {
  const runs = useList<ScheduledTaskRun>(`/scheduled-tasks/${task.id}/runs`);
  return (
    <Dialog open onClose={onClose} title={`History of ${task.name}`} size="lg">
      {runs.isPending ? (
        <Spinner />
      ) : runs.isError ? (
        <ErrorState error={runs.error} onRetry={() => void runs.refetch()} compact />
      ) : runs.items.length === 0 ? (
        <p className="text-sm text-muted">It has not run yet.</p>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Scheduled for</th>
                <th>Result</th>
                <th>Jobs</th>
              </tr>
            </thead>
            <tbody>
              {runs.items.map((r) => (
                <tr key={r.id}>
                  <td>{formatDateTime(r.scheduledFor)}</td>
                  <td>
                    <Badge tone={RUN_TONE[r.state]}>{r.state}</Badge>
                    {r.detail && <div className="mt-1 text-xs text-muted">{r.detail.trim()}</div>}
                  </td>
                  <td>
                    {r.jobIds.length === 0
                      ? "—"
                      : r.jobIds.map((id, i) => (
                          <Link key={id} to={`/jobs/${id}`} className="mr-2 text-accent hover:underline">
                            Job {i + 1}
                          </Link>
                        ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Dialog>
  );
}

const hhmm = (v: string | undefined) => v ?? "03:00";

function TaskDialog({ task, onClose }: { task: ScheduledTask | null; onClose: () => void }) {
  const toast = useToast();
  const orgs = useOrganizations();
  const [name, setName] = useState(task?.name ?? "");
  const [organizationId, setOrganizationId] = useState(task?.organizationId ?? "");
  const [siteId, setSiteId] = useState(task?.siteId ?? "");
  const [scriptId, setScriptId] = useState(task?.scriptId ?? "");
  const [args, setArgs] = useState((task?.scriptArgs ?? []).join("\n"));
  const [kind, setKind] = useState<ScheduleKind>(task?.schedule.kind ?? "daily");
  const [date, setDate] = useState(task?.schedule.date ?? "");
  const [at, setAt] = useState(hhmm(task?.schedule.at));
  const [days, setDays] = useState<number[]>(task?.schedule.days ?? [1]);
  const [dayOfMonth, setDayOfMonth] = useState(task?.schedule.dayOfMonth ?? 1);
  const [every, setEvery] = useState(task?.schedule.everyMinutes ?? 60);
  const [rule, setRule] = useState<MissedRunRule>(task?.missedRunRule ?? "skip");
  const [waitHours, setWaitHours] = useState(task?.waitHours ?? 24);
  const [repin, setRepin] = useState(false);
  const [windowId, setWindowId] = useState(task?.windowId ?? "");
  const [stagger, setStagger] = useState(task?.staggerMinutes ?? 0);
  const [onlyOnline, setOnlyOnline] = useState(task?.onlyIfOnline ?? false);
  const windows = useApi<{ windows: MaintenanceWindow[] }>(
    organizationId ? `/organizations/${organizationId}/maintenance-windows` : null,
    { siteId: siteId || undefined, purpose: "tasks" },
  );
  const sites = useSites(organizationId || null);
  const scripts = useList<Script>("/scripts", organizationId ? { organizationId, siteId: siteId || undefined } : undefined);

  const save = useApiMutation(
    (schedule: TaskSchedule) => {
      const scriptArgs = args.split("\n").filter((a) => a !== "");
      if (task) {
        return api.patch<ScheduledTask>(`/scheduled-tasks/${task.id}`, {
          name,
          scriptId: scriptId || undefined,
          scriptArgs,
          schedule,
          missedRunRule: rule,
          waitHours,
          repin,
          windowId: windowId || undefined,
          clearWindow: windowId === "",
          staggerMinutes: stagger,
          onlyIfOnline: onlyOnline,
        });
      }
      const input: ScheduledTaskInput = {
        name,
        organizationId,
        siteId: siteId || null,
        scriptId,
        scriptArgs,
        deviceIds: [],
        schedule,
        missedRunRule: rule,
        waitHours,
        windowId: windowId || null,
        staggerMinutes: stagger,
        onlyIfOnline: onlyOnline,
      };
      return api.post<ScheduledTask>("/scheduled-tasks", input);
    },
    {
      invalidate: ["/scheduled-tasks"],
      onSuccess: (t) => {
        toast.success(`Saved ${t.name}.`);
        onClose();
      },
    },
  );

  function submit(e: FormEvent) {
    e.preventDefault();
    const schedule: TaskSchedule = { kind };
    if (kind !== "interval") schedule.at = at;
    if (kind === "once") schedule.date = date;
    if (kind === "weekly") schedule.days = days;
    if (kind === "monthly") schedule.dayOfMonth = dayOfMonth;
    if (kind === "interval") schedule.everyMinutes = every;
    save.mutate(schedule);
  }

  return (
    <Dialog open onClose={onClose} title={task ? `Edit ${task.name}` : "New scheduled task"} size="lg">
      <form onSubmit={submit} className="flex flex-col gap-4">
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} />
        {!task && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Organization" htmlFor="st-org" required>
              <Select
                id="st-org"
                value={organizationId}
                onChange={(e) => {
                  setOrganizationId(e.target.value);
                  setSiteId("");
                  setScriptId("");
                }}
                required
              >
                <option value="">Choose…</option>
                {orgs.items.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Site" htmlFor="st-site" hint="Leave empty for every site of the organization.">
              <Select
                id="st-site"
                value={siteId}
                onChange={(e) => {
                  setSiteId(e.target.value);
                  setScriptId("");
                }}
                disabled={!organizationId}
              >
                <option value="">Every site</option>
                {sites.items.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        )}
        <Field label="Script" htmlFor="st-script" required hint="Pinned by its SHA-256 when you save. Devices are picked at each run: every device here the script can run on.">
          <Select id="st-script" value={scriptId} onChange={(e) => setScriptId(e.target.value)} required disabled={!organizationId && !task}>
            <option value="">Choose…</option>
            {task && !scripts.items.some((s) => s.id === task.scriptId) && <option value={task.scriptId}>{task.scriptName}</option>}
            {scripts.items.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </Select>
        </Field>
        {task?.scriptChanged && (
          <Alert tone="warn" title="The script has changed since it was pinned">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={repin} onChange={(e) => setRepin(e.target.checked)} />
              I have reviewed the script and want this task to run its current version.
            </label>
          </Alert>
        )}
        <Field label="Arguments" htmlFor="st-args" hint="One per line.">
          <textarea id="st-args" className="input font-mono text-sm" rows={2} value={args} onChange={(e) => setArgs(e.target.value)} />
        </Field>

        <fieldset className="flex flex-col gap-3 rounded-lg border border-line p-3">
          <legend className="px-1 text-xs font-medium text-muted">When</legend>
          <Field label="Repeat" htmlFor="st-kind">
            <Select id="st-kind" value={kind} onChange={(e) => setKind(e.target.value as ScheduleKind)}>
              <option value="once">Once</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
              <option value="interval">Every so often</option>
            </Select>
          </Field>
          {kind === "once" && <TextField label="Date" type="date" value={date} onChange={(e) => setDate(e.target.value)} required />}
          {kind !== "interval" && <TextField label="Time" type="time" value={at} onChange={(e) => setAt(e.target.value)} required hint="In the time zone of the site, or of the organization." />}
          {kind === "weekly" && (
            <div role="group" aria-label="Days" className="flex flex-wrap gap-2">
              {DAY_NAMES.map((n, d) => (
                <label key={n} className="flex items-center gap-1 text-sm">
                  <input
                    type="checkbox"
                    checked={days.includes(d)}
                    onChange={(e) => setDays(e.target.checked ? [...days, d].sort() : days.filter((x) => x !== d))}
                  />
                  {n}
                </label>
              ))}
            </div>
          )}
          {kind === "monthly" && (
            <TextField
              label="Day of the month"
              type="number"
              min={1}
              max={31}
              value={dayOfMonth}
              onChange={(e) => setDayOfMonth(Number(e.target.value))}
              hint="In a shorter month, the last day."
            />
          )}
          {kind === "interval" && <TextField label="Every (minutes)" type="number" min={5} max={10080} value={every} onChange={(e) => setEvery(Number(e.target.value))} />}
        </fieldset>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="If the server was down at that time" htmlFor="st-rule" hint="A long outage runs at most once, never once per missed time.">
            <Select id="st-rule" value={rule} onChange={(e) => setRule(e.target.value as MissedRunRule)}>
              <option value="skip">Skip it</option>
              <option value="run_asap">Run as soon as the server is back</option>
            </Select>
          </Field>
          <TextField
            label="Wait for an offline device (hours)"
            type="number"
            min={1}
            max={168}
            value={waitHours}
            onChange={(e) => setWaitHours(Number(e.target.value))}
            hint="Each job waits this long for a device that is offline."
          />
        </div>
        <fieldset className="grid gap-4 sm:grid-cols-2">
          <legend className="mb-1 text-sm font-medium">Maintenance window</legend>
          <Field label="Only run in the window" htmlFor="st-window" hint="The task is skipped, with a note in its history, if the window is closed when it fires. With a window and no site, it reaches the window's site.">
            <Select id="st-window" value={windowId} onChange={(e) => setWindowId(e.target.value)}>
              <option value="">Any time</option>
              {(windows.data?.windows ?? []).map((w) => (
                <option key={w.id} value={w.id}>
                  {w.siteName ? `${w.siteName}: ` : ""}
                  {w.name}
                </option>
              ))}
            </Select>
          </Field>
          <TextField
            label="Stagger starts over (minutes)"
            type="number"
            min={0}
            max={1440}
            value={stagger}
            onChange={(e) => setStagger(Number(e.target.value))}
            hint="A site's devices start one after another over this long, so they never restart at once. 0 starts them together."
            error={fieldError(save.error, "staggerMinutes")}
          />
          <label className="flex items-center gap-2 text-sm sm:col-span-2">
            <input type="checkbox" className="size-4 accent-accent" checked={onlyOnline} onChange={(e) => setOnlyOnline(e.target.checked)} />
            Only devices that are online when it starts (offline ones get no job)
          </label>
        </fieldset>
        <p className="text-xs text-muted">
          Saving asks you to confirm a second factor. The task runs with your permissions, checked again at every run.
        </p>
        <InlineError error={save.error} fields={["name", "schedule", "windowId", "staggerMinutes"]} />
        <div className="flex justify-end gap-2">
          <Button type="button" onClick={onClose}>
            Close
          </Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
