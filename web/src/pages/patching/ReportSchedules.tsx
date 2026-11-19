import { useId, useState } from "react";
import { CalendarClock, Pencil } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchReportSchedule } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Badge, Button, Card, EmptyState, ErrorState, InlineError, SelectField, Spinner, TableWrap, TextareaField } from "../../components/ui";
import { addresses } from "../reports/PatchReports";

// Settings → Patching → Report schedules (one-product plan, C5): on a day of each month, EasyPatch makes each
// organization's report of the month before and emails it.

/** "5 December 2026", from 2006-01-02, as the organization's own date. */
function day(date: string): string {
  const [y, m, d] = date.split("-").map(Number);
  return new Date(y ?? 1970, (m ?? 1) - 1, d ?? 1).toLocaleDateString(undefined, { dateStyle: "long" });
}

function ordinal(n: number): string {
  const rules = new Intl.PluralRules("en", { type: "ordinal" });
  const suffix = { one: "st", two: "nd", few: "rd", other: "th" }[rules.select(n) as "one" | "two" | "few" | "other"] ?? "th";
  return `${n}${suffix}`;
}

export function ReportSchedules() {
  const list = useApi<PatchReportSchedule[]>("/patching/report-schedules");
  const [editing, setEditing] = useState<PatchReportSchedule | null>(null);
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  return (
    <Card title="Monthly report schedules" padded={false}>
      <p className="max-w-3xl px-4 pt-3 text-sm text-muted">
        On the day you choose, each organization&apos;s report of the month before is made and emailed to its recipients. Reports are
        emailed through EasyRMM&apos;s mail server, set with the EASYRMM_SMTP_ settings. Reports made on a schedule are listed under
        Reports → Monthly patch reports.
      </p>
      {list.data.length === 0 ? (
        <EmptyState title="No organizations to schedule" compact icon={<CalendarClock className="size-8" aria-hidden />}>
          Schedules belong to organizations in the patching engine whose patching you see as a whole.
        </EmptyState>
      ) : (
        <TableWrap className="mt-3 rounded-none border-x-0 border-b-0">
          <table className="table-base">
            <caption className="sr-only">Monthly report schedules</caption>
            <thead>
              <tr>
                <th scope="col">Organization</th>
                <th scope="col">Schedule</th>
                <th scope="col">Recipients</th>
                <th scope="col">Next report</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((s) => (
                <tr key={s.organizationId}>
                  <td className="font-medium">{s.organizationName}</td>
                  <td className="whitespace-nowrap">
                    {s.enabled ? (
                      <>
                        On the {ordinal(s.dayOfMonth)} of each month
                        <span className="block text-xs text-muted">{s.includeEndpointList ? "With each device" : "Summary only"}</span>
                      </>
                    ) : (
                      <Badge tone="neutral">Off</Badge>
                    )}
                  </td>
                  <td className="max-w-72">
                    {s.recipients.length > 0 ? <span className="break-words">{s.recipients.join(", ")}</span> : <span className="text-subtle">—</span>}
                  </td>
                  <td className="whitespace-nowrap">
                    {s.enabled && s.nextReportDate ? (
                      <>
                        {day(s.nextReportDate)}
                        <span className="block text-xs text-muted">{s.timeZone}</span>
                      </>
                    ) : (
                      <span className="text-subtle">—</span>
                    )}
                  </td>
                  <td className="text-right">
                    {s.canEdit && (
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={<Pencil className="size-3.5" aria-hidden />}
                        aria-label={`Change ${s.organizationName}'s schedule`}
                        onClick={() => setEditing(s)}
                      >
                        Change
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <ScheduleDialog key={editing?.organizationId ?? "closed"} schedule={editing} onClose={() => setEditing(null)} />
    </Card>
  );
}

function ScheduleDialog({ schedule, onClose }: { schedule: PatchReportSchedule | null; onClose: () => void }) {
  const toast = useToast();
  const [enabled, setEnabled] = useState(schedule?.enabled ?? false);
  const [dayOfMonth, setDayOfMonth] = useState(String(schedule?.dayOfMonth ?? 1));
  const [recipients, setRecipients] = useState((schedule?.recipients ?? []).join("\n"));
  const [devices, setDevices] = useState(schedule?.includeEndpointList ?? true);
  const ids = { enabled: useId(), devices: useId() };
  const save = useApiMutation(
    (s: PatchReportSchedule) =>
      api.put<PatchReportSchedule>(`/patching/report-schedules/${s.organizationId}`, {
        enabled,
        dayOfMonth: Number(dayOfMonth),
        recipients: addresses(recipients),
        includeEndpointList: devices,
      }),
    {
      invalidate: ["/patching/report-schedules", "/audit"],
      onSuccess: (s) => {
        toast.success(s.enabled ? `${s.organizationName}'s report is made on the ${ordinal(s.dayOfMonth)} of each month.` : `${s.organizationName}'s schedule is off.`);
        onClose();
      },
    },
  );
  return (
    <Dialog
      open={schedule !== null}
      onClose={onClose}
      title={schedule ? `${schedule.organizationName}'s monthly report` : "Monthly report"}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} onClick={() => schedule && save.mutate(schedule)}>
            Save schedule
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <label htmlFor={ids.enabled} className="flex items-start gap-2.5 text-sm">
          <input id={ids.enabled} type="checkbox" className="mt-0.5 size-4 accent-accent" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span>
            Make and email a report each month
            <span className="block text-xs text-muted">Of the month before, in the organization&apos;s time zone{schedule ? ` (${schedule.timeZone})` : ""}.</span>
          </span>
        </label>
        <SelectField
          label="Day of the month"
          hint="Up to the 28th, so that every month has it."
          value={dayOfMonth}
          onChange={(e) => setDayOfMonth(e.target.value)}
          error={fieldError(save.error, "dayOfMonth")}
          className="max-w-80"
        >
          {Array.from({ length: 28 }, (_, i) => String(i + 1)).map((d) => (
            <option key={d} value={d}>
              {ordinal(Number(d))}
            </option>
          ))}
        </SelectField>
        <TextareaField
          label="Recipients"
          hint="One address per line, up to 20. They also receive reports emailed by hand without recipients of their own."
          value={recipients}
          onChange={(e) => setRecipients(e.target.value)}
          error={fieldError(save.error, "recipients")}
          rows={3}
          placeholder="it@example.com"
        />
        <label htmlFor={ids.devices} className="flex items-start gap-2.5 text-sm">
          <input id={ids.devices} type="checkbox" className="mt-0.5 size-4 accent-accent" checked={devices} onChange={(e) => setDevices(e.target.checked)} />
          <span>
            List each device
            <span className="block text-xs text-muted">Adds a page per device. Leave it out for a short summary.</span>
          </span>
        </label>
        <InlineError error={save.error} fields={["dayOfMonth", "recipients"]} />
      </div>
    </Dialog>
  );
}
