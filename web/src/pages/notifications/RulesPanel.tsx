import { useState } from "react";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList, useOrganizations, useSites } from "../../api/hooks";
import type { DeviceGroup, NotificationChannel, NotificationRule, NotificationRuleInput, RuleListFilter, RuleValueFilter } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, Segmented, Spinner, TableWrap, TextField } from "../../components/ui";

const RULES = "/notifications/rules";
const CHANNELS = "/notifications/channels";

const KINDS = [
  { value: "server", label: "Servers" },
  { value: "workstation", label: "Workstations" },
];
const SEVERITIES = [
  { value: "warning", label: "Warning" },
  { value: "critical", label: "Critical" },
];
const CONDITIONS = [
  { value: "offline", label: "Offline" },
  { value: "cpu", label: "Processor" },
  { value: "memory", label: "Memory" },
  { value: "disk", label: "Disk" },
  { value: "disk_health", label: "Disk health" },
  { value: "agent_removed", label: "Agent removed without a request" },
];
const CHECKS = [
  { value: "failing", label: "Failing" },
  { value: "errors", label: "Errors" },
  { value: "pending", label: "Pending sectors" },
  { value: "wear", label: "Wear" },
  { value: "temperature", label: "Temperature" },
];

const ANY_LIST: RuleListFilter = { mode: "any", ids: [] };
const ANY_VALUE: RuleValueFilter = { mode: "any", values: [] };

function blank(organizationId: string | null): NotificationRuleInput {
  return {
    organizationId,
    source: "alerts",
    name: "",
    enabled: true,
    organizations: ANY_LIST,
    sites: ANY_LIST,
    groups: ANY_LIST,
    deviceKinds: ANY_VALUE,
    severities: ANY_VALUE,
    conditions: ANY_VALUE,
    checks: ANY_VALUE,
    waitMinutes: 0,
    onResolve: true,
    onAcknowledge: false,
    reminderHours: 0,
    ignoreWindows: false,
    groupOutages: true,
    channelIds: [],
  };
}

function describe(r: NotificationRule): string {
  const parts: string[] = [];
  const list = (label: string, f: RuleListFilter) => f.mode === "list" && parts.push(`${label}: ${f.ids.length === 0 ? "none left" : f.ids.length}`);
  list("organizations", r.organizations);
  list("sites", r.sites);
  list("groups", r.groups);
  const value = (label: string, f: RuleValueFilter) => f.mode === "list" && parts.push(`${label}: ${f.values.join(", ") || "none"}`);
  value("kinds", r.deviceKinds);
  value("severity", r.severities);
  value("conditions", r.conditions);
  return parts.length === 0 ? (r.source === "notices" ? "Every notice" : "Every alert") : parts.join("; ");
}

/**
 * Device alert rules (ADR-0053): what each rule is about, when it notifies, and the channels it tells. An
 * organization's rules sit on its Notifications tab; the platform's, which may name organizations, under Settings.
 */
export function RulesPanel({ organizationId }: { organizationId: string | null }) {
  const { isSuperAdmin } = useAuth();
  const q = useApi<{ rules: NotificationRule[] }>(RULES, { organizationId }, { refetchInterval: 20_000 });
  const [editing, setEditing] = useState<NotificationRule | "new" | null>(null);
  const [deleting, setDeleting] = useState<NotificationRule | null>(null);
  const toast = useToast();
  const canManage = organizationId !== null || isSuperAdmin;
  const flip = useApiMutation((r: NotificationRule) => api.put<NotificationRule>(`${RULES}/${r.id}`, { ...r, enabled: !r.enabled }), { invalidate: [RULES, "/audit"] });
  const remove = useApiMutation((r: NotificationRule) => api.del(`${RULES}/${r.id}`), {
    invalidate: [RULES, "/audit"],
    onSuccess: () => {
      setDeleting(null);
      toast.success("Rule deleted. Channels already told of an alert are still told how it ends.");
    },
  });
  const rules = q.data?.rules ?? [];
  return (
    <>
      <Card
        title="Rules"
        actions={
          canManage && (
            <Button variant="primary" size="sm" icon={<Plus className="size-4" aria-hidden />} onClick={() => setEditing("new")}>
              Add rule
            </Button>
          )
        }
        padded={false}
      >
        {q.isPending ? (
          <div className="p-4">
            <Spinner />
          </div>
        ) : q.isError ? (
          <div className="p-4">
            <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
          </div>
        ) : rules.length === 0 ? (
          <EmptyState title="No rules yet" compact>
            A rule says which alerts are sent, when, and to which channels. Nothing is sent until one exists.
          </EmptyState>
        ) : (
          <TableWrap className="rounded-none border-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-muted">
                  <th className="px-4 py-2 font-medium">Rule</th>
                  <th className="px-4 py-2 font-medium">About</th>
                  <th className="px-4 py-2 font-medium">When</th>
                  <th className="px-4 py-2 font-medium">Channels</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id} className="border-b border-line last:border-0">
                    <td className="px-4 py-2 align-top">
                      <div className="font-medium">{r.name}</div>
                      {!r.enabled && <Badge tone="neutral">Off</Badge>}{" "}
                      {r.matchesNothing && (
                        <Badge tone="warn" title="Every site, group or organization it listed was deleted">
                          Matches nothing
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-2 align-top text-xs">{describe(r)}</td>
                    <td className="px-4 py-2 align-top text-xs">
                      {r.waitMinutes > 0 ? `After ${r.waitMinutes} min` : "At once"}
                      {r.reminderHours > 0 && `, reminders every ${r.reminderHours} h`}
                    </td>
                    <td className="px-4 py-2 align-top text-xs">{r.channelIds.length}</td>
                    <td className="whitespace-nowrap px-4 py-2 text-right align-top">
                      {canManage && (
                        <>
                          <Button size="sm" variant="ghost" loading={flip.isPending && flip.variables?.id === r.id} onClick={() => flip.mutate(r)}>
                            {r.enabled ? "Turn off" : "Turn on"}
                          </Button>
                          <Button size="sm" variant="ghost" icon={<Pencil className="size-4" aria-hidden />} onClick={() => setEditing(r)}>
                            Edit
                          </Button>
                          <Button size="sm" variant="danger-ghost" icon={<Trash2 className="size-4" aria-hidden />} onClick={() => setDeleting(r)}>
                            Delete
                          </Button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
      {editing && <RuleDialog organizationId={organizationId} rule={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title={`Delete ${deleting?.name ?? "rule"}?`}
        confirmLabel="Delete rule"
        onConfirm={() => deleting && remove.mutate(deleting)}
        loading={remove.isPending} tone="danger"
      >
        What it has not started telling is not sent. Channels already told that an alert opened are still told that it resolved.
      </ConfirmDialog>
    </>
  );
}

function ChoiceList({ label, options, filter, onChange }: { label: string; options: { value: string; label: string }[]; filter: RuleValueFilter; onChange: (f: RuleValueFilter) => void }) {
  return (
    <fieldset className="flex flex-col gap-1.5">
      <legend className="mb-1 flex items-center gap-3 text-sm font-medium">
        {label}
        <Segmented
          label={`${label}: any or a list`}
          value={filter.mode}
          options={[
            { value: "any", label: "Any" },
            { value: "list", label: "List" },
          ]}
          onChange={(mode) => onChange({ ...filter, mode })}
        />
      </legend>
      {filter.mode === "list" &&
        options.map((o) => (
          <label key={o.value} className="flex items-center gap-2.5 text-sm">
            <input
              type="checkbox"
              className="size-4 accent-accent"
              checked={filter.values.includes(o.value)}
              onChange={(e) => onChange({ ...filter, values: e.target.checked ? [...filter.values, o.value] : filter.values.filter((v) => v !== o.value) })}
            />
            {o.label}
          </label>
        ))}
    </fieldset>
  );
}

function RowChoice({ label, rows, filter, onChange }: { label: string; rows: { id: string; name: string }[]; filter: RuleListFilter; onChange: (f: RuleListFilter) => void }) {
  return (
    <fieldset className="flex flex-col gap-1.5">
      <legend className="mb-1 flex items-center gap-3 text-sm font-medium">
        {label}
        <Segmented
          label={`${label}: any or a list`}
          value={filter.mode}
          options={[
            { value: "any", label: "Any" },
            { value: "list", label: "List" },
          ]}
          onChange={(mode) => onChange({ ...filter, mode })}
        />
      </legend>
      {filter.mode === "list" &&
        rows.map((o) => (
          <label key={o.id} className="flex items-center gap-2.5 text-sm">
            <input
              type="checkbox"
              className="size-4 accent-accent"
              checked={filter.ids.includes(o.id)}
              onChange={(e) => onChange({ ...filter, ids: e.target.checked ? [...filter.ids, o.id] : filter.ids.filter((v) => v !== o.id) })}
            />
            {o.name}
          </label>
        ))}
    </fieldset>
  );
}

function SiteGroups({ siteId, siteName, filter, onChange }: { siteId: string; siteName: string; filter: RuleListFilter; onChange: (f: RuleListFilter) => void }) {
  const groups = useList<DeviceGroup>(`/sites/${siteId}/device-groups`);
  const rows = (groups.data?.items ?? []).map((g) => ({ id: g.id, name: `${siteName}: ${g.name}` }));
  if (rows.length === 0) return null;
  return (
    <>
      {rows.map((o) => (
        <label key={o.id} className="flex items-center gap-2.5 text-sm">
          <input
            type="checkbox"
            className="size-4 accent-accent"
            checked={filter.ids.includes(o.id)}
            onChange={(e) => onChange({ ...filter, ids: e.target.checked ? [...filter.ids, o.id] : filter.ids.filter((v) => v !== o.id) })}
          />
          {o.name}
        </label>
      ))}
    </>
  );
}

function RuleDialog({ organizationId, rule, onClose }: { organizationId: string | null; rule: NotificationRule | null; onClose: () => void }) {
  const toast = useToast();
  const [r, setR] = useState<NotificationRuleInput>(rule ?? blank(organizationId));
  const orgs = useOrganizations();
  const sites = useSites(organizationId);
  const channels = useApi<{ channels: NotificationChannel[] }>(CHANNELS, { organizationId });
  const save = useApiMutation((input: NotificationRuleInput) => (rule ? api.put<NotificationRule>(`${RULES}/${rule.id}`, input) : api.post<NotificationRule>(RULES, input)), {
    invalidate: [RULES, "/audit"],
    onSuccess: () => {
      toast.success(rule ? "Rule saved." : "Rule added.");
      onClose();
    },
  });
  const set = <K extends keyof NotificationRuleInput>(key: K, v: NotificationRuleInput[K]) => setR((cur) => ({ ...cur, [key]: v }));
  const allSites = sites.data?.items ?? [];
  const picked = r.sites.mode === "list" ? allSites.filter((s) => r.sites.ids.includes(s.id)) : organizationId ? allSites : [];
  const usable = (channels.data?.channels ?? []).filter((c) => c.enabled);
  return (
    <Dialog open onClose={onClose} title={rule ? `Edit ${rule.name}` : "Add a rule"} size="lg" description="Each filter is any, or a list. A list that ends up empty matches nothing.">
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(r);
        }}
      >
        <TextField label="Name" required value={r.name} maxLength={100} onChange={(e) => set("name", e.target.value)} error={fieldError(save.error, "name")} />
        <Segmented
          label="What the rule is about"
          value={r.source}
          options={[
            { value: "alerts", label: "Device alerts" },
            { value: "notices", label: "Notices" },
          ]}
          onChange={(v) => set("source", v)}
        />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {organizationId === null && <RowChoice label="Organizations" rows={orgs.data?.items ?? []} filter={r.organizations} onChange={(f) => set("organizations", f)} />}
          <RowChoice label="Sites" rows={allSites.map((s) => ({ id: s.id, name: organizationId === null ? `${s.organizationName}: ${s.name}` : s.name }))} filter={r.sites} onChange={(f) => set("sites", f)} />
          {r.source === "alerts" && (
            <fieldset className="flex flex-col gap-1.5">
              <legend className="mb-1 flex items-center gap-3 text-sm font-medium">
                Device groups
                <Segmented
                  label="Device groups: any or a list"
                  value={r.groups.mode}
                  options={[
                    { value: "any", label: "Any" },
                    { value: "list", label: "List" },
                  ]}
                  onChange={(mode) => set("groups", { ...r.groups, mode })}
                />
              </legend>
              {r.groups.mode === "list" && picked.length === 0 && <span className="text-xs text-muted">Choose sites first; their groups are listed here.</span>}
              {r.groups.mode === "list" && picked.map((s) => <SiteGroups key={s.id} siteId={s.id} siteName={s.name} filter={r.groups} onChange={(f) => set("groups", f)} />)}
            </fieldset>
          )}
          {r.source === "alerts" && <ChoiceList label="Kind of device" options={KINDS} filter={r.deviceKinds} onChange={(f) => set("deviceKinds", f)} />}
          {r.source === "alerts" && <ChoiceList label="Severity" options={SEVERITIES} filter={r.severities} onChange={(f) => set("severities", f)} />}
          {r.source === "alerts" && <ChoiceList label="Condition" options={CONDITIONS} filter={r.conditions} onChange={(f) => set("conditions", f)} />}
          {r.source === "alerts" && r.conditions.mode === "list" && r.conditions.values.includes("disk_health") && (
            <ChoiceList label="Disk health checks" options={CHECKS} filter={r.checks} onChange={(f) => set("checks", f)} />
          )}
        </div>
        <fieldset className="flex flex-col gap-3 rounded-lg border border-line p-3">
          <legend className="px-1 text-sm font-medium">When it notifies</legend>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <TextField
              label="Wait before telling (minutes)"
              type="number"
              min={0}
              max={1440}
              value={r.waitMinutes}
              onChange={(e) => set("waitMinutes", Number(e.target.value))}
              hint="On top of the policy's own minutes. An alert resolved or acknowledged before then sends nothing."
              error={fieldError(save.error, "waitMinutes")}
            />
            <TextField
              label="Remind every (hours, 0 for never)"
              type="number"
              min={0}
              max={720}
              value={r.reminderHours}
              onChange={(e) => set("reminderHours", Number(e.target.value))}
              hint="While the alert is open and not acknowledged."
              error={fieldError(save.error, "reminderHours")}
            />
          </div>
          <label className="flex items-center gap-2.5 text-sm">
            <input type="checkbox" className="size-4 accent-accent" checked={r.onResolve} onChange={(e) => set("onResolve", e.target.checked)} />
            Tell people (email, Slack, Teams) when an alert resolves. A webhook told that an alert opened is always told that it resolved.
          </label>
          <label className="flex items-center gap-2.5 text-sm">
            <input type="checkbox" className="size-4 accent-accent" checked={r.onAcknowledge} onChange={(e) => set("onAcknowledge", e.target.checked)} />
            Tell webhooks when an alert is acknowledged, with who and when.
          </label>
          <label className="flex items-center gap-2.5 text-sm">
            <input type="checkbox" className="size-4 accent-accent" checked={r.groupOutages} onChange={(e) => set("groupOutages", e.target.checked)} />
            Group a site&apos;s offline alerts into one item when every device there is offline.
          </label>
          {organizationId === null && (
            <label className="flex items-center gap-2.5 text-sm">
              <input type="checkbox" className="size-4 accent-accent" checked={r.ignoreWindows} onChange={(e) => set("ignoreWindows", e.target.checked)} />
              Ignore sites&apos; maintenance windows.
            </label>
          )}
        </fieldset>
        <fieldset className="flex flex-col gap-1.5">
          <legend className="mb-1 text-sm font-medium">Channels (1 to 20)</legend>
          {channels.isPending && <Spinner />}
          {!channels.isPending && usable.length === 0 && <Alert tone="warn">Add a channel first; a rule tells the channels it names.</Alert>}
          {usable.map((c) => (
            <label key={c.id} className="flex items-center gap-2.5 text-sm">
              <input
                type="checkbox"
                className="size-4 accent-accent"
                checked={r.channelIds.includes(c.id)}
                onChange={(e) => set("channelIds", e.target.checked ? [...r.channelIds, c.id] : r.channelIds.filter((v) => v !== c.id))}
              />
              {c.name} <span className="text-xs text-muted">({c.kind}{c.platform ? ", platform" : ""})</span>
            </label>
          ))}
        </fieldset>
        <InlineError error={save.error} fields={["name", "waitMinutes", "reminderHours"]} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            {rule ? "Save rule" : "Add rule"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
