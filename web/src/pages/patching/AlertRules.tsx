import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { BellPlus, Pencil, Plus, Trash2 } from "lucide-react";
import { api, ApiError, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchAlertRule, PatchAlertRuleInput, PatchAlertRuleKind, PatchAlertRuleList, PatchAlertSeverity, PatchTagList } from "../../api/types";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { OrganizationSelect } from "../../components/Filters";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, IconButton, SelectField, Spinner, TableWrap, TextField } from "../../components/ui";
import { plural } from "../../lib/format";
import { PatchSeverityBadge, RULE_KIND_ORDER, RULE_KINDS, SEVERITIES, thresholdText } from "./patchAlertText";

// Settings → Patching → Alert rules (one-product plan, C7): what makes EasyPatch raise an alert, for which organizations
// and devices, and where it sends it. Server-wide, so only super administrators see and change them, with the bundled
// engine: a connected server keeps them in its own console.

/** A connected server's rules and channels are its console's: said, not shown as a failure. */
export function ServerWideNotice({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  if (error instanceof ApiError && error.code === "easypatch_server_wide") {
    return (
      <Alert tone="info" title="Set in EasyPatch">
        {error.message}
      </Alert>
    );
  }
  return <ErrorState error={error} onRetry={onRetry} />;
}

function covers(r: PatchAlertRule): string {
  if (r.unlinkedOrganization) return "An EasyPatch organization EasyRMM does not link";
  const where = r.organizationName ?? "Every organization";
  return r.tagName ? `${where}, devices tagged ${r.tagName}` : where;
}

export function AlertRulesPanel() {
  const toast = useToast();
  const list = useApi<PatchAlertRuleList>("/patching/alert-rules");
  const [form, setForm] = useState<{ open: boolean; rule?: PatchAlertRule }>({ open: false });
  const [deleting, setDeleting] = useState<PatchAlertRule | null>(null);
  const remove = useApiMutation((r: PatchAlertRule) => api.del(`/patching/alert-rules/${r.id}`), {
    invalidate: ["/patching"],
    onSuccess: (_, r) => {
      toast.success(`${r.name} deleted.`);
      setDeleting(null);
    },
  });
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ServerWideNotice error={list.error} onRetry={() => void list.refetch()} />;
  const { items, channels } = list.data;
  const channelName = (id: string) => channels.find((c) => c.id === id)?.name ?? "A deleted channel";

  return (
    <Card
      title="Alert rules"
      padded={false}
      actions={
        <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setForm({ open: true })}>
          Add rule
        </Button>
      }
    >
      <div className="border-b border-line px-4 py-3">
        <p className="max-w-3xl text-sm text-muted">
          EasyPatch checks these rules every 2 minutes and opens an alert for each device, or organization, that matches; it resolves the
          alert once the cause is gone. Alerts show under Patching → Alerts, and each rule&apos;s channels send them on.
        </p>
      </div>
      {items.length === 0 ? (
        <EmptyState title="No alert rules" icon={<BellPlus className="size-8" aria-hidden />}>
          Without rules, EasyPatch raises no alerts.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <caption className="sr-only">Alert rules</caption>
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col" className="hidden md:table-cell">
                  Raises an alert
                </th>
                <th scope="col" className="hidden lg:table-cell">
                  Covers
                </th>
                <th scope="col" className="hidden lg:table-cell">
                  Sends to
                </th>
                <th scope="col" className="hidden text-right sm:table-cell">
                  Open
                </th>
                <th scope="col" className="w-0">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className="align-top">
                  <td>
                    <div className="flex flex-col items-start gap-1">
                      <span className="flex flex-wrap items-center gap-1.5">
                        <span className="font-medium">{r.name}</span>
                        {!r.enabled && <Badge tone="neutral">Off</Badge>}
                      </span>
                      <PatchSeverityBadge severity={r.severity} />
                      <span className="text-xs text-muted lg:hidden">{covers(r)}</span>
                    </div>
                  </td>
                  <td className="hidden max-w-xs md:table-cell">
                    {RULE_KINDS[r.type]?.label ?? r.type}
                    <span className="block text-xs text-muted">{thresholdText(r.type, r.threshold) ?? "Whenever it happens"}</span>
                  </td>
                  <td className="hidden max-w-56 lg:table-cell">{covers(r)}</td>
                  <td className="hidden max-w-64 lg:table-cell">
                    {r.channelIds.length === 0 ? (
                      <span className="text-muted">Patching → Alerts only</span>
                    ) : (
                      <span className="break-words">{r.channelIds.map(channelName).join(", ")}</span>
                    )}
                    {r.channelIds.length > 0 && (r.renotifyHours > 0 || r.notifyOnResolve) && (
                      <span className="block text-xs text-muted">
                        {[r.renotifyHours > 0 && `again every ${plural(r.renotifyHours, "hour")}`, r.notifyOnResolve && "and when resolved"]
                          .filter(Boolean)
                          .join(", ")}
                      </span>
                    )}
                  </td>
                  <td className="hidden text-right tabular-nums sm:table-cell">
                    {r.unresolvedAlerts > 0 ? (
                      <Link to={`/patching?tab=alerts&ruleType=${r.type}`} className="font-medium text-accent hover:underline">
                        {r.unresolvedAlerts.toLocaleString()}
                      </Link>
                    ) : (
                      <span className="text-subtle">0</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap">
                    <span className="flex justify-end gap-1">
                      <IconButton label={`Edit ${r.name}`} onClick={() => setForm({ open: true, rule: r })}>
                        <Pencil className="size-4" aria-hidden />
                      </IconButton>
                      <IconButton label={`Delete ${r.name}`} onClick={() => setDeleting(r)}>
                        <Trash2 className="size-4" aria-hidden />
                      </IconButton>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {/* Remounted on each opening, so it starts from the rule as it is then. */}
      <RuleDialog key={form.open ? (form.rule?.id ?? "new") : "closed"} open={form.open} rule={form.rule} list={list.data} onClose={() => setForm({ open: false })} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => {
          setDeleting(null);
          remove.reset();
        }}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title="Delete rule"
        confirmLabel="Delete rule"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        {deleting && (
          <p>
            EasyPatch stops checking {deleting.name}
            {deleting.unresolvedAlerts > 0 ? ` and resolves its ${plural(deleting.unresolvedAlerts, "open alert")}` : ""}. Turning it off instead keeps it
            for later.
          </p>
        )}
      </ConfirmDialog>
    </Card>
  );
}

function RuleDialog({ open, rule, list, onClose }: { open: boolean; rule?: PatchAlertRule; list: PatchAlertRuleList; onClose: () => void }) {
  const toast = useToast();
  const tags = useApi<PatchTagList>(open ? "/patching/tags" : null);
  const [name, setName] = useState(rule?.name ?? "");
  const [type, setType] = useState<PatchAlertRuleKind>(rule?.type ?? "EndpointOffline");
  const [severity, setSeverity] = useState<PatchAlertSeverity>(rule?.severity ?? "Warning");
  const spec = list.types.find((t) => t.type === type);
  const [threshold, setThreshold] = useState(rule?.threshold != null ? String(rule.threshold) : String(spec?.thresholdDefault ?? ""));
  const [organizationId, setOrganizationId] = useState(rule?.organizationId ?? "");
  const [tagId, setTagId] = useState(rule?.tagId ?? "");
  const [channelIds, setChannelIds] = useState<string[]>(rule?.channelIds ?? []);
  const [renotify, setRenotify] = useState(String(rule?.renotifyHours ?? 0));
  const [notifyOnResolve, setNotifyOnResolve] = useState(rule?.notifyOnResolve ?? false);
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [tried, setTried] = useState(false);
  const save = useApiMutation(
    (body: PatchAlertRuleInput) =>
      rule ? api.put<PatchAlertRule>(`/patching/alert-rules/${rule.id}`, body) : api.post<PatchAlertRule>("/patching/alert-rules", body),
    {
      invalidate: ["/patching"],
      onSuccess: (r) => {
        toast.success(rule ? `${r.name} saved.` : `${r.name} added.`);
        onClose();
      },
    },
  );
  const n = Number(threshold);
  const hours = Number(renotify);
  const errors = {
    name: name.trim() === "" ? "Name the rule." : null,
    threshold:
      spec?.thresholdUnit && (threshold.trim() === "" || !Number.isInteger(n) || n < (spec.thresholdMin ?? 0) || n > (spec.thresholdMax ?? 0))
        ? `Choose from ${spec.thresholdMin} to ${spec.thresholdMax} ${spec.thresholdUnit}.`
        : null,
    renotifyHours: renotify.trim() === "" || !Number.isInteger(hours) || hours < 0 || hours > 720 ? "Choose from 0 to 720 hours." : null,
  };
  const blocked = Object.values(errors).some(Boolean);
  const show = (k: keyof typeof errors) => fieldError(save.error, k) ?? (tried ? errors[k] : null);

  function chooseType(next: PatchAlertRuleKind) {
    setType(next);
    const s = list.types.find((t) => t.type === next);
    setThreshold(s?.thresholdDefault != null ? String(s.thresholdDefault) : "");
    if (!s?.supportsTag) setTagId("");
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    setTried(true);
    if (blocked) return;
    save.mutate({
      name: name.trim(),
      type,
      enabled,
      severity,
      threshold: spec?.thresholdUnit ? n : null,
      organizationId: organizationId || null,
      tagId: spec?.supportsTag && tagId ? tagId : null,
      channelIds,
      notifyOnResolve,
      renotifyHours: hours,
    });
  }

  return (
    <Dialog
      open={open}
      onClose={() => {
        onClose();
        save.reset();
      }}
      size="lg"
      title={rule ? "Edit alert rule" : "Add alert rule"}
      description={rule ? "Changing what the rule looks for, or where, resolves its open alerts; the next check opens again those that still apply." : undefined}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="alert-rule-form" loading={save.isPending}>
            {rule ? "Save rule" : "Add rule"}
          </Button>
        </>
      }
    >
      <form id="alert-rule-form" onSubmit={submit} className="grid gap-3.5 sm:grid-cols-2" noValidate>
        {rule?.unlinkedOrganization && (
          <Alert tone="warn" className="sm:col-span-2">
            This rule covers an EasyPatch organization EasyRMM does not link. Choose the organization it should cover, or change it in EasyPatch.
          </Alert>
        )}
        <TextField label="Name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} error={show("name")} required className="sm:col-span-2" />
        <SelectField
          label="Raises an alert when"
          value={type}
          onChange={(e) => chooseType(e.target.value as PatchAlertRuleKind)}
          hint={RULE_KINDS[type].about}
          error={fieldError(save.error, "type")}
          className="sm:col-span-2"
        >
          {RULE_KIND_ORDER.map((k) => (
            <option key={k} value={k}>
              {RULE_KINDS[k].label}
            </option>
          ))}
        </SelectField>
        {spec?.thresholdUnit && (
          <TextField
            label={type === "OsUnsupported" ? "Days before support ends" : type === "SecurityUpdateMissing" ? "Days after it became required" : `After how many ${spec.thresholdUnit}`}
            type="number"
            inputMode="numeric"
            min={spec.thresholdMin ?? undefined}
            max={spec.thresholdMax ?? undefined}
            value={threshold}
            onChange={(e) => setThreshold(e.target.value)}
            hint={`From ${spec.thresholdMin} to ${spec.thresholdMax} ${spec.thresholdUnit}.`}
            error={show("threshold")}
            required
          />
        )}
        <SelectField label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value as PatchAlertSeverity)} error={fieldError(save.error, "severity")}>
          {SEVERITIES.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </SelectField>
        <div>
          <OrganizationSelect value={organizationId} onChange={setOrganizationId} allLabel="Every organization" className="w-full" />
          {fieldError(save.error, "organizationId") && <p className="mt-1 text-xs text-danger">{fieldError(save.error, "organizationId")}</p>}
        </div>
        <SelectField
          label="Devices"
          value={spec?.supportsTag ? tagId : ""}
          onChange={(e) => setTagId(e.target.value)}
          disabled={!spec?.supportsTag}
          hint={spec?.supportsTag ? "A tag limits the rule to the devices that have it." : "This rule looks at organizations, not devices."}
          error={fieldError(save.error, "tagId")}
        >
          <option value="">Every device</option>
          {(tags.data?.items ?? []).map((t) => (
            <option key={t.id} value={t.id}>
              Tagged {t.name}
            </option>
          ))}
        </SelectField>
        <fieldset className="flex flex-col gap-2 sm:col-span-2">
          <legend className="mb-1 text-sm font-medium">Send to</legend>
          {list.channels.length === 0 ? (
            <p className="text-sm text-muted">No channels yet: add them under Notifications. Until then, alerts show under Patching → Alerts only.</p>
          ) : (
            list.channels.map((c) => (
              <label key={c.id} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="size-4 accent-accent"
                  checked={channelIds.includes(c.id)}
                  onChange={(e) => setChannelIds((ids) => (e.target.checked ? [...ids, c.id] : ids.filter((x) => x !== c.id)))}
                />
                {c.name}
                <span className="text-xs text-muted">
                  {c.type === "Email" ? "Email" : "Webhook"}
                  {!c.enabled && ", off"}
                </span>
              </label>
            ))
          )}
          {fieldError(save.error, "channelIds") && <p className="text-xs text-danger">{fieldError(save.error, "channelIds")}</p>}
        </fieldset>
        <TextField
          label="Send again every"
          type="number"
          inputMode="numeric"
          min={0}
          max={720}
          value={renotify}
          onChange={(e) => setRenotify(e.target.value)}
          hint="Hours, while the alert stays open; 0 sends it once."
          error={show("renotifyHours")}
        />
        <div className="flex flex-col justify-center gap-2 text-sm">
          <label className="flex items-center gap-2">
            <input type="checkbox" className="size-4 accent-accent" checked={notifyOnResolve} onChange={(e) => setNotifyOnResolve(e.target.checked)} />
            Also send when the alert resolves
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" className="size-4 accent-accent" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Check this rule
          </label>
        </div>
        {save.error && !(save.error instanceof ApiError && Object.keys(save.error.fields).length > 0) && (
          <p className="text-sm text-danger sm:col-span-2">{save.error.message}</p>
        )}
      </form>
    </Dialog>
  );
}
