import { useState, type ReactNode } from "react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { AgentSettingEntry, AgentSettingScope, AgentSettingSource, AgentSettingsListing } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, ErrorState, Field, InlineError, Input, Skeleton } from "../../components/ui";

const SCOPE_NOUN: Record<AgentSettingScope, string> = {
  platform: "the platform",
  organization: "this organization",
  site: "this site",
  device: "this device",
};

/** Where a value comes from, in the words technicians read (ADR-0058): `scope` is the page the value is shown on. */
export function sourceText(from: AgentSettingSource | null, scope: AgentSettingScope): string {
  if (!from) return "Default";
  if (from.scope === scope) return `Set for ${SCOPE_NOUN[scope]}`;
  if (from.scope === "platform") return "Set by your MSP";
  return `Inherited from ${from.scope} ${from.name ?? ""}`.trim();
}

/**
 * Every key of the catalog at one scope, each with its effective value, where it comes from and, for who may write it
 * here, an editor. The device, site, organization and platform pages all use it (ADR-0058, slice 3).
 */
export function AgentSettingsPanel({ base, scope, editable = true, header }: {
  /** The scope's route: `/devices/{id}/agent-settings` and its kin. */
  base: string;
  scope: AgentSettingScope;
  /** False for a viewer who lacks the permission here; the server's own `canWrite` still applies. */
  editable?: boolean;
  /** Shown above the keys, from the same read. */
  header?: (listing: AgentSettingsListing) => ReactNode;
}) {
  const listing = useApi<AgentSettingsListing>(base);
  if (listing.isPending) {
    return (
      <div className="flex flex-col gap-4" role="status" aria-label="Loading agent settings">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }
  if (listing.isError) return <ErrorState error={listing.error} onRetry={() => void listing.refetch()} />;
  return (
    <div className="flex flex-col gap-4">
      {header?.(listing.data)}
      {listing.data.items.map((e) => (
        <SettingCard key={e.key} entry={e} base={base} scope={scope} editable={editable} />
      ))}
    </div>
  );
}

function SettingCard({ entry, base, scope, editable }: { entry: AgentSettingEntry; base: string; scope: AgentSettingScope; editable: boolean }) {
  const e = entry;
  return (
    <Card title={e.title}>
      <p className="mb-3 text-sm text-muted">{e.description}</p>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
        <span>
          In effect: <strong>{e.effective.value} seconds</strong>
        </span>
        <Badge tone={e.effective.from === null ? "neutral" : e.effective.from.scope === "platform" && scope !== "platform" ? "accent" : "info"}>
          {sourceText(e.effective.from, scope)}
        </Badge>
        {e.effective.raised && <Badge tone="warn">Raised to the platform minimum</Badge>}
        <code className="ml-auto text-xs text-subtle">{e.key}</code>
      </div>
      {e.enforcedBy && (
        <Alert tone="info" className="mb-3">
          {sourceText(e.enforcedBy, scope)} enforces this value for everything below it, so it cannot be changed here.
        </Alert>
      )}
      <SettingEditor
        key={`${e.key}:${e.set?.updatedAt ?? ""}:${e.effective.value}`}
        entry={e}
        base={base}
        scope={scope}
        editable={editable && e.canWrite}
      />
    </Card>
  );
}

function SettingEditor({ entry: e, base, scope, editable }: { entry: AgentSettingEntry; base: string; scope: AgentSettingScope; editable: boolean }) {
  const toast = useToast();
  const [draft, setDraft] = useState(String(e.set?.value ?? e.effective.value));
  const [enforced, setEnforced] = useState(e.set?.enforced ?? false);
  const path = `${base}/${encodeURIComponent(e.key)}`;
  const invalidate = [base, "/settings/agent-settings/problems", "/devices"];
  const save = useApiMutation((v: { value: number; enforced: boolean }) => api.put(path, v), {
    invalidate,
    onSuccess: () => toast.success("Saved."),
  });
  const clear = useApiMutation(() => api.del(path), { invalidate, onSuccess: () => toast.success("This scope now uses the inherited value.") });

  const n = Number(draft);
  const valid = draft.trim() !== "" && Number.isInteger(n) && n >= e.min && n <= e.max;
  const changed = e.set === null || n !== e.set.value || enforced !== e.set.enforced;
  const inputId = `setting-${scope}-${e.key}`;

  if (!editable) {
    return (
      <p className="text-sm text-muted">
        {e.set ? `Set here to ${e.set.value} seconds.` : `Nothing is set here; the value above is inherited.`} You can see it, not change it.
      </p>
    );
  }
  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(ev) => {
        ev.preventDefault();
        if (valid) save.mutate({ value: n, enforced: e.canEnforce && enforced });
      }}
    >
      <div className="flex flex-wrap items-end gap-3">
        <Field
          label="Seconds"
          htmlFor={inputId}
          hint={`${e.min} to ${e.max}`}
          error={draft !== "" && !valid ? `Use a whole number from ${e.min} to ${e.max}.` : null}
        >
          <Input id={inputId} type="number" inputMode="numeric" min={e.min} max={e.max} step={1} className="w-28" value={draft} onChange={(ev) => setDraft(ev.target.value)} />
        </Field>
        <Button type="submit" variant="primary" loading={save.isPending} disabled={!valid || !changed}>
          Save
        </Button>
        {e.set && (
          <Button type="button" loading={clear.isPending} onClick={() => clear.mutate()}>
            Use inherited
          </Button>
        )}
      </div>
      {e.canEnforce && (
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enforced} onChange={(ev) => setEnforced(ev.target.checked)} />
          Enforce for everything below
        </label>
      )}
      <InlineError error={save.error ?? clear.error} />
    </form>
  );
}
