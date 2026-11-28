import { useEffect, useState, type FormEvent } from "react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import { useToast } from "../../components/Toast";
import type { QuickAssistLimits } from "../../api/types";
import { Button, Card, ErrorState, InlineError, Spinner, TextField } from "../../components/ui";

/** The bounds of a one-time Quick Assist link's life (ADR-0080): 1 minute to 7 days. */
export const MIN_LINK_MINUTES = 1;
export const MAX_LINK_MINUTES = 7 * 24 * 60;

/** The limits of Quick Assist (ADR-0080), with the bounds the server enforces. */
export const LIMIT_FIELDS: { key: keyof QuickAssistLimits; label: string; min: number; max: number; hint: string }[] = [
  { key: "idleMinutes", label: "End an idle session after (minutes)", min: 5, max: 240, hint: "No remote use, job or technician action for this long ends the session. 5 to 240; the default is 30." },
  { key: "maxSessionHours", label: "Longest session (hours)", min: 1, max: 24, hint: "A technician may extend a session once by this much. 1 to 24; the default is 8." },
  { key: "retentionDays", label: "Keep ended sessions (days)", min: 1, max: 365, hint: "1 to 365; the default is 30." },
  { key: "bucketBurst", label: "Permanent link burst (downloads)", min: 1, max: 20, hint: "How many downloads a permanent link allows at once. 1 to 20; the default is 5." },
  { key: "bucketRefillMinutes", label: "Permanent link refill (minutes per download)", min: 1, max: 60, hint: "1 to 60; the default is 3." },
  { key: "waitingCap", label: "Requests waiting per organization", min: 5, max: 100, hint: "The oldest unanswered request makes room. 5 to 100; the default is 20." },
  { key: "permanentLinkCap", label: "Permanent links per organization", min: 1, max: 20, hint: "1 to 20; the default is 5." },
];

/**
 * Settings > General: app-wide defaults. For now, how long a new Quick Assist link lasts (ADR-0080); super
 * administrators change it.
 */
export function GeneralTab() {
  const q = useApi<{ mode: string; defaultLifeMinutes?: number } & Partial<QuickAssistLimits>>("/quickassist/settings");
  const toast = useToast();
  const [minutes, setMinutes] = useState("");
  useEffect(() => {
    if (q.data?.defaultLifeMinutes) setMinutes(String(q.data.defaultLifeMinutes));
  }, [q.data?.defaultLifeMinutes]);
  const save = useApiMutation((m: number) => api.put("/quickassist/settings/default-life", { minutes: m }), {
    invalidate: ["/quickassist"],
    onSuccess: () => toast.success("Saved."),
  });
  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const n = Number(minutes);
  const valid = Number.isInteger(n) && n >= MIN_LINK_MINUTES && n <= MAX_LINK_MINUTES;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (valid) save.mutate(n);
  };
  return (
    <div className="space-y-4">
    <Card title="Quick Assist">
      <form onSubmit={submit} className="max-w-md space-y-3">
        <TextField
          label="New link expires after (minutes)"
          type="number"
          min={MIN_LINK_MINUTES}
          max={MAX_LINK_MINUTES}
          value={minutes}
          onChange={(e) => setMinutes(e.target.value)}
          hint="1 to 10080 minutes (7 days). The default is 1440 (24 hours). Every new one-time link uses it."
        />
        {save.error && <InlineError error={save.error} />}
        <Button type="submit" disabled={!valid || save.isPending}>
          Save
        </Button>
      </form>
    </Card>
    <LimitsCard current={q.data} />
    </div>
  );
}

/** The limits form: every field is checked against its bounds, and only changed fields are sent. */
function LimitsCard({ current }: { current: Partial<QuickAssistLimits> | undefined }) {
  const toast = useToast();
  const [vals, setVals] = useState<Record<string, string>>({});
  useEffect(() => {
    setVals(Object.fromEntries(LIMIT_FIELDS.map((f) => [f.key, current?.[f.key] === undefined ? "" : String(current[f.key])])));
  }, [current]);
  const save = useApiMutation((patch: Partial<QuickAssistLimits>) => api.put("/quickassist/settings", patch), {
    invalidate: ["/quickassist"],
    onSuccess: () => toast.success("Saved."),
  });
  const parsed = LIMIT_FIELDS.map((f) => {
    const n = Number(vals[f.key]);
    return { f, n, ok: vals[f.key] !== "" && Number.isInteger(n) && n >= f.min && n <= f.max };
  });
  const allOk = parsed.every((p) => p.ok);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!allOk) return;
    save.mutate(Object.fromEntries(parsed.filter((p) => p.n !== current?.[p.f.key]).map((p) => [p.f.key, p.n])));
  };
  return (
    <Card title="Quick Assist limits">
      <form onSubmit={submit} className="max-w-md space-y-3">
        {parsed.map(({ f, ok }) => (
          <TextField
            key={f.key}
            label={f.label}
            type="number"
            min={f.min}
            max={f.max}
            value={vals[f.key] ?? ""}
            onChange={(e) => setVals((v) => ({ ...v, [f.key]: e.target.value }))}
            hint={f.hint}
            error={ok ? undefined : `Use ${f.min} to ${f.max}.`}
          />
        ))}
        {save.error && <InlineError error={save.error} />}
        <Button type="submit" disabled={!allOk || save.isPending}>
          Save limits
        </Button>
      </form>
    </Card>
  );
}
