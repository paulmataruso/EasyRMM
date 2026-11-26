import { useEffect, useState, type FormEvent } from "react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import { useToast } from "../../components/Toast";
import { Button, Card, ErrorState, InlineError, Spinner, TextField } from "../../components/ui";

/** The bounds of a one-time Quick Assist link's life (ADR-0080): 1 minute to 7 days. */
export const MIN_LINK_MINUTES = 1;
export const MAX_LINK_MINUTES = 7 * 24 * 60;

/**
 * Settings > General: app-wide defaults. For now, how long a new Quick Assist link lasts (ADR-0080); super
 * administrators change it.
 */
export function GeneralTab() {
  const q = useApi<{ mode: string; defaultLifeMinutes?: number }>("/quickassist/settings");
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
  );
}
