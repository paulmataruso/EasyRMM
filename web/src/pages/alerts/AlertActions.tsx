// Acknowledging and resolving alerts, from the alerts page, the device page and the dashboard.
import { api, errorMessage } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { AlertEntry } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Button, cx } from "../../components/ui";
import { risingHint } from "./alertText";

type Action = "acknowledge" | "resolve";

export function useAlertAction() {
  const toast = useToast();
  const mutation = useApiMutation(({ alert, action }: { alert: AlertEntry; action: Action }) => api.post<AlertEntry>(`/alerts/${alert.id}/${action}`), {
    invalidate: ["/alerts", "/alert-policies", "/audit"],
    onSuccess: (a, { action }) =>
      toast.success(
        action === "acknowledge"
          ? `Acknowledged ${a.name} on ${a.deviceName}. It resolves on its own when the condition clears.`
          : `Resolved ${a.name} on ${a.deviceName}. If the condition still holds, a new alert opens within a minute.`,
      ),
  });
  return {
    run: (alert: AlertEntry, action: Action) => mutation.mutate({ alert, action }, { onError: (e) => toast.error(errorMessage(e)) }),
    pending: (alert: AlertEntry, action: Action) => mutation.isPending && mutation.variables?.alert.id === alert.id && mutation.variables.action === action,
    busy: mutation.isPending,
  };
}

/** Acknowledge (while open) and Resolve (while active), for someone allowed to. */
export function AlertActions({ alert, actions, align = "end", nowrap = false, className }: {
  alert: AlertEntry;
  actions: ReturnType<typeof useAlertAction>;
  /** "end" pushes the buttons to the right of their row, even when they wrap below it. */
  align?: "start" | "end";
  nowrap?: boolean;
  className?: string;
}) {
  if (!alert.canManage || alert.status === "resolved") return null;
  return (
    <div className={cx("flex gap-1.5", nowrap ? "flex-nowrap" : "flex-wrap", align === "end" ? "ml-auto justify-end" : "justify-start", className)}>
      {alert.status === "open" && (
        <Button
          size="sm"
          variant="secondary"
          loading={actions.pending(alert, "acknowledge")}
          disabled={actions.busy}
          aria-label={`Acknowledge ${alert.name} on ${alert.deviceName}`}
          onClick={() => actions.run(alert, "acknowledge")}
        >
          Acknowledge
        </Button>
      )}
      <Button
        size="sm"
        variant="ghost"
        loading={actions.pending(alert, "resolve")}
        disabled={actions.busy}
        title={risingHint(alert) ?? undefined}
        aria-label={`Resolve ${alert.name} on ${alert.deviceName}`}
        onClick={() => actions.run(alert, "resolve")}
      >
        Resolve
      </Button>
    </div>
  );
}
