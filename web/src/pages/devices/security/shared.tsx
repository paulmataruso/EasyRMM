import { useState, type ReactNode } from "react";
import { Loader2, Lock } from "lucide-react";
import { Dialog } from "../../../components/Dialog";
import { Alert, Badge, Button, Card, InlineError, Skeleton } from "../../../components/ui";
import { formatDateTime, formatRelative } from "../../../lib/format";
import { ActionFailed, type Read } from "./winmod";
import { MANAGED_TEXT } from "./text";
import type { ManagedBy } from "./types";

/** Why a script refused or did not apply, in words, by its code. */
const FAILURE_TEXT: Record<string, string> = {
  module_missing: "Microsoft Defender is not installed on this computer.",
  managed_by_policy: "A policy on the computer manages this. Change it where it is managed.",
  protected_exclusion: "EasyRMM needs this entry so Defender does not block its own files.",
  ours_not_covered: "EasyRMM's own files are not covered yet, so turning this on could block the agents. Nothing was changed.",
  passive_mode: "Defender is not the active antivirus on this computer.",
  unsupported: "This computer does not support this.",
  not_in_list: "That value is not in the list on the computer any more.",
};

export function failureText(e: unknown): string {
  if (e instanceof ActionFailed) return FAILURE_TEXT[e.code] ?? e.message;
  return e instanceof Error ? e.message : "Something went wrong.";
}

/** The lock shown beside a setting something else owns: it is shown, never hidden, and its controls are off. */
export function Managed({ by }: { by: ManagedBy | null }) {
  if (!by) return null;
  return (
    <Badge tone={by === "unknown_owner" ? "warn" : "neutral"} icon={<Lock className="size-3" aria-hidden />}>
      {MANAGED_TEXT[by]}
    </Badge>
  );
}

/** A panel that reads by itself: its name, when it was read, a skeleton while the first result loads, and the failure if any. */
export function ReadPanel<T>({
  title,
  read,
  children,
  extra,
}: {
  title: string;
  read: Read<T>;
  children: (data: T) => ReactNode;
  extra?: ReactNode;
}) {
  return (
    <Card
      title={title}
      actions={
        <div className="flex items-center gap-2">
          {read.refreshing && read.data && (
            <span className="inline-flex items-center gap-1 text-xs text-muted" role="status">
              <Loader2 className="size-3 animate-spin" aria-hidden /> Updating
            </span>
          )}
          {read.asOf && (
            <span className="text-xs text-muted" title={formatDateTime(read.asOf)}>
              As of {formatRelative(read.asOf)}
            </span>
          )}
        </div>
      }
    >
      <div className="flex flex-col gap-3">
        {read.error && <Alert tone="warn">{failureText(read.error)}</Alert>}
        {extra}
        {read.data ? (
          children(read.data)
        ) : (
          read.loading && (
            <div role="status" aria-busy="true" aria-label={`Loading ${title}`} className="flex flex-col gap-2">
              <Skeleton className="w-full" />
              <Skeleton className="w-3/4" />
              <Skeleton className="w-1/2" />
            </div>
          )
        )}
      </div>
    </Card>
  );
}

/**
 * Asks before a change: what it does in words, and whether it needs the second factor (a tier 3 change; the API client
 * asks for it when the server says so). `run` does the work; its failure is shown in the dialog.
 */
export function ConfirmChange({
  open,
  onClose,
  title,
  effect,
  confirmLabel,
  danger = false,
  run,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  effect: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  run: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      await run();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant={danger ? "danger" : "primary"} onClick={go} loading={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        {effect}
        {error != null && <InlineError error={error instanceof ActionFailed ? new Error(failureText(error)) : error} />}
      </div>
    </Dialog>
  );
}

/** What was done, after a write that read the value back. */
export function appliedMessage(c: { applied: boolean; reason: string }): { ok: boolean; text: string } {
  return c.applied ? { ok: true, text: "Done." } : { ok: false, text: c.reason || "The value did not change." };
}
