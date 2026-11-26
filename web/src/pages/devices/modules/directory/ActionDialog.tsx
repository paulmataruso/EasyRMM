import { useEffect, useState, type ReactNode } from "react";
import { Dialog } from "../../../../components/Dialog";
import { Alert, Button, InlineError, TextField } from "../../../../components/ui";
import type { Finished } from "./useWinmod";

/**
 * A dialog for one directory action: the fields as children, an optional typed confirmation, and the answer of the
 * controller in its own words. The step-up (ADR-0055) is asked for by the API client. `done` is what is shown once it
 * worked; `onClose(true)` tells the caller to reload.
 */
export function ActionDialog<T = unknown>({
  open,
  title,
  description,
  verb,
  danger = false,
  confirmWord,
  ready = true,
  submit,
  done,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  description?: ReactNode;
  verb: string;
  danger?: boolean;
  /** When set, the person types this word before the button works. */
  confirmWord?: string;
  ready?: boolean;
  submit: () => Promise<Finished<T>>;
  done: (r: Finished<T>) => ReactNode;
  onClose: (changed: boolean) => void;
  children?: ReactNode;
}) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [result, setResult] = useState<Finished<T> | null>(null);
  useEffect(() => {
    setTyped("");
    setError(null);
    setRefusal(null);
    setResult(null);
  }, [open]);
  const go = async () => {
    setBusy(true);
    setError(null);
    setRefusal(null);
    try {
      const r = await submit();
      if (r.ok) setResult(r);
      else setRefusal(r.failure?.message ?? "The controller refused.");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={open}
      onClose={() => onClose(result !== null)}
      dismissible={!busy}
      title={title}
      description={description}
      footer={
        result ? (
          <Button variant="primary" onClick={() => onClose(true)}>
            Close
          </Button>
        ) : (
          <>
            <Button onClick={() => onClose(false)}>Cancel</Button>
            <Button variant={danger ? "danger" : "primary"} onClick={() => void go()} loading={busy} disabled={!ready || (confirmWord !== undefined && typed !== confirmWord)}>
              {verb}
            </Button>
          </>
        )
      }
    >
      {result ? (
        done(result)
      ) : (
        <div className="flex flex-col gap-3">
          {children}
          {confirmWord !== undefined && <TextField label={`Type ${confirmWord} to confirm`} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />}
          <InlineError error={error} />
          {refusal && <Alert tone="danger">{refusal}</Alert>}
        </div>
      )}
    </Dialog>
  );
}

export const Done = ({ children }: { children?: ReactNode }) => (
  <Alert tone="ok">{children ?? "Done."} Other controllers may take a few moments to learn of it.</Alert>
);
