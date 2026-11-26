// Reading a disk recovery key (ADR-0081, slice 2). The key is held in this component's state only: it is never put in
// the query cache, local or session storage, a URL, a toast or the console, there is no copy button (select it by
// hand), and it is dropped when the panel is closed, after 60 seconds, when the tab is hidden or the page is left.
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { Eye } from "lucide-react";
import { api, ApiError } from "../../api/client";
import type { RecoveryKeyRequest } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import {
  Alert,
  Button,
  InlineError,
  TextareaField,
  TextField,
} from "../../components/ui";

/** How long a revealed key stays on the page. */
export const REVEAL_SECONDS = 60;
const POLL_MS = 5_000;

type Phase =
  | { kind: "form" }
  | { kind: "waiting"; request: RecoveryKeyRequest }
  | { kind: "approved"; request: RecoveryKeyRequest }
  | { kind: "shown"; key: string; left: number };

export function RevealRecoveryKey({
  deviceId,
  deviceLabel,
  volume,
  protector,
  mount,
}: {
  deviceId: string;
  deviceLabel?: string;
  volume: string;
  protector: string;
  mount: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button
        size="sm"
        variant="secondary"
        icon={<Eye className="size-3.5" aria-hidden />}
        onClick={() => setOpen(true)}
        aria-label={`Reveal the recovery key of ${mount || "the volume"}`}
      >
        Reveal key
      </Button>
      {open && (
        <RevealDialog
          deviceId={deviceId}
          deviceLabel={deviceLabel}
          volume={volume}
          protector={protector}
          mount={mount}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

function RevealDialog({
  deviceId,
  deviceLabel,
  volume,
  protector,
  mount,
  onClose,
}: {
  deviceId: string;
  deviceLabel?: string;
  volume: string;
  protector: string;
  mount: string;
  onClose: () => void;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "form" });
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  // The key lives only in `phase`; this ref lets the cleanup drop it without a stale closure.
  const clear = useRef<() => void>(() => {});
  clear.current = () => setPhase({ kind: "form" });

  const post = useCallback(
    async (body: Record<string, unknown>) => {
      setBusy(true);
      setError(null);
      try {
        const res = await api.post<{
          key?: string;
          pending?: RecoveryKeyRequest;
        }>(`/devices/${deviceId}/escrow/read`, { volume, protector, ...body });
        if (res.key)
          setPhase({ kind: "shown", key: res.key, left: REVEAL_SECONDS });
        else if (res.pending)
          setPhase({ kind: "waiting", request: res.pending });
      } catch (e) {
        setError(e);
      } finally {
        setBusy(false);
      }
    },
    [deviceId, volume, protector],
  );

  // The countdown, and the key's removal when it ends.
  const shown = phase.kind === "shown";
  useEffect(() => {
    if (!shown) return;
    const t = window.setInterval(() => {
      setPhase((p) =>
        p.kind === "shown"
          ? p.left <= 1
            ? { kind: "form" }
            : { ...p, left: p.left - 1 }
          : p,
      );
    }, 1000);
    return () => window.clearInterval(t);
  }, [shown]);

  // Gone from the page when it is hidden or left, and when this dialog unmounts.
  useEffect(() => {
    const drop = () => clear.current();
    const hidden = () => {
      if (document.visibilityState === "hidden") drop();
    };
    window.addEventListener("pagehide", drop);
    document.addEventListener("visibilitychange", hidden);
    return () => {
      window.removeEventListener("pagehide", drop);
      document.removeEventListener("visibilitychange", hidden);
      drop();
    };
  }, []);

  // Waiting for a second person: ask for the request's state until it is decided.
  const waitingId = phase.kind === "waiting" ? phase.request.id : null;
  useEffect(() => {
    if (!waitingId) return;
    const t = window.setInterval(() => {
      void api
        .get<{ requests: RecoveryKeyRequest[] }>("/keystore/requests")
        .then((r) => {
          const mine = r.requests.find((x) => x.id === waitingId);
          if (mine && mine.state === "approved")
            setPhase({ kind: "approved", request: mine });
          else if (mine && mine.state === "denied") {
            setPhase({ kind: "form" });
            setError(new Error("A second person refused the request."));
          }
        })
        .catch(() => undefined);
    }, POLL_MS);
    return () => window.clearInterval(t);
  }, [waitingId]);

  const close = () => {
    clear.current();
    onClose();
  };

  function submit(e: FormEvent) {
    e.preventDefault();
    if (phase.kind === "form")
      void post({ reason: reason.trim(), ticket: ticket.trim() });
    else if (phase.kind === "approved")
      void post({ requestId: phase.request.id });
  }

  const reasonTooShort = reason.trim().length < 10;
  return (
    <Dialog
      open
      onClose={close}
      title="Reveal the recovery key"
      description={`${deviceLabel ? `${deviceLabel}, ` : ""}${mount || "volume"}. This is recorded, and your organization’s administrators are told.`}
      size="md"
    >
      {phase.kind === "shown" ? (
        <div className="flex flex-col gap-3">
          <p className="text-sm text-muted">
            Shown once. It leaves this page in {phase.left} seconds, when you
            close this window or leave the page.
          </p>
          <output
            aria-label="Recovery key"
            className="select-all rounded-md border border-line bg-surface-2 px-3 py-2 font-mono text-base tracking-wide text-fg"
          >
            {phase.key}
          </output>
          <div className="flex justify-end">
            <Button onClick={close}>Done</Button>
          </div>
        </div>
      ) : phase.kind === "waiting" ? (
        <div className="flex flex-col gap-3">
          <Alert tone="info" title="Waiting for a second person">
            Your organization asks for two people. Someone else with the approve
            permission has to approve this within 30 minutes; it stays valid for
            10 minutes after that. This window checks every few seconds.
          </Alert>
          <div className="flex justify-end">
            <Button variant="secondary" onClick={close}>
              Close
            </Button>
          </div>
        </div>
      ) : (
        <form
          onSubmit={submit}
          className="flex flex-col gap-3"
          aria-label="Reveal the recovery key"
        >
          {phase.kind === "approved" ? (
            <Alert tone="ok" title="Approved">
              {phase.request.approver ?? "A second person"} approved it. Reveal
              the key within 10 minutes of the approval; it works once.
            </Alert>
          ) : (
            <>
              <TextareaField
                label="Why do you need the key?"
                hint="At least 10 characters. It is kept in the audit log. Do not type the key here."
                required
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                autoComplete="off"
                maxLength={500}
              />
              <TextField
                label="Ticket reference"
                hint="Optional."
                value={ticket}
                onChange={(e) => setTicket(e.target.value)}
                autoComplete="off"
                maxLength={64}
              />
            </>
          )}
          {error instanceof ApiError || error instanceof Error ? (
            <Alert tone="danger">{error.message}</Alert>
          ) : (
            <InlineError error={error} />
          )}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="secondary" onClick={close}>
              Cancel
            </Button>
            <Button
              type="submit"
              loading={busy}
              disabled={phase.kind === "form" && reasonTooShort}
            >
              {phase.kind === "approved" ? "Reveal the key" : "Reveal"}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
