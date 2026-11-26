// Turning BitLocker on from the console (ADR-0081, slice 4). It changes a customer's computer, so it asks for the
// computer's name typed out and, through the API client, a fresh step-up. The agent makes a recovery password, sends
// it sealed, and starts encryption only after the server says the keystore verified it: that order is the agent's and
// the server's, this dialog only says it.
import { useRef, useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import { api, ApiError } from "../../api/client";
import type { WinmodResult, WinmodRun } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import {
  Alert,
  Button,
  InlineError,
  SelectField,
  TextField,
} from "../../components/ui";

const FINISHED = new Set([
  "succeeded",
  "failed",
  "timed_out",
  "canceled",
  "expired",
  "lost",
]);
const POLL_MS = 2_000;
const GIVE_UP_MS = 15 * 60 * 1000;

/** What each refusal of the agent says to a person. Nothing was changed unless the text says so. */
export const ENABLE_FAILURES: Record<string, string> = {
  escrow_not_ready:
    "The computer has no current key to seal the recovery password to yet. Try again in a few minutes. Nothing was changed.",
  wrong_computer: "That is not this computer’s name. Nothing was changed.",
  domain_controller:
    "This computer is a domain controller; EasyRMM does not turn BitLocker on there. Nothing was changed.",
  edition_unsupported:
    "This edition of Windows does not have BitLocker. Nothing was changed.",
  tpm_not_ready:
    "There is no TPM that is present, enabled and ready. Nothing was changed.",
  reboot_pending:
    "A restart is pending. Restart the computer and try again. Nothing was changed.",
  volume_not_found: "That volume is not on this computer. Nothing was changed.",
  already_encrypted:
    "BitLocker is already on this volume or has protectors on it. Nothing was changed.",
  agent_busy:
    "The agent was busy escrowing keys. Nothing was changed; try again.",
  protector_failed:
    "A recovery password could not be added. Nothing else was changed.",
  escrow_unverified:
    "The recovery password could not be escrowed and verified, so encryption was not started.",
  tpm_protector_failed:
    "The recovery password is escrowed, but the TPM protector could not be added. Encryption was not started.",
  encrypt_failed:
    "The recovery password is escrowed and the TPM protector added, but encryption could not be started.",
  unsupported: "This agent cannot manage BitLocker.",
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function EnableBitLocker({
  deviceId,
  deviceName,
  volume,
  mount,
  onDone,
}: {
  deviceId: string;
  deviceName: string;
  volume: string;
  mount: string;
  onDone?: () => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button
        size="sm"
        variant="secondary"
        icon={<ShieldCheck className="size-3.5" aria-hidden />}
        onClick={() => setOpen(true)}
        aria-label={`Turn on BitLocker for ${mount || volume}`}
      >
        Turn on BitLocker
      </Button>
      {open && (
        <EnableDialog
          deviceId={deviceId}
          deviceName={deviceName}
          volume={volume}
          mount={mount}
          onClose={() => {
            setOpen(false);
            onDone?.();
          }}
        />
      )}
    </>
  );
}

type Phase =
  | { kind: "form" }
  | { kind: "running"; status: string }
  | { kind: "done" }
  | { kind: "refused"; message: string };

function EnableDialog({
  deviceId,
  deviceName,
  volume,
  mount,
  onClose,
}: {
  deviceId: string;
  deviceName: string;
  volume: string;
  mount: string;
  onClose: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [mode, setMode] = useState("used_space");
  const [phase, setPhase] = useState<Phase>({ kind: "form" });
  const [error, setError] = useState<unknown>(null);
  const gone = useRef(false);
  // The server compares the name trimmed and ignoring case; the button follows the same rule.
  const matches =
    typed.trim().length > 0 &&
    typed.trim().toLowerCase() === deviceName.trim().toLowerCase();

  async function run() {
    setError(null);
    setPhase({ kind: "running", status: "queued" });
    try {
      const started = await api.post<WinmodRun>(
        `/devices/${deviceId}/winmod/bitlocker.enable`,
        {
          params: { computer: typed.trim(), volume: mount, encryption: mode },
          confirm: `bitlocker.enable:${typed.trim()}`,
        },
      );
      const until = Date.now() + GIVE_UP_MS;
      for (;;) {
        if (gone.current) return;
        const r = await api.get<WinmodResult>(`/winmod/runs/${started.runId}`);
        if (r.ok === true) {
          setPhase({ kind: "done" });
          return;
        }
        if (r.ok === false) {
          setPhase({
            kind: "refused",
            message:
              (r.failure?.code && ENABLE_FAILURES[r.failure.code]) ||
              r.failure?.message ||
              "The action did not finish.",
          });
          return;
        }
        if (FINISHED.has(r.status)) {
          setPhase({
            kind: "refused",
            message: r.error ?? `The action ended as ${r.status}.`,
          });
          return;
        }
        if (Date.now() > until) {
          setPhase({
            kind: "refused",
            message:
              "The computer did not answer in time. Look at it again before trying once more.",
          });
          return;
        }
        setPhase({ kind: "running", status: r.status });
        await sleep(POLL_MS);
      }
    } catch (e) {
      setError(e);
      setPhase({ kind: "form" });
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (matches) void run();
  }

  const running = phase.kind === "running";
  return (
    <Dialog
      open
      onClose={() => {
        gone.current = true;
        onClose();
      }}
      title="Turn on BitLocker"
      description={`${deviceName}, ${mount || volume}. This changes the computer and is recorded.`}
      size="md"
    >
      {phase.kind === "done" ? (
        <div className="flex flex-col gap-3">
          <Alert tone="ok" title="Encryption started">
            The recovery password was sealed, sent and verified by the keystore
            before encryption began. Encryption continues in the background; the
            volume’s key is listed here once the agent reports it.
          </Alert>
          <div className="flex justify-end">
            <Button
              onClick={() => {
                gone.current = true;
                onClose();
              }}
            >
              Done
            </Button>
          </div>
        </div>
      ) : (
        <form
          onSubmit={submit}
          className="flex flex-col gap-3"
          aria-label="Turn on BitLocker"
        >
          <p className="text-sm text-muted">
            In this order: the agent makes a recovery password, seals it to your
            organization’s key and sends it; the keystore checks it; only then
            does the agent add the TPM protector and start encryption.
            Encryption is never started on a key that was not verified. This
            asks for your second factor.
          </p>
          <SelectField
            label="What to encrypt"
            value={mode}
            onChange={(e) => setMode(e.target.value)}
            disabled={running}
          >
            <option value="used_space">Used space only (faster)</option>
            <option value="full">The whole volume</option>
          </SelectField>
          <TextField
            label={`Type the computer’s name to confirm: ${deviceName}`}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
            disabled={running}
          />
          {phase.kind === "refused" && (
            <Alert tone="danger">{phase.message}</Alert>
          )}
          {running && (
            <Alert tone="info">
              Working on {deviceName} ({phase.status}). This waits for the
              keystore’s check and can take a minute or two.
            </Alert>
          )}
          {error instanceof ApiError || error instanceof Error ? (
            <Alert tone="danger">{error.message}</Alert>
          ) : (
            <InlineError error={error} />
          )}
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                gone.current = true;
                onClose();
              }}
            >
              Cancel
            </Button>
            <Button type="submit" loading={running} disabled={!matches}>
              Turn on BitLocker
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
