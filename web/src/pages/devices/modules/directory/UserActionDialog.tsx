import { useEffect, useState } from "react";
import { useAuth } from "../../../../auth/AuthContext";
import { Dialog } from "../../../../components/Dialog";
import { Alert, Button, InlineError, TextField } from "../../../../components/ui";
import type { UserRow } from "./types";
import { confirmFor, useWinmod } from "./useWinmod";

export type UserAction = "user_unlock" | "user_enable" | "user_disable" | "user_delete";

const WORDS: Record<UserAction, { title: string; verb: string; effect: (u: UserRow) => string; typed: boolean }> = {
  user_unlock: { title: "Unlock", verb: "Unlock", effect: (u) => `${u.name} can sign in again.`, typed: false },
  user_enable: { title: "Enable", verb: "Enable", effect: (u) => `${u.name} can sign in again, with the password the account already has.`, typed: true },
  user_disable: { title: "Disable", verb: "Disable", effect: (u) => `${u.name} can no longer sign in, anywhere in the domain.`, typed: true },
  user_delete: { title: "Delete", verb: "Delete", effect: (u) => `${u.name} is removed from the directory.`, typed: true },
};

/**
 * One account action. An action that grants or removes access (enable, disable, delete) asks for the account's name and,
 * through the API client, for the second factor (ADR-0055); a service account asks for the extra confirmation.
 */
export function UserActionDialog({
  deviceId,
  recycleBin,
  target,
  onClose,
}: {
  deviceId: string;
  recycleBin: boolean;
  target: { user: UserRow; action: UserAction } | null;
  onClose: (changed: boolean) => void;
}) {
  const { can } = useAuth();
  const run = useWinmod(deviceId);
  const [typed, setTyped] = useState("");
  const [service, setService] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  useEffect(() => {
    setTyped("");
    setService("");
    setError(null);
    setRefusal(null);
    setDone(false);
  }, [target]);
  if (!target) return <Dialog open={false} onClose={() => undefined} title="" />;
  const { user, action } = target;
  const words = WORDS[action];
  const isService = user.protection === "service";
  const ready = (!words.typed || typed === user.sam) && (!isService || service === `service-account:${user.sam}`);

  const submit = async () => {
    setBusy(true);
    setError(null);
    setRefusal(null);
    try {
      const params: Record<string, unknown> = { id: user.id };
      if (isService) params.serviceConfirm = service;
      const r = await run(action, params, words.typed ? confirmFor(action, user.id) : undefined);
      if (r.ok) setDone(true);
      else setRefusal(r.failure?.message ?? "The controller refused.");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open
      onClose={() => onClose(done)}
      title={`${words.title} ${user.name}`}
      description={words.effect(user)}
      footer={
        done ? (
          <Button variant="primary" onClick={() => onClose(true)}>
            Close
          </Button>
        ) : (
          <>
            <Button onClick={() => onClose(false)}>Cancel</Button>
            <Button variant={action === "user_enable" || action === "user_unlock" ? "primary" : "danger"} onClick={() => void submit()} loading={busy} disabled={!ready}>
              {words.verb}
            </Button>
          </>
        )
      }
    >
      {done ? (
        <Alert tone="ok">
          Done. Other controllers may take a few moments to learn of it.
        </Alert>
      ) : (
        <div className="flex flex-col gap-3">
          {action === "user_delete" && (
            <Alert tone="warn">
              {recycleBin
                ? "The directory's Recycle Bin is on, so the account can be restored with the directory's own tools."
                : "The Recycle Bin is off: the account is permanently gone once the controllers have replicated."}
            </Alert>
          )}
          {isService && (
            <Alert tone="warn" title="This looks like a service account">
              {user.reason}. Changing it can stop the services that run as it.
              {!can("ad.manage") && " Only an administrator can confirm this."}
            </Alert>
          )}
          {words.typed && (
            <TextField label={`Type ${user.sam} to confirm`} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
          )}
          {isService && (
            <TextField label={`Type service-account:${user.sam} to confirm it is a service account`} value={service} onChange={(e) => setService(e.target.value)} autoComplete="off" />
          )}
          <InlineError error={error} />
          {refusal && <Alert tone="danger">{refusal}</Alert>}
        </div>
      )}
    </Dialog>
  );
}
