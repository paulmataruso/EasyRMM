import { useEffect, useState, type FormEvent } from "react";
import { KeyRound, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { RdpCredential, RdpCredentialInput } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, InlineError, TextField } from "../../components/ui";

/** How a remote RDP session signs in: with a credential saved for the device, or with what is typed in the session. */
export type RdpChoice = { mode: "saved"; id: string } | { mode: "typed" };

export const rdpCredentialsPath = (deviceId: string) => `/devices/${deviceId}/rdp-credentials`;

export function accountOf(c: Pick<RdpCredential, "domain" | "username">): string {
  return c.domain ? `${c.domain}\\${c.username}` : c.username;
}

/**
 * Shown before an RDP session opens for a person who has a credential saved for the device (ADR-0079): sign in with
 * it, or type credentials in the session as before. The password is on the server; this page never has it.
 */
export function RdpChooser({ credentials, deviceName, onChoose, onManage }: {
  credentials: RdpCredential[];
  deviceName: string;
  onChoose: (choice: RdpChoice) => void;
  onManage: () => void;
}) {
  const [picked, setPicked] = useState(credentials[0]?.id ?? "");
  return (
    <div className="flex h-full items-center justify-center p-4">
      <form
        aria-label="How to sign in"
        className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-line bg-surface p-4"
        onSubmit={(e) => {
          e.preventDefault();
          onChoose(picked ? { mode: "saved", id: picked } : { mode: "typed" });
        }}
      >
        <h2 className="text-sm font-medium text-fg">Sign in to {deviceName}</h2>
        <fieldset className="flex flex-col gap-2">
          <legend className="sr-only">Credentials</legend>
          {credentials.map((c) => (
            <label key={c.id} className="flex cursor-pointer items-start gap-2 rounded-md border border-line p-2 text-sm has-[:checked]:border-accent/60 has-[:checked]:bg-accent-soft">
              <input type="radio" name="rdp-credential" className="mt-0.5" checked={picked === c.id} onChange={() => setPicked(c.id)} />
              <span className="min-w-0">
                <span className="block truncate font-medium text-fg">Use the saved credential “{c.label}”</span>
                <span className="block truncate font-mono text-xs text-muted">{accountOf(c)}</span>
              </span>
            </label>
          ))}
          <label className="flex cursor-pointer items-start gap-2 rounded-md border border-line p-2 text-sm has-[:checked]:border-accent/60 has-[:checked]:bg-accent-soft">
            <input type="radio" name="rdp-credential" className="mt-0.5" checked={picked === ""} onChange={() => setPicked("")} />
            <span className="font-medium text-fg">Type credentials in the session</span>
          </label>
        </fieldset>
        {picked && <p className="text-xs text-muted">A saved credential asks you to confirm with your second factor first. It is never shown to you or to the browser.</p>}
        <div className="flex items-center justify-between gap-2 pt-1">
          <Button type="button" variant="ghost" size="sm" icon={<KeyRound className="size-3.5" aria-hidden />} onClick={onManage}>
            Manage saved credentials
          </Button>
          <Button type="submit" variant="primary">
            Connect
          </Button>
        </div>
      </form>
    </div>
  );
}

/** Saves, replaces and deletes the person's own credential for a device. Asks for step-up through the API client. */
export function RdpCredentialsDialog({ open, onClose, deviceId, deviceName, credentials, onChanged, onUse }: {
  open: boolean;
  onClose: () => void;
  deviceId: string;
  deviceName: string;
  credentials: RdpCredential[];
  /** Called after any change, to read the list again. */
  onChanged: () => void;
  /** Called with a credential that was just saved, so a session can start with it. */
  onUse: (id: string) => void;
}) {
  const toast = useToast();
  const current = credentials[0];
  const [form, setForm] = useState<RdpCredentialInput>({ label: "", domain: "", username: "", password: "" });
  useEffect(() => {
    if (!open) return;
    setForm({ label: current?.label ?? "", domain: current?.domain ?? "", username: current?.username ?? "", password: "" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, current?.id]);

  const save = useApiMutation((req: RdpCredentialInput) => api.put<RdpCredential>(rdpCredentialsPath(deviceId), req), {
    onSuccess: (saved) => {
      // The password leaves the form as soon as it is sent.
      setForm((f) => ({ ...f, password: "" }));
      toast.success(current ? "Saved credential replaced." : "Credential saved for this device.");
      onChanged();
      onUse(saved.id);
    },
  });
  const remove = useApiMutation((id: string) => api.del(`${rdpCredentialsPath(deviceId)}/${id}`), {
    onSuccess: () => {
      toast.success("Saved credential deleted.");
      onChanged();
    },
  });
  useEffect(() => {
    if (open) {
      save.reset();
      remove.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const set = <K extends keyof RdpCredentialInput>(k: K, v: RdpCredentialInput[K]) => setForm((f) => ({ ...f, [k]: v }));

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ label: form.label.trim(), domain: form.domain.trim(), username: form.username.trim(), password: form.password });
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Saved RDP credential"
      description={`Saved for ${deviceName}, for you only. The password is stored encrypted on the server and cannot be read back; use it by choosing it when you connect.`}
    >
      <div className="flex flex-col gap-3.5">
        {current && (
          <div className="flex items-center justify-between gap-2 rounded-md border border-line p-2 text-sm">
            <span className="min-w-0">
              <span className="block truncate font-medium text-fg">{current.label}</span>
              <span className="block truncate font-mono text-xs text-muted">{accountOf(current)}</span>
            </span>
            <Button size="sm" variant="danger" icon={<Trash2 className="size-3.5" aria-hidden />} loading={remove.isPending} onClick={() => remove.mutate(current.id)}>
              Delete
            </Button>
          </div>
        )}
        <form onSubmit={submit} className="flex flex-col gap-3.5" autoComplete="off">
          <p className="text-sm font-medium text-fg">{current ? "Replace the credential" : "Save a credential for this device"}</p>
          <TextField label="Label" value={form.label} onChange={(e) => set("label", e.target.value)} error={fieldError(save.error, "label")} maxLength={100} hint="Optional. The user name is used when empty." />
          <TextField label="Domain" value={form.domain} onChange={(e) => set("domain", e.target.value)} error={fieldError(save.error, "domain")} maxLength={255} hint="Leave empty for a local account." />
          <TextField label="User name" value={form.username} onChange={(e) => set("username", e.target.value)} error={fieldError(save.error, "username")} required maxLength={255} />
          <TextField
            label={current ? "New password" : "Password"}
            type="password"
            autoComplete="new-password"
            value={form.password}
            onChange={(e) => set("password", e.target.value)}
            error={fieldError(save.error, "password")}
            required
            maxLength={1024}
          />
          <InlineError error={save.error ?? remove.error} fields={["label", "domain", "username", "password"]} />
          <Alert tone="info">Saving asks you to confirm with your authenticator app or security key.</Alert>
          <div className="flex justify-end gap-2 pt-1">
            <Button type="button" onClick={onClose}>
              Close
            </Button>
            <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.username.trim() || !form.password}>
              {current ? "Replace and connect" : "Save and connect"}
            </Button>
          </div>
        </form>
      </div>
    </Dialog>
  );
}
