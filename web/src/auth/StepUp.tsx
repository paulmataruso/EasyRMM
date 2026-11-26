// Step-up authentication in the console (ADR-0055). When the server refuses a request with `step_up_required`, the API
// client asks this dialog, which asks for a second factor (an authenticator app's code, a security key or passkey, or a
// fresh sign-in at the identity provider the account signs in through), and the request is sent again once.
// A recovery code or a password does not do.

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { useLocation } from "react-router";
import { api, setStepUpHandler } from "../api/client";
import type { StepUpStatus } from "../api/types";
import { Dialog } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { Alert, Button, InlineError, Segmented, Spinner, TextField } from "../components/ui";
import { leaveFor } from "../lib/navigate";
import { getKey, KeyCancelled, NO_KEY_ANSWERED } from "./webauthn";

type Method = StepUpStatus["methods"][number];

/** Why a fresh sign-in at the provider did not step the session up, by the code the server put in the address. */
const OIDC_REASONS: Record<string, string> = {
  identity: "That was not the account you are signed in with. Sign in again as yourself.",
  auth_time: "The provider did not ask you to sign in again. Try again.",
  trust: "Your administrator no longer trusts that provider to ask for a second factor. Use your authenticator app or a security key.",
  expired: "That sign-in took too long. Try again.",
};

/** Mounted once, inside the auth provider: registers the handler the API client calls, and shows the dialog. */
export function StepUpGate() {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const waiting = useRef<((done: boolean) => void)[]>([]);

  const finish = useCallback((done: boolean) => {
    const list = waiting.current;
    waiting.current = [];
    setOpen(false);
    for (const resolve of list) resolve(done);
  }, []);

  useEffect(() => {
    // Requests that fail together share one dialog.
    setStepUpHandler(
      () =>
        new Promise<boolean>((resolve) => {
          waiting.current.push(resolve);
          setOpen(true);
        }),
    );
    return () => {
      setStepUpHandler(null);
      for (const resolve of waiting.current) resolve(false);
      waiting.current = [];
    };
  }, []);

  // Back from the identity provider: it sends the browser to the page it left with ?stepup=done or failed.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const outcome = params.get("stepup");
    if (!outcome) return;
    const reason = params.get("reason") ?? "";
    params.delete("stepup");
    params.delete("reason");
    const rest = params.toString();
    window.history.replaceState(null, "", `${window.location.pathname}${rest ? `?${rest}` : ""}${window.location.hash}`);
    if (outcome === "done") toast.success("Confirmed. Do what you were doing again; it is allowed for the next 5 minutes.");
    else toast.error(OIDC_REASONS[reason] ?? "Your provider did not confirm it was you. Try again.");
  }, [toast]);

  return (
    <Dialog
      open={open}
      onClose={() => finish(false)}
      title="Confirm it is you"
      description="This needs your second factor again, even though you are signed in. It stays allowed for 5 minutes."
      size="sm"
    >
      {open && <StepUpForm onDone={() => finish(true)} onCancel={() => finish(false)} />}
    </Dialog>
  );
}

function StepUpForm({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [status, setStatus] = useState<StepUpStatus | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [method, setMethod] = useState<Method | null>(null);

  useEffect(() => {
    let live = true;
    api
      .get<StepUpStatus>("/auth/step-up")
      .then((s) => {
        if (!live) return;
        setStatus(s);
        setMethod(s.methods[0] ?? null);
      })
      .catch((e: unknown) => live && setLoadError(e));
    return () => {
      live = false;
    };
  }, []);

  if (loadError) return <InlineError error={loadError} />;
  if (!status) return <Spinner label="Loading…" />;
  if (status.methods.length === 0 || method === null) {
    return (
      <div className="flex flex-col gap-3">
        <Alert tone="warn" title="No second factor to confirm with">
          Set up an authenticator app or a security key in your account settings first. A password and recovery codes cannot confirm this.
        </Alert>
        <div className="flex justify-end">
          <Button onClick={onCancel}>Close</Button>
        </div>
      </div>
    );
  }
  const labels: Record<Method, string> = { totp: "Authenticator app", webauthn: "Security key", oidc: status.provider ? `Sign in at ${status.provider}` : "Provider" };
  return (
    <div className="flex flex-col gap-3.5">
      {status.methods.length > 1 && (
        <Segmented<Method> label="Confirm with" options={status.methods.map((m) => ({ value: m, label: labels[m] }))} value={method} onChange={setMethod} />
      )}
      {method === "totp" && <CodeStep onDone={onDone} onCancel={onCancel} />}
      {method === "webauthn" && <KeyStep onDone={onDone} onCancel={onCancel} />}
      {method === "oidc" && <ProviderStep provider={status.provider ?? "your identity provider"} onCancel={onCancel} />}
    </div>
  );
}

function CodeStep({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post("/auth/step-up/totp", { code: code.trim() });
      onDone();
    } catch (err) {
      setError(err);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3.5">
      <TextField
        label="Code from your authenticator app"
        hint="A code you have already used does not work; wait for the next one."
        name="code"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        autoComplete="one-time-code"
        inputMode="numeric"
        maxLength={7}
        spellCheck={false}
        autoFocus
        required
      />
      <InlineError error={error} />
      <div className="flex justify-end gap-2">
        <Button type="button" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={busy} icon={<ShieldCheck className="size-4" aria-hidden />}>
          Confirm
        </Button>
      </div>
    </form>
  );
}

function KeyStep({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [noKey, setNoKey] = useState(false);

  async function use() {
    setBusy(true);
    setError(null);
    setNoKey(false);
    try {
      const options = await api.post<unknown>("/auth/step-up/webauthn/begin");
      const credential = await getKey(options);
      await api.post("/auth/step-up/webauthn/finish", { credential });
      onDone();
    } catch (err) {
      if (err instanceof KeyCancelled) setNoKey(true);
      else setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-3.5">
      <p className="text-sm text-muted">Touch your security key or use your passkey when your browser asks.</p>
      {noKey && <Alert tone="info">{NO_KEY_ANSWERED}</Alert>}
      <InlineError error={error} />
      <div className="flex justify-end gap-2">
        <Button type="button" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" loading={busy} onClick={() => void use()} icon={<KeyRound className="size-4" aria-hidden />}>
          Use a security key
        </Button>
      </div>
    </div>
  );
}

function ProviderStep({ provider, onCancel }: { provider: string; onCancel: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const location = useLocation();

  async function go() {
    setBusy(true);
    setError(null);
    try {
      const returnTo = `${location.pathname}${location.search}`;
      const { authUrl } = await api.post<{ authUrl: string }>("/auth/step-up/oidc/begin", { returnTo });
      // The provider asks you to sign in again, then sends the browser back to this page; do what you were doing then.
      leaveFor(authUrl);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-3.5">
      <p className="text-sm text-muted">
        You sign in through {provider}. It will ask you to sign in again, then bring you back here. Then do what you were doing again.
      </p>
      <InlineError error={error} />
      <div className="flex justify-end gap-2">
        <Button type="button" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" loading={busy} onClick={() => void go()}>
          Sign in again at {provider}
        </Button>
      </div>
    </div>
  );
}
