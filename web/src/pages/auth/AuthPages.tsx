import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router";
import { CheckCircle2, KeyRound, LogIn, Smartphone } from "lucide-react";
import { api, fieldError, request } from "../../api/client";
import { useApi } from "../../api/hooks";
import type { AuthOptions, ConfirmTotpResult, SecurityKeyAdded, SessionView, SsoButton, TotpEnrollment } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { createKey, getKey, KeyCancelled, keyAvailability, type KeyAvailability } from "../../auth/webauthn";
import { CopyButton, DownloadButton, OneTimeNotice } from "../../components/Copy";
import { AuthShell } from "../../components/Layout";
import { Alert, Button, buttonClasses, InlineError, Spinner, TextField } from "../../components/ui";

export const PASSWORD_HINT = "At least 12 characters. Must not contain your name or email address. Passphrases are encouraged.";

/** Only same-site absolute paths are accepted as return targets (prevents open redirects). */
export function safeReturnTo(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\") || value.startsWith("/login")) return "/";
  return value;
}

/** Where a completed sign-in goes: first the offer of a passkey, when the server offers one and keys work here. */
export function afterSignIn(view: SessionView, returnTo: string, keys: KeyAvailability): string {
  if (view.state !== "active" || !view.user.passkeyPrompt || !keys.usable) return returnTo;
  return returnTo !== "/" ? `/login/passkey?returnTo=${encodeURIComponent(returnTo)}` : "/login/passkey";
}

/** A name for a passkey made on this device, such as "Passkey on Windows"; the person can change it. */
export function passkeyName(userAgent = navigator.userAgent): string {
  const platforms: [RegExp, string][] = [
    [/iPhone/, "iPhone"],
    [/iPad/, "iPad"],
    [/Android/, "Android"],
    [/Windows/, "Windows"],
    [/CrOS/, "Chromebook"],
    [/Mac OS X|Macintosh/, "Mac"],
    [/Linux/, "Linux"],
  ];
  const found = platforms.find(([re]) => re.test(userAgent));
  return found ? `Passkey on ${found[1]}` : "Passkey";
}

/** Client-side mirror of the server password policy, for immediate feedback only (the server enforces it). */
export function passwordProblem(password: string, confirm: string, minLength = 12): string | null {
  if (password.length < minLength) return `Use at least ${minLength} characters.`;
  if (password.length > 256) return "Use at most 256 characters.";
  if (confirm && password !== confirm) return "The passwords do not match.";
  return null;
}

// ---------------------------------------------------------------------------------------------
// First-run setup
// ---------------------------------------------------------------------------------------------

export function SetupPage() {
  const { completeSetup } = useAuth();
  const [form, setForm] = useState({ token: "", organizationName: "", displayName: "", email: "", password: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const local = form.password ? passwordProblem(form.password, form.confirm) : null;
  const set = (k: keyof typeof form, v: string) => setForm((f) => ({ ...f, [k]: v }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (local || form.password !== form.confirm) return;
    setBusy(true);
    setError(null);
    try {
      await request("POST", "/setup", {
        silentAuth: true,
        body: {
          token: form.token.trim(),
          email: form.email.trim(),
          displayName: form.displayName.trim(),
          password: form.password,
          organizationName: form.organizationName.trim(),
        },
      });
      // The guard then routes to sign-in, which greets the new administrator with this address filled in.
      await completeSetup(form.email.trim());
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Set up EasyRMM" subtitle="Create the first administrator account for this server." wide>
      <form onSubmit={submit} className="flex flex-col gap-3.5" noValidate>
        <TextField
          label="Setup token"
          value={form.token}
          onChange={(e) => set("token", e.target.value)}
          error={fieldError(error, "token")}
          hint="Find it in the setup-token file in the server's data directory, e.g. sudo cat /srv/easyrmm/server/setup-token"
          autoComplete="off"
          spellCheck={false}
          required
          autoFocus
        />
        <TextField
          label="First organization"
          value={form.organizationName}
          onChange={(e) => set("organizationName", e.target.value)}
          error={fieldError(error, "organizationName")}
          hint="Optional. A customer or your own company; you can add more later."
          maxLength={200}
        />
        <TextField label="Your name" value={form.displayName} onChange={(e) => set("displayName", e.target.value)} error={fieldError(error, "displayName")} autoComplete="name" required />
        <TextField label="Email" type="email" value={form.email} onChange={(e) => set("email", e.target.value)} error={fieldError(error, "email")} autoComplete="email" required />
        <TextField
          label="Password"
          type="password"
          value={form.password}
          onChange={(e) => set("password", e.target.value)}
          error={fieldError(error, "password")}
          hint={PASSWORD_HINT}
          autoComplete="new-password"
          required
        />
        <TextField
          label="Confirm password"
          type="password"
          value={form.confirm}
          onChange={(e) => set("confirm", e.target.value)}
          error={form.confirm && form.password !== form.confirm ? "The passwords do not match." : null}
          autoComplete="new-password"
          required
        />
        <InlineError error={error} fields={["token", "organizationName", "displayName", "email", "password"]} />
        <Button
          type="submit"
          variant="primary"
          loading={busy}
          disabled={!form.token.trim() || !form.email.trim() || !form.displayName.trim() || !!local || form.password !== form.confirm}
          className="mt-1 w-full"
        >
          Create administrator
        </Button>
        <p className="text-center text-xs text-muted">You will set up two-factor authentication the first time you sign in.</p>
      </form>
    </AuthShell>
  );
}

// ---------------------------------------------------------------------------------------------
// Sign-in and second factor
// ---------------------------------------------------------------------------------------------

/** Why a single sign-on came back to the sign-in page (ADR-0034), as the server names it. */
export const SSO_ERRORS: Record<string, string> = {
  expired: "The single sign-on did not finish in this browser, or took more than 10 minutes. Try again.",
  provider: "The identity provider did not complete the sign-in. Try again; if it keeps failing, ask an administrator to check the provider's settings.",
  unavailable: "That single sign-on is not available right now. Sign in with your password, or ask an administrator.",
  no_account: "There is no EasyRMM account for the email address your identity provider gave. Ask an administrator to invite you.",
  domain: "Your identity provider's email address is not in a domain allowed to sign in this way. Ask an administrator.",
  unverified: "Your identity provider did not confirm your email address, so EasyRMM cannot match it to an account. Ask an administrator.",
  linked_other:
    "Your EasyRMM account is linked to a different account at this identity provider. Sign in with that one, or unlink it under Account first.",
  account: "This EasyRMM account is disabled or temporarily locked. Ask an administrator.",
  rate_limited: "Too many sign-in attempts from your network. Wait a few minutes and try again.",
};

export function ssoErrorMessage(code: string): string {
  return SSO_ERRORS[code] ?? "Single sign-on failed. Try again, or sign in with your password.";
}

export function LoginPage() {
  const { applySession, sessionEnded, setupEmail } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const options = useApi<AuthOptions>("/auth/options", undefined, { staleTime: 300_000 });
  const sso = useApi<{ providers: SsoButton[] }>("/auth/sso", undefined, { staleTime: 300_000 });
  const returnTo = safeReturnTo(params.get("returnTo"));
  const ssoError = params.get("sso_error");
  const emailParam = params.get("email") || setupEmail;
  const [email, setEmail] = useState(emailParam ?? "");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [missing, setMissing] = useState<{ email?: string; password?: string }>({});
  const [keyBusy, setKeyBusy] = useState(false);
  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const keys = keyAvailability(options.data?.webauthn);

  // A known address (finished setup, ?email= from a reset) fills the form and moves focus to the password.
  useEffect(() => {
    if (emailParam) {
      setEmail(emailParam);
      passwordRef.current?.focus();
    }
  }, [emailParam]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    // The button stays enabled: password managers can fill the fields without telling React until the
    // first click, and a disabled button would swallow that click. Empty fields are named instead.
    const absent = { email: email.trim() ? undefined : "Enter your email address.", password: password ? undefined : "Enter your password." };
    setMissing(absent);
    if (absent.email || absent.password) {
      (absent.email ? emailRef : passwordRef).current?.focus();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const view = await request<SessionView>("POST", "/auth/login", { body: { email: email.trim(), password }, silentAuth: true });
      setPassword("");
      applySession(view);
      const query = returnTo !== "/" ? `?returnTo=${encodeURIComponent(returnTo)}` : "";
      if (view.state === "mfa_required") navigate(`/login/mfa${query}`, { replace: true });
      else if (view.state === "mfa_enrollment") navigate("/login/mfa-setup", { replace: true });
      else navigate(afterSignIn(view, returnTo, keys), { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  // A passkey verified by PIN or biometric is both factors, so it signs in fully (ADR-0032).
  async function signInWithPasskey() {
    setKeyBusy(true);
    setError(null);
    setMissing({});
    try {
      const options = await request<unknown>("POST", "/auth/passkey/begin", { silentAuth: true });
      const credential = await getKey(options);
      const view = await request<SessionView>("POST", "/auth/passkey/finish", { body: { credential }, silentAuth: true });
      setPassword("");
      applySession(view);
      navigate(returnTo, { replace: true });
    } catch (err) {
      if (!(err instanceof KeyCancelled)) setError(err);
    } finally {
      setKeyBusy(false);
    }
  }

  return (
    <AuthShell title="Sign in" subtitle="EasyRMM technician console">
      <form onSubmit={submit} className="flex flex-col gap-3.5" noValidate>
        {setupEmail && <Alert tone="ok">Setup is complete. Sign in with the account you just created.</Alert>}
        {params.get("reset") === "done" && <Alert tone="ok">Your password is set. Sign in with it now.</Alert>}
        {sessionEnded && !error && !ssoError && <Alert tone="info">Your session ended. Sign in again to continue.</Alert>}
        {ssoError && !error && <Alert tone="danger">{ssoErrorMessage(ssoError)}</Alert>}
        <TextField
          ref={emailRef}
          label="Email"
          type="email"
          name="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          error={missing.email}
          required
          autoFocus={!emailParam}
        />
        <TextField
          ref={passwordRef}
          label="Password"
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={missing.password}
          required
          autoFocus={!!emailParam}
        />
        <InlineError error={error} />
        <Button type="submit" variant="primary" loading={busy} disabled={keyBusy} className="mt-1 w-full">
          Sign in
        </Button>
        {keys.usable && (
          <Button icon={<KeyRound className="size-4" aria-hidden />} loading={keyBusy} disabled={busy} onClick={signInWithPasskey} className="w-full">
            Sign in with a passkey
          </Button>
        )}
        {(sso.data?.providers ?? []).map((p) => (
          <a
            key={p.id}
            href={returnTo !== "/" ? `${p.startUrl}?returnTo=${encodeURIComponent(returnTo)}` : p.startUrl}
            className={`${buttonClasses("secondary")} w-full`}
          >
            <LogIn className="size-4" aria-hidden />
            Sign in with {p.name}
          </a>
        ))}
        {!keys.usable && keys.why === "address" && (
          <p className="text-center text-xs text-muted">
            Passkeys work at{" "}
            <a href={`${keys.origin}/login`} className="text-accent hover:underline">
              {keys.origin}
            </a>
            .
          </p>
        )}
        {options.data?.passwordResetAvailable ? (
          <Link to={`/forgot-password${email ? `?email=${encodeURIComponent(email)}` : ""}`} className="text-center text-xs text-accent hover:underline">
            Forgot your password?
          </Link>
        ) : (
          <p className="text-center text-xs text-muted">Forgot your password? Ask an administrator for a reset link.</p>
        )}
      </form>
    </AuthShell>
  );
}

type SecondFactor = "key" | "totp" | "recovery";

const FACTOR_SUBTITLE: Record<SecondFactor, string> = {
  key: "Use your security key or passkey.",
  totp: "Enter the 6-digit code from your authenticator app.",
  recovery: "Enter one of your unused recovery codes.",
};

const FACTOR_SWITCH: Record<SecondFactor, string> = {
  key: "Use a security key",
  totp: "Use authenticator code",
  recovery: "Use a recovery code",
};

export function MfaVerifyPage() {
  const { applySession, signOut, session } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const options = useApi<AuthOptions>("/auth/options", undefined, { staleTime: 300_000 });
  const returnTo = safeReturnTo(params.get("returnTo"));
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [chosen, setChosen] = useState<SecondFactor | null>(null);
  const [short, setShort] = useState(false);

  const hasKeys = (session?.user.securityKeys ?? 0) > 0;
  const hasTotp = session?.user.totp ?? true;
  const keys = keyAvailability(options.data?.webauthn);
  // A key where it works; else the app; a key the browser cannot use here still says why.
  const method: SecondFactor = chosen ?? (hasKeys && (keys.usable || !hasTotp) ? "key" : hasTotp ? "totp" : "recovery");
  const others = (["key", "totp", "recovery"] as const).filter((m) => m !== method && (m !== "key" || hasKeys) && (m !== "totp" || hasTotp));

  function finish(view: SessionView) {
    applySession(view);
    navigate(afterSignIn(view, returnTo, keys), { replace: true });
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    // Enabled for the same reason as sign-in: password managers fill one-time codes too.
    const tooShort = code.trim().length < 6;
    setShort(tooShort);
    if (tooShort) return;
    setBusy(true);
    setError(null);
    try {
      finish(await request<SessionView>("POST", "/auth/mfa/verify", { body: { code: code.trim() }, silentAuth: true }));
    } catch (err) {
      setError(err);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  async function verifyWithKey() {
    setBusy(true);
    setError(null);
    try {
      const options = await request<unknown>("POST", "/auth/mfa/webauthn/begin", { silentAuth: true });
      const credential = await getKey(options);
      finish(await request<SessionView>("POST", "/auth/mfa/webauthn/finish", { body: { credential }, silentAuth: true }));
    } catch (err) {
      if (!(err instanceof KeyCancelled)) setError(err);
    } finally {
      setBusy(false);
    }
  }

  const waiting = hasKeys && options.isPending && chosen === null;
  return (
    <AuthShell title="Two-factor verification" subtitle={waiting ? undefined : FACTOR_SUBTITLE[method]}>
      <div className="flex flex-col gap-3.5">
        {waiting ? (
          <Spinner label="Loading sign-in options…" />
        ) : method === "key" ? (
          <KeyStep availability={keys} busy={busy} error={error} onUse={verifyWithKey} />
        ) : (
          <form onSubmit={submit} className="flex flex-col gap-3.5">
            <TextField
              key={method}
              label={method === "recovery" ? "Recovery code" : "Verification code"}
              name="code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="one-time-code"
              inputMode={method === "recovery" ? "text" : "numeric"}
              maxLength={method === "recovery" ? 32 : 7}
              spellCheck={false}
              error={short ? (method === "recovery" ? "Enter the whole recovery code." : "Enter the 6-digit code from your authenticator app.") : null}
              autoFocus
              required
            />
            <InlineError error={error} />
            <Button type="submit" variant="primary" loading={busy} className="w-full">
              Verify
            </Button>
          </form>
        )}
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 text-xs">
          <div className="flex flex-wrap gap-x-4 gap-y-2">
            {others.map((m) => (
              <button
                key={m}
                type="button"
                className="text-accent hover:underline"
                disabled={busy}
                onClick={() => {
                  setChosen(m);
                  setCode("");
                  setError(null);
                  setShort(false);
                }}
              >
                {FACTOR_SWITCH[m]}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="text-muted hover:text-fg"
            onClick={async () => {
              await signOut();
              navigate("/login", { replace: true });
            }}
          >
            Sign in as someone else
          </button>
        </div>
      </div>
    </AuthShell>
  );
}

/** The security-key step: one button, or why keys cannot be used on this page. */
function KeyStep({ availability, busy, error, onUse }: { availability: KeyAvailability; busy: boolean; error: unknown; onUse: () => void }) {
  if (!availability.usable) {
    return (
      <Alert tone="warn">
        {availability.message}
        {availability.why === "address" && (
          <>
            {" "}
            <a href={`${availability.origin}/login`} className="font-medium underline">
              Sign in there
            </a>
            , or use another way below.
          </>
        )}
      </Alert>
    );
  }
  return (
    <>
      <p className="text-sm text-muted">Your browser will ask you to insert or touch your key, or to confirm with your fingerprint, face or PIN.</p>
      <InlineError error={error} />
      <Button variant="primary" icon={<KeyRound className="size-4" aria-hidden />} loading={busy} onClick={onUse} className="w-full" autoFocus>
        Use security key
      </Button>
    </>
  );
}

/**
 * Authenticator enrollment: scan the QR code, confirm a code, then show the recovery codes once.
 * `onConfirmed` receives the session the server returns once the authenticator is active.
 * Signed-in users (`needsPassword`) confirm their password before the secret is shown.
 */
export function MfaEnrollment({
  onDone,
  onConfirmed,
  onCancel,
  needsPassword = false,
  submitLabel = "Turn on two-factor authentication",
}: {
  onDone: () => void;
  onConfirmed?: (session: SessionView) => void;
  onCancel?: () => void;
  needsPassword?: boolean;
  submitLabel?: string;
}) {
  const [setup, setSetup] = useState<TotpEnrollment | null>(null);
  const [setupError, setSetupError] = useState<unknown>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (needsPassword || started.current) return;
    started.current = true;
    api.post<TotpEnrollment>("/auth/mfa/totp/begin").then(setSetup).catch(setSetupError);
  }, [needsPassword]);

  async function confirm(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<ConfirmTotpResult>("/auth/mfa/totp/confirm", { code: code.trim() });
      setCodes(result.recoveryCodes);
      onConfirmed?.(result.session);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (codes) return <RecoveryCodesView codes={codes} onDone={onDone} />;
  if (!setup && needsPassword) return <TotpPasswordStep onReady={setSetup} onCancel={onCancel} />;
  if (setupError) return <InlineError error={setupError} />;
  if (!setup) return <Spinner label="Preparing authenticator setup…" />;

  const grouped = setup.secret.replace(/(.{4})/g, "$1 ").trim();
  return (
    <form onSubmit={confirm} className="flex flex-col gap-4">
      <ol className="list-decimal space-y-1 pl-5 text-sm text-fg">
        <li>Open an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden…).</li>
        <li>Scan the QR code, or enter the secret key by hand.</li>
        <li>Enter the 6-digit code the app shows.</li>
      </ol>
      <div className="flex flex-col items-center gap-3">
        <img src={setup.qrCodeSvg} alt="QR code for your authenticator app" width={192} height={192} className="rounded-md bg-white p-2" />
        <div className="w-full text-center">
          <p className="text-xs text-muted">Secret key</p>
          <p className="font-mono text-sm tracking-wider select-all">{grouped}</p>
          <CopyButton text={setup.secret} label="Copy secret" className="mt-1.5" />
        </div>
      </div>
      <TextField
        label="Verification code"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        autoComplete="one-time-code"
        inputMode="numeric"
        maxLength={7}
        required
      />
      <InlineError error={error} />
      <Button type="submit" variant="primary" loading={busy} disabled={code.trim().length < 6}>
        {submitLabel}
      </Button>
    </form>
  );
}

/** The password check before a signed-in user sees a new authenticator secret. */
function TotpPasswordStep({ onReady, onCancel }: { onReady: (setup: TotpEnrollment) => void; onCancel?: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      onReady(await api.post<TotpEnrollment>("/auth/mfa/totp/begin", { password }));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3.5" noValidate>
      <p className="text-sm text-muted">Enter your password to see the code for your authenticator app.</p>
      <TextField
        label="Password"
        type="password"
        autoComplete="current-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        error={fieldError(error, "password")}
        required
        autoFocus
      />
      <InlineError error={error} fields={["password"]} />
      <div className="flex justify-end gap-2">
        {onCancel && (
          <Button onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
        )}
        <Button type="submit" variant="primary" loading={busy} disabled={!password}>
          Continue
        </Button>
      </div>
    </form>
  );
}

export function RecoveryCodesView({ codes, onDone, doneLabel = "Continue" }: { codes: string[]; onDone: () => void; doneLabel?: string }) {
  const [saved, setSaved] = useState(false);
  const text = codes.join("\n");
  return (
    <div className="flex flex-col gap-3.5">
      <OneTimeNotice>Each recovery code signs you in once if you lose your authenticator. Store them in your password manager.</OneTimeNotice>
      <ul className="grid grid-cols-2 gap-1.5 rounded-md border border-line bg-raised p-3 font-mono text-sm">
        {codes.map((c) => (
          <li key={c} className="select-all">
            {c}
          </li>
        ))}
      </ul>
      <div className="flex gap-2">
        <CopyButton text={text} label="Copy codes" />
        <DownloadButton fileName="easyrmm-recovery-codes.txt" text={`EasyRMM recovery codes\n\n${text}\n`} />
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} className="size-4" />
        I have saved these recovery codes
      </label>
      <Button variant="primary" disabled={!saved} onClick={onDone}>
        {doneLabel}
      </Button>
    </div>
  );
}

/**
 * Registers a security key or passkey: name it, then let the browser create the credential. The first second
 * factor brings recovery codes, shown once before `onDone`. Signed-in users confirm their password.
 */
export function SecurityKeyEnrollment({
  needsPassword,
  existingNames = [],
  defaultName = "",
  onConfirmed,
  onDone,
  onCancel,
  submitLabel = "Add security key",
}: {
  needsPassword: boolean;
  existingNames?: string[];
  defaultName?: string;
  onConfirmed?: (result: SecurityKeyAdded) => void;
  onDone: () => void;
  onCancel?: () => void;
  submitLabel?: string;
}) {
  const [name, setName] = useState(defaultName);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const trimmed = name.trim();
  // Checked here first: a refusal after the person touched their key would waste the touch.
  const nameProblem =
    [...trimmed].length > 64 ? "Use at most 64 characters." : existingNames.includes(trimmed) ? "You already have a key with this name." : null;

  async function add(e: FormEvent) {
    e.preventDefault();
    if (!trimmed || nameProblem || (needsPassword && !password)) return;
    setBusy(true);
    setError(null);
    try {
      const options = await api.post<unknown>("/auth/security-keys/begin", { password });
      const credential = await createKey(options);
      const result = await api.post<SecurityKeyAdded>("/auth/security-keys/finish", { name: trimmed, credential });
      setPassword("");
      onConfirmed?.(result);
      if (result.recoveryCodes.length > 0) setCodes(result.recoveryCodes);
      else onDone();
    } catch (err) {
      if (!(err instanceof KeyCancelled)) setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (codes) return <RecoveryCodesView codes={codes} onDone={onDone} />;
  const submit = (
    <Button
      type="submit"
      variant="primary"
      icon={<KeyRound className="size-4" aria-hidden />}
      loading={busy}
      disabled={!trimmed || !!nameProblem || (needsPassword && !password)}
      className={onCancel ? undefined : "w-full"}
    >
      {submitLabel}
    </Button>
  );
  return (
    <form onSubmit={add} className="flex flex-col gap-3.5" noValidate>
      <TextField
        label="Key name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        error={nameProblem ?? fieldError(error, "name")}
        hint="So you can tell your keys apart, e.g. YubiKey 5C or Work laptop."
        autoComplete="off"
        maxLength={80}
        required
        autoFocus={!defaultName}
      />
      {needsPassword && (
        <TextField
          label="Password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={fieldError(error, "password")}
          required
          // A suggested name leaves only the password to type.
          autoFocus={!!defaultName}
        />
      )}
      <p className="text-xs text-muted">Next, your browser asks you to insert or touch the key, or to confirm with your fingerprint, face or PIN.</p>
      <InlineError error={error} fields={["name", "password"]} />
      {onCancel ? (
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          {submit}
        </div>
      ) : (
        submit
      )}
    </form>
  );
}

/**
 * Offered once a sign-in with a password and a code is complete, to people without a passkey (ADR-0032). Adding one
 * asks for the password again, as everywhere else; "Not now" asks again in 30 days, and "Don't ask again" stops.
 */
export function PasskeyPromptPage() {
  const { session, applySession } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const returnTo = safeReturnTo(params.get("returnTo"));
  // Decided once: adding a key changes the count, and a first key still has recovery codes to show.
  const [offered] = useState(() => (session?.user.securityKeys ?? 0) === 0);
  const [answering, setAnswering] = useState<"later" | "never" | null>(null);
  const leave = () => navigate(returnTo, { replace: true });

  async function answer(choice: "later" | "never") {
    setAnswering(choice);
    try {
      await api.post("/auth/passkey-prompt", { answer: choice });
    } catch {
      // Unrecorded, the offer comes again at the next sign-in; not a reason to hold the person here.
    }
    leave();
  }

  if (!offered) return <Navigate to={returnTo} replace />;
  return (
    <AuthShell title="Add a passkey" subtitle="Sign in next time with your fingerprint, face, PIN or security key.">
      <p className="mb-4 text-sm text-muted">
        A passkey replaces your password and code. It works only at EasyRMM&apos;s own address, so a fake sign-in page cannot use it.
      </p>
      <SecurityKeyEnrollment
        needsPassword
        defaultName={passkeyName()}
        onConfirmed={(r) => applySession(r.session)}
        onDone={leave}
        submitLabel="Add passkey"
      />
      <div className="mt-4 flex items-center justify-center gap-5 text-xs">
        <button
          type="button"
          className="text-accent hover:underline disabled:opacity-50"
          disabled={answering !== null}
          onClick={() => void answer("later")}
        >
          Not now
        </button>
        <button
          type="button"
          className="text-muted hover:text-fg disabled:opacity-50"
          disabled={answering !== null}
          onClick={() => void answer("never")}
        >
          Don&apos;t ask again
        </button>
      </div>
      <p className="mt-3 text-center text-xs text-muted">You can add one at any time under Account.</p>
    </AuthShell>
  );
}

export function MfaSetupRequiredPage() {
  const { applySession, signOut, setShowingRecoveryCodes } = useAuth();
  const navigate = useNavigate();
  const options = useApi<AuthOptions>("/auth/options", undefined, { staleTime: 300_000 });
  const [chosen, setChosen] = useState<"key" | "app" | null>(null);
  const keys = keyAvailability(options.data?.webauthn);
  const method = chosen ?? (keys.usable ? null : "app");

  function confirmed(view: SessionView) {
    // The session is now fully signed in; keep this page until the codes are acknowledged.
    setShowingRecoveryCodes(true);
    applySession(view);
  }
  function done() {
    setShowingRecoveryCodes(false);
    navigate("/", { replace: true });
  }
  const switchTo = (m: "key" | "app", label: string) => (
    <button type="button" className="mt-3 w-full text-center text-xs text-accent hover:underline" onClick={() => setChosen(m)}>
      {label}
    </button>
  );

  return (
    <AuthShell
      title="Set up two-factor authentication"
      subtitle="EasyRMM requires a second factor for every account, so a stolen password is not enough to sign in."
    >
      {options.isPending && !chosen ? (
        <Spinner label="Loading sign-in options…" />
      ) : method === null ? (
        <div className="flex flex-col gap-2.5">
          <ChoiceButton
            icon={<KeyRound className="size-5" aria-hidden />}
            title="Security key or passkey"
            detail="A key such as a YubiKey, or a passkey on this device or in your password manager. It only works at EasyRMM's own address, so it cannot be phished."
            onClick={() => setChosen("key")}
          />
          <ChoiceButton
            icon={<Smartphone className="size-5" aria-hidden />}
            title="Authenticator app"
            detail="6-digit codes from an app such as Microsoft Authenticator, Google Authenticator or 1Password."
            onClick={() => setChosen("app")}
          />
          <p className="text-xs text-muted">You can add the other kind later, under Account.</p>
        </div>
      ) : method === "key" ? (
        <>
          <SecurityKeyEnrollment needsPassword={false} onConfirmed={(r) => confirmed(r.session)} onDone={done} submitLabel="Add security key" />
          {switchTo("app", "Use an authenticator app instead")}
        </>
      ) : (
        <>
          <MfaEnrollment onConfirmed={confirmed} onDone={done} />
          {keys.usable && switchTo("key", "Use a security key or passkey instead")}
        </>
      )}
      <button
        type="button"
        className="mt-4 w-full text-center text-xs text-muted hover:text-fg"
        onClick={async () => {
          await signOut();
          navigate("/login", { replace: true });
        }}
      >
        Sign out
      </button>
    </AuthShell>
  );
}

function ChoiceButton({ icon, title, detail, onClick }: { icon: ReactNode; title: string; detail: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-start gap-3 rounded-md border border-line bg-raised p-3.5 text-left transition-colors hover:border-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
    >
      <span className="mt-0.5 shrink-0 text-accent">{icon}</span>
      <span>
        <span className="block text-sm font-medium text-fg">{title}</span>
        <span className="mt-0.5 block text-xs text-muted">{detail}</span>
      </span>
    </button>
  );
}

// ---------------------------------------------------------------------------------------------
// Password reset and invitations
// ---------------------------------------------------------------------------------------------

export function ForgotPasswordPage() {
  const [params] = useSearchParams();
  const [email, setEmail] = useState(params.get("email") ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [empty, setEmpty] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setEmpty(!email.trim());
    if (!email.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const result = await request<{ message: string }>("POST", "/auth/password-reset/request", { body: { email: email.trim() }, silentAuth: true });
      setMessage(result.message);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Reset your password" subtitle="We will email you a link to choose a new password.">
      {message ? (
        <div className="flex flex-col gap-3.5">
          <Alert tone="ok">{message}</Alert>
          <p className="text-sm text-muted">The link works once and expires soon. Check your spam folder if it does not arrive.</p>
          <Link to="/login" className={buttonClasses("secondary")}>
            Back to sign in
          </Link>
        </div>
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-3.5" noValidate>
          <TextField
            label="Email"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            error={empty ? "Enter your email address." : null}
            required
            autoFocus
          />
          <InlineError error={error} />
          <Button type="submit" variant="primary" loading={busy} className="w-full">
            Send reset link
          </Button>
          <Link to="/login" className="text-center text-xs text-muted hover:text-fg">
            Back to sign in
          </Link>
        </form>
      )}
    </AuthShell>
  );
}

/**
 * Completes a password reset (/reset-password) or an invitation (/welcome). The token travels in the URL
 * fragment, so it never reaches server logs; it is read once and removed from the address bar.
 */
export function ResetPasswordPage({ invite = false }: { invite?: boolean }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [token] = useState(() => new URLSearchParams(location.hash.replace(/^#/, "")).get("token") ?? "");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const local = password ? passwordProblem(password, confirm) : null;

  useEffect(() => {
    if (location.hash) window.history.replaceState(window.history.state, "", location.pathname);
  }, [location.hash, location.pathname]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (local || password !== confirm) return;
    setBusy(true);
    setError(null);
    try {
      await request("POST", "/auth/password-reset/complete", { body: { token, password }, silentAuth: true });
      navigate("/login?reset=done", { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const title = invite ? "Welcome to EasyRMM" : "Choose a new password";
  const subtitle = invite ? "Choose a password to finish setting up your account." : "Your new password replaces the old one and signs out your other sessions.";

  if (!token) {
    return (
      <AuthShell title={title}>
        <div className="flex flex-col gap-3.5">
          <Alert tone="warn">This link is incomplete. Open the link from your email again, or ask an administrator for a new one.</Alert>
          <Link to="/login" className={buttonClasses("secondary")}>
            Go to sign in
          </Link>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell title={title} subtitle={subtitle}>
      <form onSubmit={submit} className="flex flex-col gap-3.5" noValidate>
        <TextField
          label="New password"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={fieldError(error, "password")}
          hint={PASSWORD_HINT}
          required
          autoFocus
        />
        <TextField
          label="Confirm new password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          error={confirm && password !== confirm ? "The passwords do not match." : null}
          required
        />
        <InlineError error={error} fields={["password"]} />
        <Button type="submit" variant="primary" loading={busy} disabled={!!local || password !== confirm} className="w-full" icon={<CheckCircle2 className="size-4" aria-hidden />}>
          {invite ? "Set password" : "Change password"}
        </Button>
        {invite && <p className="text-center text-xs text-muted">Next, sign in and set up two-factor authentication.</p>}
      </form>
    </AuthShell>
  );
}

/**
 * The one-time sign-in link `easyrmm-server recover` prints for a super administrator, for when single sign-on is
 * down (ADR-0044). Like a reset link, its token is in the fragment, read once and removed from the address bar.
 */
export function RecoverPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const { applySession } = useAuth();
  const [token] = useState(() => new URLSearchParams(location.hash.replace(/^#/, "")).get("token") ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (location.hash) window.history.replaceState(window.history.state, "", location.pathname);
  }, [location.hash, location.pathname]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const view = await request<SessionView>("POST", "/auth/recover", { body: { token }, silentAuth: true });
      applySession(view);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <AuthShell title="Recovery sign-in">
        <div className="flex flex-col gap-3.5">
          <Alert tone="warn">This link is incomplete. Copy the whole link the recover command printed, or run it again.</Alert>
          <Link to="/login" className={buttonClasses("secondary")}>
            Go to sign in
          </Link>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Recovery sign-in" subtitle="A one-time link from the server, for when single sign-on is not working.">
      <form onSubmit={submit} className="flex flex-col gap-3.5" noValidate>
        <InlineError error={error} />
        <Button type="submit" variant="primary" loading={busy} className="w-full" icon={<LogIn className="size-4" aria-hidden />}>
          Sign in
        </Button>
        <p className="text-center text-xs text-muted">The link works once. Signing in with it is recorded in the audit log.</p>
      </form>
    </AuthShell>
  );
}
