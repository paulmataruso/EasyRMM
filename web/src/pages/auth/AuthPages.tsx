import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router";
import { CheckCircle2 } from "lucide-react";
import { api, fieldError, request } from "../../api/client";
import { useApi } from "../../api/hooks";
import type { AuthOptions, ConfirmTotpResult, SessionView, TotpEnrollment } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { CopyButton, DownloadButton, OneTimeNotice } from "../../components/Copy";
import { AuthShell } from "../../components/Layout";
import { Alert, Button, buttonClasses, InlineError, Spinner, TextField } from "../../components/ui";

export const PASSWORD_HINT = "At least 12 characters. Must not contain your name or email address. Passphrases are encouraged.";

/** Only same-site absolute paths are accepted as return targets (prevents open redirects). */
export function safeReturnTo(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\") || value.startsWith("/login")) return "/";
  return value;
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
        <p className="text-center text-xs text-muted">You will set up an authenticator app the first time you sign in.</p>
      </form>
    </AuthShell>
  );
}

// ---------------------------------------------------------------------------------------------
// Sign-in and second factor
// ---------------------------------------------------------------------------------------------

export function LoginPage() {
  const { applySession, sessionEnded, setupEmail } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const options = useApi<AuthOptions>("/auth/options", undefined, { staleTime: 300_000 });
  const returnTo = safeReturnTo(params.get("returnTo"));
  const emailParam = params.get("email") || setupEmail;
  const [email, setEmail] = useState(emailParam ?? "");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [missing, setMissing] = useState<{ email?: string; password?: string }>({});
  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

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
      else navigate(returnTo, { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Sign in" subtitle="EasyRMM technician console">
      <form onSubmit={submit} className="flex flex-col gap-3.5" noValidate>
        {setupEmail && <Alert tone="ok">Setup is complete. Sign in with the account you just created.</Alert>}
        {params.get("reset") === "done" && <Alert tone="ok">Your password is set. Sign in with it now.</Alert>}
        {sessionEnded && !error && <Alert tone="info">Your session ended. Sign in again to continue.</Alert>}
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
        <Button type="submit" variant="primary" loading={busy} className="mt-1 w-full">
          Sign in
        </Button>
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

export function MfaVerifyPage() {
  const { applySession, signOut } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const returnTo = safeReturnTo(params.get("returnTo"));
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [useRecovery, setUseRecovery] = useState(false);
  const [short, setShort] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    // Enabled for the same reason as sign-in: password managers fill one-time codes too.
    const tooShort = code.trim().length < 6;
    setShort(tooShort);
    if (tooShort) return;
    setBusy(true);
    setError(null);
    try {
      const view = await request<SessionView>("POST", "/auth/mfa/verify", { body: { code: code.trim() }, silentAuth: true });
      applySession(view);
      navigate(returnTo, { replace: true });
    } catch (err) {
      setError(err);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Two-factor verification"
      subtitle={useRecovery ? "Enter one of your unused recovery codes." : "Enter the 6-digit code from your authenticator app."}
    >
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField
          key={useRecovery ? "recovery" : "totp"}
          label={useRecovery ? "Recovery code" : "Verification code"}
          name="code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          autoComplete="one-time-code"
          inputMode={useRecovery ? "text" : "numeric"}
          maxLength={useRecovery ? 32 : 7}
          spellCheck={false}
          error={short ? (useRecovery ? "Enter the whole recovery code." : "Enter the 6-digit code from your authenticator app.") : null}
          autoFocus
          required
        />
        <InlineError error={error} />
        <Button type="submit" variant="primary" loading={busy} className="w-full">
          Verify
        </Button>
        <div className="flex items-center justify-between text-xs">
          <button
            type="button"
            className="text-accent hover:underline"
            onClick={() => {
              setUseRecovery((v) => !v);
              setCode("");
              setError(null);
              setShort(false);
            }}
          >
            {useRecovery ? "Use authenticator code" : "Use a recovery code"}
          </button>
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
      </form>
    </AuthShell>
  );
}

/**
 * Authenticator enrollment: scan the QR code, confirm a code, then show the recovery codes once.
 * `onConfirmed` receives the session the server returns once the authenticator is active.
 */
export function MfaEnrollment({ onDone, onConfirmed, submitLabel = "Turn on two-factor authentication" }: {
  onDone: () => void;
  onConfirmed?: (session: SessionView) => void;
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
    if (started.current) return;
    started.current = true;
    api.post<TotpEnrollment>("/auth/mfa/totp/begin").then(setSetup).catch(setSetupError);
  }, []);

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

export function MfaSetupRequiredPage() {
  const { applySession, signOut, setShowingRecoveryCodes } = useAuth();
  const navigate = useNavigate();
  return (
    <AuthShell title="Set up two-factor authentication" subtitle="EasyRMM requires an authenticator app for every account.">
      <MfaEnrollment
        onConfirmed={(view) => {
          // The session is now fully signed in; keep this page until the codes are acknowledged.
          setShowingRecoveryCodes(true);
          applySession(view);
        }}
        onDone={() => {
          setShowingRecoveryCodes(false);
          navigate("/", { replace: true });
        }}
      />
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
        {invite && <p className="text-center text-xs text-muted">Next, sign in and set up an authenticator app.</p>}
      </form>
    </AuthShell>
  );
}
