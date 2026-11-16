import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { KeyRound, LogOut, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { api, fieldError } from "../../api/client";
import { pathKey, useApi, useApiMutation, useList } from "../../api/hooks";
import type { AuthOptions, RecoveryCodes, SecurityKey, SessionItem, SessionView } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { keyAvailability } from "../../auth/webauthn";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Badge, Button, Card, ErrorState, InlineError, KeyValueList, PageHeader, Spinner, TableWrap, TextField } from "../../components/ui";
import { describeUserAgent, formatDateTime, formatRelative } from "../../lib/format";
import { MfaEnrollment, PASSWORD_HINT, passwordProblem, RecoveryCodesView, SecurityKeyEnrollment } from "../auth/AuthPages";

export function AccountPage() {
  const { session } = useAuth();
  if (!session) return null;
  return (
    <>
      <PageHeader title="Account" subtitle="Your profile, password, second factors and signed-in sessions." />
      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-2">
        <ProfileCard />
        <PasswordCard />
        <SecondFactorCard />
        <SecurityKeysCard />
        <SessionsCard />
      </div>
    </>
  );
}

function ProfileCard() {
  const { session, refresh } = useAuth();
  const toast = useToast();
  const [name, setName] = useState(session?.user.displayName ?? "");
  const save = useApiMutation((displayName: string) => api.patch("/me", { displayName }), {
    invalidate: ["/users", "/audit"],
    onSuccess: async () => {
      await refresh();
      toast.success("Name updated.");
    },
  });
  if (!session) return null;
  return (
    <Card title="Profile">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(name.trim());
        }}
        className="flex flex-col gap-3.5"
      >
        <KeyValueList items={[["Email", session.user.email]]} />
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} error={fieldError(save.error, "displayName")} autoComplete="name" required maxLength={200} />
        <InlineError error={save.error} fields={["displayName"]} />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!name.trim() || name.trim() === session.user.displayName}>
            Save name
          </Button>
        </div>
      </form>
    </Card>
  );
}

function PasswordCard() {
  const toast = useToast();
  const { applySession } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const local = next ? passwordProblem(next, confirm) : null;
  // The session continues under a new token, so the server returns it (with a new CSRF token).
  const save = useApiMutation((body: { currentPassword: string; newPassword: string }) => api.post<SessionView>("/auth/password", body), {
    invalidate: ["/auth/sessions", "/audit"],
    onSuccess: (view) => {
      applySession(view);
      setCurrent("");
      setNext("");
      setConfirm("");
      toast.success("Password changed. Your other sessions were signed out.");
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (local || next !== confirm) return;
    save.mutate({ currentPassword: current, newPassword: next });
  }

  return (
    <Card title="Password">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField
          label="Current password"
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          error={fieldError(save.error, "currentPassword")}
          required
        />
        <TextField
          label="New password"
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          error={fieldError(save.error, "newPassword")}
          hint={PASSWORD_HINT}
          required
        />
        <TextField
          label="Confirm new password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          error={confirm && next !== confirm ? "The passwords do not match." : null}
          required
        />
        <InlineError error={save.error} fields={["currentPassword", "newPassword"]} />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!current || !!local || next !== confirm}>
            Change password
          </Button>
        </div>
      </form>
    </Card>
  );
}

function SecondFactorCard() {
  const { session, applySession } = useAuth();
  const [codesOpen, setCodesOpen] = useState(false);
  const [enrollOpen, setEnrollOpen] = useState(false);
  if (!session) return null;
  const { totp, mfaEnabled } = session.user;
  return (
    <Card title="Two-factor authentication">
      <div className="flex flex-col gap-3.5">
        <div className="flex items-start gap-2.5">
          <ShieldCheck
            className={totp ? "mt-0.5 size-5 shrink-0 text-ok" : mfaEnabled ? "mt-0.5 size-5 shrink-0 text-muted" : "mt-0.5 size-5 shrink-0 text-warn"}
            aria-hidden
          />
          <div className="text-sm">
            <p className="font-medium">{totp ? "Authenticator app is on" : "No authenticator app"}</p>
            <p className="text-muted">
              {totp
                ? "You can enter a code from your authenticator app when you sign in. To move to a new phone, ask another administrator to reset your second factor, then set it up again at sign-in."
                : mfaEnabled
                  ? "Optional. An app gives you another way in if you lose your security keys."
                  : "Add an authenticator app or a security key so a stolen password is not enough to sign in."}
            </p>
          </div>
        </div>
        {mfaEnabled && <p className="text-sm text-muted">Recovery codes sign you in once each if you lose every other second factor.</p>}
        <div className="flex flex-wrap gap-2">
          {!totp && (
            <Button variant={mfaEnabled ? "secondary" : "primary"} icon={<ShieldCheck className="size-4" aria-hidden />} onClick={() => setEnrollOpen(true)}>
              Set up authenticator
            </Button>
          )}
          {mfaEnabled && (
            <Button icon={<KeyRound className="size-4" aria-hidden />} onClick={() => setCodesOpen(true)}>
              New recovery codes
            </Button>
          )}
        </div>
      </div>
      <RecoveryCodesDialog open={codesOpen} onClose={() => setCodesOpen(false)} />
      <Dialog open={enrollOpen} onClose={() => setEnrollOpen(false)} title="Set up authenticator" dismissible={false}>
        {enrollOpen && (
          <MfaEnrollment
            needsPassword
            onConfirmed={(view) => applySession(view)}
            onDone={() => setEnrollOpen(false)}
            onCancel={() => setEnrollOpen(false)}
          />
        )}
      </Dialog>
    </Card>
  );
}

const MAX_KEYS = 10;

function SecurityKeysCard() {
  const { session, applySession, refresh } = useAuth();
  const client = useQueryClient();
  const options = useApi<AuthOptions>("/auth/options", undefined, { staleTime: 300_000 });
  const keys = useList<SecurityKey>("/auth/security-keys");
  const [adding, setAdding] = useState(false);
  const [codesShown, setCodesShown] = useState(false);
  const [removing, setRemoving] = useState<SecurityKey | null>(null);
  if (!session) return null;
  const availability = keyAvailability(options.data?.webauthn);
  const full = keys.items.length >= MAX_KEYS;

  async function added() {
    await client.invalidateQueries({ queryKey: pathKey("/auth/security-keys") });
    await client.invalidateQueries({ queryKey: pathKey("/audit") });
  }

  return (
    <Card title="Security keys and passkeys">
      <div className="flex flex-col gap-3.5">
        <p className="text-sm text-muted">
          Sign in with a key such as a YubiKey, or a passkey on this device or in your password manager. They only work at EasyRMM's own address, so a
          look-alike site cannot use them.
        </p>
        {keys.isPending ? (
          <Spinner />
        ) : keys.isError ? (
          <ErrorState error={keys.error} onRetry={() => void keys.refetch()} compact />
        ) : keys.items.length > 0 ? (
          <ul className="divide-y divide-line rounded-md border border-line">
            {keys.items.map((k) => (
              <li key={k.id} className="flex items-center gap-3 px-3 py-2.5">
                <KeyRound className="size-4 shrink-0 text-muted" aria-hidden />
                <div className="min-w-0 flex-1 text-sm">
                  <p className="flex flex-wrap items-center gap-2 font-medium">
                    <span className="truncate">{k.name}</span>
                    {k.synced && (
                      <Badge tone="neutral" title="A passkey your platform or password manager copies between your devices.">
                        Synced
                      </Badge>
                    )}
                  </p>
                  <p className="text-xs text-muted">
                    Added {formatDateTime(k.createdAt)} ·{" "}
                    {k.lastUsedAt ? <span title={formatDateTime(k.lastUsedAt)}>last used {formatRelative(k.lastUsedAt)}</span> : "not used yet"}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="danger-ghost"
                  icon={<Trash2 className="size-3.5" aria-hidden />}
                  onClick={() => setRemoving(k)}
                  aria-label={`Remove ${k.name}`}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm">No security keys or passkeys yet.</p>
        )}
        {!availability.usable ? (
          <p className="text-sm text-muted">
            {availability.message}
            {availability.why === "address" && (
              <>
                {" "}
                <a href={`${availability.origin}/account`} className="text-accent hover:underline">
                  Open your account there
                </a>{" "}
                to add one.
              </>
            )}
          </p>
        ) : (
          <div className="flex flex-wrap items-center gap-3">
            <Button
              variant={session.user.mfaEnabled ? "secondary" : "primary"}
              icon={<Plus className="size-4" aria-hidden />}
              onClick={() => setAdding(true)}
              disabled={full || keys.isPending}
            >
              Add security key
            </Button>
            {full && <span className="text-xs text-muted">You have {MAX_KEYS}, the most allowed. Remove one to add another.</span>}
          </div>
        )}
      </div>
      <Dialog
        open={adding}
        onClose={() => setAdding(false)}
        title={codesShown ? "Save your recovery codes" : "Add a security key or passkey"}
        dismissible={!codesShown}
      >
        {adding && (
          <SecurityKeyEnrollment
            needsPassword
            existingNames={keys.items.map((k) => k.name)}
            onConfirmed={(r) => {
              applySession(r.session);
              setCodesShown(r.recoveryCodes.length > 0);
              void added();
            }}
            onDone={() => {
              setAdding(false);
              setCodesShown(false);
            }}
            onCancel={() => setAdding(false)}
          />
        )}
      </Dialog>
      <RemoveKeyDialog
        target={removing}
        onClose={() => setRemoving(null)}
        onRemoved={async () => {
          setRemoving(null);
          await Promise.all([refresh(), added()]);
        }}
      />
    </Card>
  );
}

function RemoveKeyDialog({ target, onClose, onRemoved }: { target: SecurityKey | null; onClose: () => void; onRemoved: () => Promise<void> }) {
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const remove = useApiMutation((v: { id: string; password: string }) => api.post(`/auth/security-keys/${v.id}/remove`, { password: v.password }), {
    onSuccess: async () => {
      setPassword("");
      await onRemoved();
      toast.success(`${name} no longer signs you in.`);
    },
  });
  function close() {
    setPassword("");
    remove.reset();
    onClose();
  }
  return (
    <Dialog open={target !== null} onClose={close} title={target ? `Remove ${target.name}` : "Remove security key"}>
      {target && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setName(target.name);
            remove.mutate({ id: target.id, password });
          }}
          className="flex flex-col gap-3.5"
        >
          <p className="text-sm">
            {target.name} will no longer sign you in to EasyRMM. The key itself, or the passkey in your password manager, is not changed; you can delete the
            passkey there too. Enter your password to continue.
          </p>
          <TextField
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={fieldError(remove.error, "password")}
            required
            autoFocus
          />
          <InlineError error={remove.error} fields={["password"]} />
          <div className="flex justify-end gap-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant="danger" loading={remove.isPending} disabled={!password}>
              Remove key
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function RecoveryCodesDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [password, setPassword] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const generate = useApiMutation((pw: string) => api.post<RecoveryCodes>("/auth/mfa/recovery-codes", { password: pw }), {
    invalidate: ["/audit"],
    onSuccess: (res) => {
      setPassword("");
      setCodes(res.recoveryCodes);
    },
  });
  function close() {
    setPassword("");
    setCodes(null);
    generate.reset();
    onClose();
  }
  return (
    <Dialog open={open} onClose={close} title="New recovery codes" dismissible={codes === null}>
      {codes ? (
        <RecoveryCodesView codes={codes} onDone={close} doneLabel="Done" />
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            generate.mutate(password);
          }}
          className="flex flex-col gap-3.5"
        >
          <p className="text-sm">New codes replace all of your current recovery codes, used or not. Enter your password to continue.</p>
          <TextField
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={fieldError(generate.error, "password")}
            required
            autoFocus
          />
          <InlineError error={generate.error} fields={["password"]} />
          <div className="flex justify-end gap-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant="primary" loading={generate.isPending} disabled={!password}>
              Create new codes
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function SessionsCard() {
  const { signOut } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const sessions = useList<SessionItem>("/auth/sessions");
  const revoke = useApiMutation((id: string) => api.del(`/auth/sessions/${id}`), {
    invalidate: ["/auth/sessions", "/audit"],
    onSuccess: () => toast.success("That session was signed out."),
  });

  return (
    <Card title="Signed-in sessions" className="xl:col-span-2" padded={false}>
      {sessions.isPending ? (
        <Spinner />
      ) : sessions.isError ? (
        <ErrorState error={sessions.error} onRetry={() => void sessions.refetch()} compact />
      ) : (
        <>
          <TableWrap className="rounded-none border-0">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Address</th>
                  <th>Signed in</th>
                  <th>Last active</th>
                  <th>Expires</th>
                  <th className="text-right">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {sessions.items.map((s) => (
                  <tr key={s.id}>
                    <td title={s.userAgent}>
                      {describeUserAgent(s.userAgent)}
                      {s.current && (
                        <Badge tone="accent" className="ml-2">
                          This browser
                        </Badge>
                      )}
                    </td>
                    <td className="font-mono text-xs whitespace-nowrap">{s.sourceIp ?? "—"}</td>
                    <td className="whitespace-nowrap text-muted">{formatDateTime(s.createdAt)}</td>
                    <td className="whitespace-nowrap text-muted" title={formatDateTime(s.lastSeenAt)}>
                      {formatRelative(s.lastSeenAt)}
                    </td>
                    <td className="whitespace-nowrap text-muted">{formatDateTime(s.expiresAt)}</td>
                    <td className="text-right">
                      {s.current ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          icon={<LogOut className="size-3.5" aria-hidden />}
                          onClick={async () => {
                            await signOut();
                            navigate("/login", { replace: true });
                          }}
                        >
                          Sign out
                        </Button>
                      ) : (
                        <Button size="sm" variant="danger-ghost" loading={revoke.isPending && revoke.variables === s.id} onClick={() => revoke.mutate(s.id)}>
                          Sign out
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <InlineError error={revoke.error} />
          <p className="border-t border-line px-4 py-2.5 text-xs text-muted">
            Sessions end after a period without activity, and always at their expiry time. Changing your password signs out every other session.
          </p>
        </>
      )}
    </Card>
  );
}
