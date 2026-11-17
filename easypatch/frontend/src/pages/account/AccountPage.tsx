import { useEffect, useState, type FormEvent } from 'react';
import { KeyRound, LogOut, MonitorSmartphone, ShieldCheck, ShieldOff } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useOrganizations } from '../../api/hooks';
import type { RecoveryCodesResponse, ServerSettings, SessionDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { Dialog } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Alert, Badge, Button, Card, ErrorState, InlineError, KeyValueList, PageHeader, Spinner, TableWrap, TextField } from '../../components/ui';
import { describeUserAgent, formatDateTime, formatRelative, humanize } from '../../lib/format';
import { MfaEnrollment, PasswordChangeForm, RecoveryCodesView } from '../auth/AuthPages';
import { SecurityKeysCard } from '../auth/SecurityKeys';

export function AccountPage() {
  const { user, refresh } = useAuth();
  const toast = useToast();
  const orgs = useOrganizations();
  if (!user) return <Spinner />;
  const orgNames = user.organizationIds.map((id) => orgs.page.items.find((o) => o.id === id)?.name ?? id);

  return (
    <>
      <PageHeader title="My account" subtitle="Your profile, password, two-factor authentication and active sessions." />
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <Card title="Profile">
          <KeyValueList
            items={[
              ['Email (sign-in)', user.email],
              ['Username', user.username],
              ['Role', humanize(user.role)],
              ['Organization access', user.role === 'SuperAdmin' || orgNames.length === 0 ? 'All organizations' : orgNames.join(', ')],
              ['Last sign-in', user.lastLoginAt ? `${formatDateTime(user.lastLoginAt)} (${formatRelative(user.lastLoginAt)})` : '—'],
            ]}
          />
          <p className="mt-4 text-xs text-muted">A super administrator can change your role or organization access.</p>
        </Card>
        <Card title="Change email">
          <div className="max-w-md">
            <EmailChangeForm
              currentEmail={user.email}
              hasPassword={user.hasPassword}
              onDone={(email) => {
                toast.success(`Your email is now ${email}.`);
                void refresh();
              }}
            />
          </div>
        </Card>
        <MfaCard />
        <SecurityKeysCard />
        {user.hasPassword ? (
          <Card title="Change password">
            <p className="mb-3 text-sm text-muted">Changing your password signs out your other sessions.</p>
            <div className="max-w-md">
              <PasswordChangeForm
                user={user}
                onDone={() => {
                  toast.success('Password changed. Your other sessions were signed out.');
                  void refresh();
                }}
              />
            </div>
          </Card>
        ) : (
          <Card title="Password">
            <p className="text-sm text-muted">
              You sign in with single sign-on and have no EasyPatch password. A super administrator can send you a link to set one. To change
              passkeys or two-factor settings, sign in again first if your sign-in is more than 10 minutes old.
            </p>
          </Card>
        )}
        <SessionsCard />
      </div>
    </>
  );
}

function EmailChangeForm({ currentEmail, hasPassword, onDone }: { currentEmail: string; hasPassword: boolean; onDone: (email: string) => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const trimmed = email.trim();
  const same = trimmed.toLowerCase() === currentEmail.toLowerCase();

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/auth/email/change', { currentPassword: password, newEmail: trimmed });
      setEmail('');
      setPassword('');
      onDone(trimmed.toLowerCase());
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3.5">
      <TextField
        label="New email"
        type="email"
        autoComplete="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        error={trimmed && same ? 'That is already your email.' : null}
        hint={`Currently ${currentEmail}. You sign in with this address.`}
        maxLength={256}
        required
      />
      {hasPassword ? (
        <TextField label="Current password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      ) : (
        <p className="text-xs text-muted">Your account has no password: a sign-in within the last 10 minutes confirms the change.</p>
      )}
      <InlineError error={error} />
      <Button type="submit" variant="primary" loading={busy} disabled={!trimmed || same || (hasPassword && !password)} className="self-start">
        Change email
      </Button>
    </form>
  );
}

function MfaCard() {
  const { user, refresh } = useAuth();
  const toast = useToast();
  const settings = useApi<ServerSettings>('/settings', undefined, { staleTime: 60_000 });
  const [enrolling, setEnrolling] = useState(false);
  const [enrollLocked, setEnrollLocked] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const [disabling, setDisabling] = useState(false);
  if (!user) return null;
  const required = settings.data?.requireMfa ?? true;
  const keys = user.securityKeyCount;
  // The authenticator app can go when the server does not require MFA, or a security key or passkey remains.
  const canRemoveApp = user.totpEnabled && (!required || keys > 0);

  return (
    <Card title="Two-factor authentication">
      <div className="flex items-start gap-3">
        {user.mfaEnabled ? <ShieldCheck className="mt-0.5 size-6 shrink-0 text-ok" aria-hidden /> : <ShieldOff className="mt-0.5 size-6 shrink-0 text-warn" aria-hidden />}
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">
            {user.mfaEnabled ? 'Enabled' : 'Not enabled'} {required && <Badge tone="info">Required by server policy</Badge>}
          </p>
          <p className="mt-0.5 text-sm text-muted">
            {user.mfaEnabled
              ? 'Signing in requires your password and a second factor (or a recovery code), or a passkey alone.'
              : 'Protect your account with an authenticator app, a security key or a passkey. Anyone with your password can otherwise install updates on managed endpoints.'}
          </p>
          <ul className="mt-2 space-y-0.5 text-sm">
            <li>Authenticator app: {user.totpEnabled ? 'on' : 'off'}</li>
            <li>
              Passkeys and security keys: {keys === 0 ? 'none' : keys}
              {user.passkeyCount > 0 && keys > 0 && ` (${user.passkeyCount} passkey${user.passkeyCount === 1 ? '' : 's'})`}
            </li>
          </ul>
        </div>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        {!user.totpEnabled && (
          <Button variant={user.mfaEnabled ? 'secondary' : 'primary'} icon={<ShieldCheck className="size-4" aria-hidden />} onClick={() => setEnrolling(true)}>
            Set up authenticator app
          </Button>
        )}
        {user.mfaEnabled && (
          <Button icon={<KeyRound className="size-4" aria-hidden />} onClick={() => setRegenerating(true)}>
            New recovery codes
          </Button>
        )}
        {canRemoveApp && (
          <Button variant="danger-ghost" icon={<ShieldOff className="size-4" aria-hidden />} onClick={() => setDisabling(true)}>
            Remove authenticator app
          </Button>
        )}
      </div>
      {user.totpEnabled && !canRemoveApp && (
        <p className="mt-3 text-xs text-muted">The server requires two-factor authentication: add a passkey or security key before removing the authenticator app.</p>
      )}

      <Dialog
        open={enrolling}
        onClose={() => setEnrolling(false)}
        dismissible={!enrollLocked}
        title="Set up an authenticator app"
        size="sm"
      >
        {enrolling && (
          <MfaEnrollment
            onEnabled={() => setEnrollLocked(true)}
            onDone={() => {
              setEnrolling(false);
              setEnrollLocked(false);
              toast.success('Authenticator app is set up.');
              void refresh();
            }}
          />
        )}
      </Dialog>
      <RegenerateCodesDialog open={regenerating} hasPassword={user.hasPassword} onClose={() => setRegenerating(false)} />
      <DisableMfaDialog
        open={disabling}
        keysRemain={keys > 0}
        hasPassword={user.hasPassword}
        onClose={() => setDisabling(false)}
        onDisabled={() => {
          setDisabling(false);
          toast.success(keys > 0 ? 'Authenticator app removed.' : 'Two-factor authentication is off.');
          void refresh();
        }}
      />
    </Card>
  );
}

/** Accounts without a password (single sign-on) confirm with a recent sign-in instead (the server checks it). */
function RegenerateCodesDialog({ open, hasPassword, onClose }: { open: boolean; hasPassword: boolean; onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const regenerate = useApiMutation((pw: string) => api.post<RecoveryCodesResponse>('/auth/mfa/recovery-codes', { password: pw }), {
    onSuccess: (r) => {
      setPassword('');
      setCodes(r.recoveryCodes);
    },
  });
  const resetMutation = regenerate.reset;
  useEffect(() => {
    if (open) {
      setPassword('');
      setCodes(null);
      resetMutation();
    }
  }, [open, resetMutation]);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (password || !hasPassword) regenerate.mutate(password);
  }

  return (
    <Dialog open={open} onClose={onClose} dismissible={codes === null} title={codes ? 'Your new recovery codes' : 'Generate new recovery codes'} size="sm">
      {codes ? (
        <RecoveryCodesView codes={codes} onDone={onClose} />
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-3.5">
          <Alert tone="warn">Your current recovery codes stop working as soon as new ones are generated.</Alert>
          {hasPassword && (
            <TextField label="Your password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus />
          )}
          <InlineError error={regenerate.error} />
          <div className="flex justify-end gap-2">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" loading={regenerate.isPending} disabled={hasPassword && !password}>
              Generate codes
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function DisableMfaDialog({ open, keysRemain, hasPassword, onClose, onDisabled }: {
  open: boolean;
  keysRemain: boolean;
  hasPassword: boolean;
  onClose: () => void;
  onDisabled: () => void;
}) {
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    if (open) {
      setPassword('');
      setCode('');
      setError(null);
    }
  }, [open]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/auth/mfa/disable', { password, code: code.trim() });
      onDisabled();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} title={keysRemain ? 'Remove the authenticator app?' : 'Turn off two-factor authentication?'} size="sm">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <Alert tone="warn">
          {keysRemain
            ? 'You will sign in with your passkey or security key. Your recovery codes keep working.'
            : 'Your account will be protected by your password alone. Your recovery codes stop working.'}
        </Alert>
        {hasPassword && (
          <TextField label="Your password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus />
        )}
        <TextField label="Authenticator code" autoComplete="one-time-code" inputMode="numeric" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} required />
        <InlineError error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" loading={busy} disabled={(hasPassword && !password) || code.trim().length < 6}>
            Turn off
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function SessionsCard() {
  const toast = useToast();
  const sessions = useApi<SessionDto[]>('/auth/sessions', undefined, { refetchInterval: 60_000 });
  const revoke = useApiMutation((id: string) => api.del(`/auth/sessions/${id}`), {
    invalidate: ['/auth/sessions'],
    onSuccess: () => toast.success('Session signed out.'),
  });
  const revokeOthers = useApiMutation(
    async (ids: string[]) => {
      for (const id of ids) await api.del(`/auth/sessions/${id}`);
    },
    { invalidate: ['/auth/sessions'], onSuccess: (_, ids) => toast.success(`${ids.length} other session${ids.length === 1 ? '' : 's'} signed out.`) },
  );
  const others = (sessions.data ?? []).filter((s) => !s.current);

  return (
    <Card
      title="Active sessions"
      padded={false}
      actions={
        others.length > 0 && (
          <Button size="sm" variant="danger-ghost" icon={<LogOut className="size-3.5" aria-hidden />} loading={revokeOthers.isPending} onClick={() => revokeOthers.mutate(others.map((s) => s.id))}>
            Sign out other sessions
          </Button>
        )
      }
    >
      <div className="p-4">
        {sessions.isPending ? (
          <Spinner />
        ) : sessions.isError ? (
          <ErrorState error={sessions.error} compact onRetry={() => void sessions.refetch()} />
        ) : (
          <>
            <InlineError error={revoke.error ?? revokeOthers.error} />
            <TableWrap>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>IP address</th>
                    <th>Last active</th>
                    <th>Expires</th>
                    <th className="text-right">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {(sessions.data ?? []).map((s) => (
                    <tr key={s.id}>
                      <td>
                        <div className="flex items-center gap-2">
                          <MonitorSmartphone className="size-4 shrink-0 text-subtle" aria-hidden />
                          <span title={s.userAgent ?? undefined}>{describeUserAgent(s.userAgent)}</span>
                          {s.current && <Badge tone="accent">This session</Badge>}
                        </div>
                        <div className="text-xs text-muted">signed in {formatDateTime(s.createdAt)}</div>
                      </td>
                      <td className="font-mono text-xs whitespace-nowrap">{s.ipAddress ?? '—'}</td>
                      <td className="whitespace-nowrap text-muted" title={formatDateTime(s.lastSeenAt)}>
                        {formatRelative(s.lastSeenAt)}
                      </td>
                      <td className="whitespace-nowrap text-muted" title={formatDateTime(s.expiresAt)}>
                        {formatRelative(s.expiresAt)}
                      </td>
                      <td className="text-right">
                        {!s.current && (
                          <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables === s.id} onClick={() => revoke.mutate(s.id)}>
                            Sign out
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </>
        )}
      </div>
    </Card>
  );
}
