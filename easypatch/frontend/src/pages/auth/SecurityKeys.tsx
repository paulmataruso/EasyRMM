import { useEffect, useState, type FormEvent } from 'react';
import { FingerprintPattern, KeyRound, Pencil, Trash, Usb } from 'lucide-react';
import { ApiError, api } from '../../api/client';
import { useApi } from '../../api/hooks';
import type { WebAuthnCredentialDto, WebAuthnRegisterResponse, WebAuthnStatusDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { Dialog } from '../../components/Dialog';
import { RecoveryCodesView } from '../../components/RecoveryCodes';
import { useToast } from '../../components/Toast';
import { Alert, Badge, Button, Card, ErrorState, InlineError, Spinner, TableWrap, TextField } from '../../components/ui';
import { formatDateTime, formatRelative } from '../../lib/format';
import { createCredential, webAuthnSupported, type WebAuthnJson } from '../../lib/webauthn';

/** Whether this server can offer passkeys and security keys (it needs HTTPS and a DNS name). */
export function useWebAuthnStatus() {
  return useApi<WebAuthnStatusDto>('/auth/webauthn', undefined, { staleTime: 5 * 60_000 });
}

/** Passkeys work here: the server allows them and the browser supports WebAuthn. */
export function useWebAuthnReady(): boolean {
  const status = useWebAuthnStatus();
  return status.data?.available === true && webAuthnSupported();
}

/** Explains why passkeys and security keys cannot be used, or nothing when they can. */
export function WebAuthnUnavailableNotice({ status }: { status: WebAuthnStatusDto | undefined }) {
  if (!status) return null;
  if (!status.available) {
    return (
      <Alert tone="info" title="Passkeys and security keys are not available on this server">
        {status.message ?? 'The console must be reached over HTTPS by a DNS name.'} Browsers allow passkeys only for a DNS name with a certificate
        they trust; an IP address does not work.
      </Alert>
    );
  }
  if (!webAuthnSupported()) {
    return <Alert tone="info">This browser does not support passkeys or security keys. Use a current version of Edge, Chrome, Firefox or Safari.</Alert>;
  }
  return null;
}

/**
 * Registers a passkey (signs in without a password, with fingerprint, face or device PIN) or a security key used as the second
 * factor. The server may ask for the current password when the sign-in is more than 10 minutes old; the field appears then.
 */
export function SecurityKeyEnrollment({ passkey, onDone, onCancel }: { passkey: boolean; onDone: () => void; onCancel?: () => void }) {
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [needPassword, setNeedPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [codes, setCodes] = useState<string[] | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const options = await api.post<WebAuthnJson>('/auth/webauthn/register/options', { passkey, password: password || null });
      const credential = await createCredential(options);
      const result = await api.post<WebAuthnRegisterResponse>('/auth/webauthn/register', { name: name.trim() || null, credential });
      setPassword('');
      if (result.recoveryCodes && result.recoveryCodes.length > 0) setCodes(result.recoveryCodes);
      else onDone();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'invalid_password') setNeedPassword(true);
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (codes) return <RecoveryCodesView codes={codes} onDone={onDone} />;

  return (
    <form onSubmit={submit} className="flex flex-col gap-3.5">
      <p className="text-sm text-muted">
        {passkey
          ? 'A passkey signs you in without your password: you confirm with your fingerprint, face or device PIN. It lives on this device, in your password manager or on a security key.'
          : 'A hardware security key (YubiKey, Google Titan, Feitian…) as the second step after your password: insert or tap it when asked.'}
      </p>
      <TextField
        label="Name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        maxLength={64}
        placeholder={passkey ? 'e.g. Work laptop' : 'e.g. YubiKey 5C'}
        hint="Helps you tell your keys apart. Optional."
      />
      {needPassword && (
        <TextField
          label="Current password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint="You signed in more than 10 minutes ago: confirm it is you."
          required
          autoFocus
        />
      )}
      <InlineError error={error} />
      <div className="flex justify-end gap-2">
        {onCancel && <Button onClick={onCancel}>Cancel</Button>}
        <Button type="submit" variant="primary" loading={busy} disabled={needPassword && !password}
          icon={passkey ? <FingerprintPattern className="size-4" aria-hidden /> : <Usb className="size-4" aria-hidden />}>
          {passkey ? 'Create passkey' : 'Register security key'}
        </Button>
      </div>
    </form>
  );
}

/** My account: the user's passkeys and security keys. */
export function SecurityKeysCard() {
  const { user, refresh } = useAuth();
  const toast = useToast();
  const status = useWebAuthnStatus();
  const keys = useApi<WebAuthnCredentialDto[]>('/auth/webauthn/credentials');
  const [adding, setAdding] = useState<'passkey' | 'key' | null>(null);
  const [renaming, setRenaming] = useState<WebAuthnCredentialDto | null>(null);
  const [removing, setRemoving] = useState<WebAuthnCredentialDto | null>(null);
  const ready = status.data?.available === true && webAuthnSupported();

  async function changed(message: string) {
    toast.success(message);
    await keys.refetch();
    await refresh();
  }

  return (
    <Card title="Passkeys and security keys" padded={false}>
      <div className="flex flex-col gap-3 p-4">
        <p className="text-sm text-muted">
          A passkey signs you in without a password. A security key can replace the authenticator app as your second step. Either one counts as
          two-factor authentication.
        </p>
        <WebAuthnUnavailableNotice status={status.data} />
        {keys.isPending ? (
          <Spinner />
        ) : keys.isError ? (
          <ErrorState error={keys.error} compact onRetry={() => void keys.refetch()} />
        ) : (keys.data ?? []).length === 0 ? (
          <p className="text-sm text-muted">You have no passkeys or security keys yet.</p>
        ) : (
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Added</th>
                  <th>Last used</th>
                  <th className="text-right">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {(keys.data ?? []).map((k) => (
                  <tr key={k.id}>
                    <td>
                      <div className="flex flex-wrap items-center gap-2">
                        {k.isPasskey ? <FingerprintPattern className="size-4 text-subtle" aria-hidden /> : <KeyRound className="size-4 text-subtle" aria-hidden />}
                        <span className="font-medium">{k.name}</span>
                        <Badge tone={k.isPasskey ? 'accent' : 'neutral'}>{k.isPasskey ? 'Passkey' : 'Security key'}</Badge>
                        {k.isSynced && <Badge tone="info" title="Synced to your other devices by your password manager or platform">Synced</Badge>}
                      </div>
                    </td>
                    <td className="whitespace-nowrap text-muted" title={formatDateTime(k.createdAt)}>
                      {formatRelative(k.createdAt)}
                    </td>
                    <td className="whitespace-nowrap text-muted" title={formatDateTime(k.lastUsedAt)}>
                      {k.lastUsedAt ? formatRelative(k.lastUsedAt) : 'Never'}
                    </td>
                    <td>
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setRenaming(k)}>
                          Rename
                        </Button>
                        <Button size="sm" variant="danger-ghost" icon={<Trash className="size-3.5" aria-hidden />} onClick={() => setRemoving(k)}>
                          Remove
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" icon={<FingerprintPattern className="size-4" aria-hidden />} disabled={!ready} onClick={() => setAdding('passkey')}>
            Add a passkey
          </Button>
          <Button icon={<Usb className="size-4" aria-hidden />} disabled={!ready} onClick={() => setAdding('key')}>
            Add a security key
          </Button>
        </div>
      </div>

      <Dialog open={adding !== null} onClose={() => setAdding(null)} title={adding === 'passkey' ? 'Add a passkey' : 'Add a security key'} size="sm">
        {adding && (
          <SecurityKeyEnrollment
            passkey={adding === 'passkey'}
            onCancel={() => setAdding(null)}
            onDone={() => {
              const kind = adding;
              setAdding(null);
              void changed(kind === 'passkey' ? 'Passkey added.' : 'Security key added.');
            }}
          />
        )}
      </Dialog>
      <RenameKeyDialog credential={renaming} onClose={() => setRenaming(null)} onRenamed={() => { setRenaming(null); void changed('Renamed.'); }} />
      <RemoveKeyDialog
        credential={removing}
        lastFactor={user ? !user.totpEnabled && user.securityKeyCount <= 1 : false}
        onClose={() => setRemoving(null)}
        onRemoved={() => {
          setRemoving(null);
          void changed('Removed.');
        }}
      />
    </Card>
  );
}

function RenameKeyDialog({ credential, onClose, onRenamed }: { credential: WebAuthnCredentialDto | null; onClose: () => void; onRenamed: () => void }) {
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    if (credential) {
      setName(credential.name);
      setError(null);
    }
  }, [credential]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!credential) return;
    setBusy(true);
    setError(null);
    try {
      await api.put(`/auth/webauthn/credentials/${credential.id}`, { name: name.trim() });
      onRenamed();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={credential !== null} onClose={onClose} title="Rename" size="sm">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required autoFocus />
        <InlineError error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={busy} disabled={!name.trim()}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function RemoveKeyDialog({ credential, lastFactor, onClose, onRemoved }: {
  credential: WebAuthnCredentialDto | null;
  lastFactor: boolean;
  onClose: () => void;
  onRemoved: () => void;
}) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    if (credential) {
      setPassword('');
      setError(null);
    }
  }, [credential]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!credential) return;
    setBusy(true);
    setError(null);
    try {
      await api.post(`/auth/webauthn/credentials/${credential.id}/remove`, { password: password || null });
      onRemoved();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={credential !== null} onClose={onClose} title={`Remove ${credential?.name ?? ''}?`} size="sm">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <Alert tone="warn">
          {lastFactor
            ? 'This is your only second factor. If the server requires two-factor authentication, add another one first.'
            : 'It will no longer sign you in. Remove it from the device or password manager too.'}
        </Alert>
        <TextField
          label="Your password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint="Not needed if you signed in within the last 10 minutes."
          autoFocus
        />
        <InlineError error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" loading={busy}>
            Remove
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/**
 * After sign-in: offers a passkey to users who have none, when passkeys work here. "Not now" is stored on the server and the offer
 * returns after 30 days.
 */
export function PasskeyPrompt() {
  const { user, refresh } = useAuth();
  const toast = useToast();
  const [closed, setClosed] = useState(false);
  const [creating, setCreating] = useState(false);
  const open = !!user?.passkeyPrompt && !closed && webAuthnSupported();

  async function notNow() {
    setClosed(true);
    try {
      await api.post('/auth/passkey-prompt/dismiss');
    } catch {
      // Asked again at the next sign-in.
    }
    void refresh();
  }

  return (
    <Dialog open={open} onClose={() => void notNow()} dismissible={!creating} title="Sign in faster with a passkey" size="sm">
      {creating ? (
        <SecurityKeyEnrollment
          passkey
          onCancel={() => setCreating(false)}
          onDone={() => {
            setClosed(true);
            toast.success('Passkey created. Next time, choose “Sign in with a passkey”.');
            void refresh();
          }}
        />
      ) : (
        <div className="flex flex-col gap-3.5">
          <p className="text-sm">
            Use your fingerprint, face or device PIN instead of your password and authenticator code. Passkeys cannot be phished or reused on
            another site.
          </p>
          <div className="flex justify-end gap-2">
            <Button onClick={() => void notNow()}>Not now</Button>
            <Button variant="primary" icon={<FingerprintPattern className="size-4" aria-hidden />} onClick={() => setCreating(true)}>
              Set up a passkey
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
