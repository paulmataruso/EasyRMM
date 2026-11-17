import { useEffect, useState, type FormEvent } from 'react';
import { LogIn, Pencil, Plus, Search, Trash } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation } from '../../api/hooks';
import type { SsoProbeDto, SsoProviderDto, SsoProviderRequest, SsoSettingsDto, UserRole } from '../../api/types';
import { CodeBlock } from '../../components/Copy';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Alert, Badge, Button, Card, Checkbox, EmptyState, ErrorState, InlineError, SelectField, Spinner, TableWrap, TextField } from '../../components/ui';
import { humanize } from '../../lib/format';

const EMPTY: SsoProviderRequest = {
  displayName: '',
  issuer: '',
  clientId: '',
  clientSecret: '',
  scopes: 'openid email profile',
  enabled: true,
  trustEmailClaim: false,
  providerEnforcesMfa: false,
  autoProvision: false,
  defaultRole: 'ReadOnly',
  allowedDomains: [],
};

/** Single sign-on providers (OpenID Connect). Super administrators only. */
export function SsoTab() {
  const toast = useToast();
  const settings = useApi<SsoSettingsDto>('/sso/providers');
  const [editing, setEditing] = useState<SsoProviderDto | 'new' | null>(null);
  const [deleting, setDeleting] = useState<SsoProviderDto | null>(null);
  const remove = useApiMutation((p: SsoProviderDto) => api.del<void>(`/sso/providers/${p.id}`), {
    invalidate: ['/sso/providers', '/users'],
    onSuccess: (_, p) => {
      setDeleting(null);
      toast.success(`${p.displayName} removed.`);
    },
  });

  if (settings.isPending) return <Spinner />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  const { redirectUri, providers } = settings.data;

  return (
    <div className="flex flex-col gap-4">
      <Card title="Redirect URI">
        <p className="mb-2 text-sm text-muted">
          Register this redirect URI (also called reply URL or callback URL) for the EasyPatch application at each identity provider. It is
          derived from the server's public address.
        </p>
        <CodeBlock code={redirectUri} />
      </Card>
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-muted">
          Users sign in with an OpenID Connect provider such as Microsoft Entra ID, Google or Keycloak. Password sign-in stays available.
        </p>
        <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setEditing('new')}>
          Add provider
        </Button>
      </div>
      {providers.length === 0 ? (
        <EmptyState title="No single sign-on providers" icon={<LogIn className="size-8" aria-hidden />} />
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Sign-in</th>
                <th>Options</th>
                <th>Linked users</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {providers.map((p) => (
                <tr key={p.id}>
                  <td>
                    <div className="font-medium">{p.displayName}</div>
                    <div className="max-w-96 truncate text-xs text-muted" title={p.issuer}>
                      {p.issuer}
                    </div>
                  </td>
                  <td>{p.enabled ? <Badge tone="ok">Enabled</Badge> : <Badge>Disabled</Badge>}</td>
                  <td>
                    <div className="flex flex-wrap gap-1">
                      {p.providerEnforcesMfa && <Badge tone="info">Provider MFA</Badge>}
                      {p.trustEmailClaim && <Badge tone="warn">Trusts email claim</Badge>}
                      {p.autoProvision && (
                        <Badge tone="info" title={p.allowedDomains.join(', ')}>
                          Creates {humanize(p.defaultRole)} accounts
                        </Badge>
                      )}
                    </div>
                  </td>
                  <td>{p.linkedUsers}</td>
                  <td>
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(p)}>
                        Edit
                      </Button>
                      <Button size="sm" variant="ghost" icon={<Trash className="size-3.5" aria-hidden />} onClick={() => setDeleting(p)}>
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
      <ProviderDialog provider={editing} onClose={() => setEditing(null)} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting)}
        loading={remove.isPending}
        error={remove.error}
        tone="danger"
        title={`Remove ${deleting?.displayName ?? ''}?`}
        confirmLabel="Remove"
      >
        Its sign-in button disappears and the links of {deleting?.linkedUsers ?? 0} user(s) to it are removed. Their EasyPatch accounts stay.
      </ConfirmDialog>
    </div>
  );
}

function ProviderDialog({ provider, onClose }: { provider: SsoProviderDto | 'new' | null; onClose: () => void }) {
  const toast = useToast();
  const existing = provider !== 'new' ? provider : null;
  const [form, setForm] = useState<SsoProviderRequest>(EMPTY);
  const [domains, setDomains] = useState('');
  const [changeSecret, setChangeSecret] = useState(true);
  const [probe, setProbe] = useState<SsoProbeDto | null>(null);

  useEffect(() => {
    if (provider === null) return;
    const p = provider === 'new' ? null : provider;
    setForm(
      p
        ? {
            displayName: p.displayName,
            issuer: p.issuer,
            clientId: p.clientId,
            clientSecret: null,
            scopes: p.scopes,
            enabled: p.enabled,
            trustEmailClaim: p.trustEmailClaim,
            providerEnforcesMfa: p.providerEnforcesMfa,
            autoProvision: p.autoProvision,
            defaultRole: p.defaultRole,
            allowedDomains: p.allowedDomains,
          }
        : EMPTY,
    );
    setDomains(p ? p.allowedDomains.join(', ') : '');
    setChangeSecret(!p);
    setProbe(null);
  }, [provider]);

  const save = useApiMutation(
    (req: SsoProviderRequest) => (existing ? api.put<SsoProviderDto>(`/sso/providers/${existing.id}`, req) : api.post<SsoProviderDto>('/sso/providers', req)),
    {
      invalidate: ['/sso/providers'],
      onSuccess: (p) => {
        toast.success(existing ? `${p.displayName} saved.` : `${p.displayName} added. Its button appears on the sign-in page while it is enabled.`);
        onClose();
      },
    },
  );
  const check = useApiMutation((issuer: string) => api.post<SsoProbeDto>('/sso/providers/probe', { issuer }), { onSuccess: setProbe });

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({
      ...form,
      // null keeps the stored secret; only send one when the administrator chose to change it.
      clientSecret: changeSecret ? (form.clientSecret ?? '') : null,
      allowedDomains: domains.split(/[\s,;]+/).filter(Boolean),
    });
  }

  return (
    <Dialog open={provider !== null} onClose={onClose} title={existing ? `Edit ${existing.displayName}` : 'Add a single sign-on provider'} size="lg">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-x-6 gap-y-3 md:grid-cols-2">
          <TextField label="Name on the sign-in button" placeholder="Microsoft" required maxLength={64} value={form.displayName}
            onChange={(e) => setForm({ ...form, displayName: e.target.value })} hint={`Shown as "Sign in with ${form.displayName || '…'}".`} />
          <TextField label="Client ID" required maxLength={256} autoComplete="off" value={form.clientId} onChange={(e) => setForm({ ...form, clientId: e.target.value })} />
        </div>
        <div className="flex flex-col gap-1">
          <div className="flex items-end gap-2">
            <TextField className="flex-1" label="Issuer" type="url" required maxLength={512} placeholder="https://login.microsoftonline.com/<tenant-id>/v2.0"
              value={form.issuer} onChange={(e) => { setForm({ ...form, issuer: e.target.value }); setProbe(null); }} />
            <Button icon={<Search className="size-4" aria-hidden />} loading={check.isPending} disabled={!form.issuer.trim()} onClick={() => check.mutate(form.issuer.trim())}>
              Check
            </Button>
          </div>
          <p className="text-xs text-muted">EasyPatch reads &lt;issuer&gt;/.well-known/openid-configuration. It must name exactly this issuer.</p>
          <InlineError error={check.error} />
          {probe && <Alert tone={probe.ok ? 'ok' : 'danger'}>{probe.message}</Alert>}
        </div>
        <div className="flex flex-col gap-1">
          {changeSecret ? (
            <TextField label="Client secret" type="password" autoComplete="new-password" maxLength={1024} value={form.clientSecret ?? ''}
              onChange={(e) => setForm({ ...form, clientSecret: e.target.value })}
              hint={existing?.clientSecretConfigured ? 'Leave empty to remove the stored secret (a public client).' : 'Leave empty for a public client (PKCE only).'} />
          ) : (
            <>
              <span className="text-sm font-medium">Client secret</span>
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted">{existing?.clientSecretConfigured ? 'Stored (encrypted)' : 'Not set (public client)'}</span>
                <Button size="sm" onClick={() => setChangeSecret(true)}>
                  {existing?.clientSecretConfigured ? 'Change' : 'Set secret'}
                </Button>
              </div>
            </>
          )}
        </div>
        <TextField label="Scopes" maxLength={512} value={form.scopes ?? ''} onChange={(e) => setForm({ ...form, scopes: e.target.value })}
          hint="Separated by spaces; must include openid. EasyPatch reads the email address from the ID token." />
        <Checkbox label="Enabled" hint="Shows the sign-in button." checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
        <Checkbox
          label="The provider enforces MFA"
          hint="Users who sign in through it skip EasyPatch's second factor. Tick this only if the provider requires MFA for every user of this application."
          checked={form.providerEnforcesMfa}
          onChange={(e) => setForm({ ...form, providerEnforcesMfa: e.target.checked })}
        />
        <Checkbox
          label="Trust the provider's email claim"
          hint="Link an account by its email address even when the ID token does not say email_verified (Microsoft Entra ID does not send it). Only for a provider whose users cannot choose their own address, such as a single-tenant Entra ID application."
          checked={form.trustEmailClaim}
          onChange={(e) => setForm({ ...form, trustEmailClaim: e.target.checked })}
        />
        <Checkbox
          label="Create accounts on first sign-in"
          hint="For addresses in the allowed domains that have no EasyPatch account yet. Otherwise only existing users can sign in."
          checked={form.autoProvision}
          onChange={(e) => setForm({ ...form, autoProvision: e.target.checked })}
        />
        {form.autoProvision && (
          <div className="grid grid-cols-1 gap-x-6 gap-y-3 md:grid-cols-2">
            <SelectField label="Role of new accounts" value={form.defaultRole} onChange={(e) => setForm({ ...form, defaultRole: e.target.value as UserRole })}
              hint="Never super administrator. New accounts can access every organization until you restrict them under Users.">
              <option value="ReadOnly">Read only</option>
              <option value="Admin">Admin</option>
            </SelectField>
            <TextField label="Allowed email domains" required placeholder="example.com, example.org" value={domains} onChange={(e) => setDomains(e.target.value)} />
          </div>
        )}
        <InlineError error={save.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            {existing ? 'Save changes' : 'Add provider'}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
