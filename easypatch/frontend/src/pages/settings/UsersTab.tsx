import { useEffect, useState, type FormEvent } from 'react';
import { KeyRound, LogOut, Pencil, Plus, ShieldOff, Unlink, Users } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useList, useOrganizations } from '../../api/hooks';
import { USER_ROLES, type CreateUserRequest, type CreateUserResponse, type ExternalLoginDto, type ResetLinkResponse, type UserDto, type UserRole } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { CodeBlock, OneTimeNotice } from '../../components/Copy';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Alert, Badge, Button, Checkbox, EmptyState, ErrorState, InlineError, SelectField, Spinner, TableWrap, TextField } from '../../components/ui';
import { formatDateTime, formatRelative, humanize } from '../../lib/format';
import { PASSWORD_HINT, passwordProblem } from '../auth/AuthPages';

const ROLE_HELP: Record<UserRole, string> = {
  SuperAdmin: 'Everything, including users, server settings, global policy and lifecycle data.',
  Admin: 'Operate: install updates, manage organizations, sites, policies, tokens and approvals.',
  ReadOnly: 'View dashboards, endpoints, jobs and reports. Cannot change anything.',
};

type Action = { kind: 'reset-link' | 'reset-mfa' | 'revoke-sessions'; user: UserDto };

export function UsersTab() {
  const { user: me } = useAuth();
  const toast = useToast();
  const list = useList<UserDto>('/users');
  const orgs = useOrganizations(true);
  const orgName = (id: string) => orgs.page.items.find((o) => o.id === id)?.name ?? id;
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<UserDto | null>(null);
  const [action, setAction] = useState<Action | null>(null);
  const [link, setLink] = useState<{ user: string; link: ResetLinkResponse } | null>(null);

  const run = useApiMutation(
    async (a: Action): Promise<ResetLinkResponse | null> => {
      if (a.kind === 'reset-link') return api.post<ResetLinkResponse>(`/users/${a.user.id}/reset-link`);
      await api.post<void>(a.kind === 'reset-mfa' ? `/users/${a.user.id}/mfa/reset` : `/users/${a.user.id}/sessions/revoke`);
      return null;
    },
    {
      invalidate: ['/users'],
      onSuccess: (result, a) => {
        setAction(null);
        if (a.kind === 'reset-link' && result) setLink({ user: a.user.username, link: result });
        else toast.success(a.kind === 'reset-mfa' ? `MFA reset for ${a.user.username}. They must enroll again at next sign-in.` : `All sessions of ${a.user.username} were signed out.`);
      },
    },
  );

  return (
    <>
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="text-sm text-muted">Administrator accounts. Users with no organization restriction can access every organization.</p>
        <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setCreating(true)}>
          New user
        </Button>
      </div>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title="No users" icon={<Users className="size-8" aria-hidden />} />
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>MFA</th>
                <th>Organizations</th>
                <th>Last sign-in</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {list.page.items.map((u) => (
                <tr key={u.id}>
                  <td>
                    <div className="flex items-center gap-2 font-medium">
                      {u.username}
                      {u.id === me?.id && <Badge tone="accent">you</Badge>}
                      {!u.isActive && <Badge tone="danger">disabled</Badge>}
                      {u.externalLoginCount > 0 && <Badge tone="info" title="Linked to a single sign-on provider">SSO</Badge>}
                      {u.lockoutUntil && new Date(u.lockoutUntil) > new Date() && <Badge tone="warn" title={`Until ${formatDateTime(u.lockoutUntil)}`}>locked out</Badge>}
                    </div>
                    <div className="text-xs text-muted">{u.email}</div>
                  </td>
                  <td>{humanize(u.role)}</td>
                  <td>
                    {u.mfaEnabled ? (
                      <Badge tone="ok" title={[u.totpEnabled && 'Authenticator app', u.securityKeyCount > 0 && `${u.securityKeyCount} passkey(s) / security key(s)`].filter(Boolean).join(' · ')}>
                        Enabled{u.securityKeyCount > 0 ? ` · ${u.securityKeyCount} key${u.securityKeyCount === 1 ? '' : 's'}` : ''}
                      </Badge>
                    ) : (
                      <Badge tone="warn">Not enrolled</Badge>
                    )}
                  </td>
                  <td className="max-w-64 text-sm">
                    {u.role === 'SuperAdmin' || u.organizationIds.length === 0 ? (
                      <span className="text-muted">All organizations</span>
                    ) : (
                      <span title={u.organizationIds.map(orgName).join(', ')}>{u.organizationIds.map(orgName).join(', ')}</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap text-muted" title={formatDateTime(u.lastLoginAt)}>
                    {formatRelative(u.lastLoginAt)}
                  </td>
                  <td>
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(u)}>
                        Edit
                      </Button>
                      <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" aria-hidden />} onClick={() => setAction({ kind: 'reset-link', user: u })} title="Create a password reset link">
                        Reset link
                      </Button>
                      {u.mfaEnabled && (
                        <Button size="sm" variant="ghost" icon={<ShieldOff className="size-3.5" aria-hidden />} onClick={() => setAction({ kind: 'reset-mfa', user: u })} disabled={u.id === me?.id}>
                          Reset MFA
                        </Button>
                      )}
                      <Button size="sm" variant="ghost" icon={<LogOut className="size-3.5" aria-hidden />} onClick={() => setAction({ kind: 'revoke-sessions', user: u })} disabled={u.id === me?.id} title="Sign out everywhere">
                        Sign out
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <CreateUserDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(r) => {
          setCreating(false);
          if (r.resetLink) setLink({ user: r.user.username, link: r.resetLink });
          else toast.success(`User ${r.user.username} created.`);
        }}
      />
      <EditUserDialog user={editing} isSelf={editing?.id === me?.id} onClose={() => setEditing(null)} />
      <ConfirmDialog
        open={action !== null}
        onClose={() => setAction(null)}
        onConfirm={() => action && run.mutate(action)}
        loading={run.isPending}
        error={run.error}
        tone={action?.kind === 'reset-link' ? 'primary' : 'danger'}
        title={
          action?.kind === 'reset-link'
            ? `Create a password reset link for ${action.user.username}?`
            : action?.kind === 'reset-mfa'
              ? `Reset MFA for ${action?.user.username}?`
              : `Sign ${action?.user.username} out everywhere?`
        }
        confirmLabel={action?.kind === 'reset-link' ? 'Create link' : action?.kind === 'reset-mfa' ? 'Reset MFA' : 'Sign out'}
      >
        {action?.kind === 'reset-link' && 'The link works once and expires in 60 minutes. Send it to the user over a trusted channel.'}
        {action?.kind === 'reset-mfa' &&
          'Their authenticator app, passkeys, security keys and recovery codes are removed and their sessions end. They must set up MFA again at next sign-in.'}
        {action?.kind === 'revoke-sessions' && 'All of their active sessions end immediately.'}
      </ConfirmDialog>
      <Dialog
        open={link !== null}
        onClose={() => setLink(null)}
        title={`Password link for ${link?.user ?? ''}`}
        footer={<Button variant="primary" onClick={() => setLink(null)}>Done</Button>}
      >
        {link && (
          <div className="flex flex-col gap-3 text-sm">
            <OneTimeNotice>
              This link lets the user choose a new password. It works once and expires {formatRelative(link.link.expiresAt)} ({formatDateTime(link.link.expiresAt)}).
            </OneTimeNotice>
            <CodeBlock code={link.link.url} />
          </div>
        )}
      </Dialog>
    </>
  );
}

export function OrgAccessPicker({ value, onChange, subject = 'user' }: { value: string[]; onChange: (ids: string[]) => void; subject?: string }) {
  const orgs = useOrganizations(true);
  return (
    <fieldset className="flex flex-col gap-1">
      <legend className="mb-1 text-xs font-medium text-muted">Organization access</legend>
      <p className="mb-1 text-xs text-muted">Leave all unchecked for access to every organization. Check organizations to restrict this {subject} to them.</p>
      <div className="max-h-48 overflow-y-auto rounded-md border border-line p-2">
        {orgs.page.items.length === 0 && <p className="text-sm text-muted">No organizations yet.</p>}
        {orgs.page.items.map((o) => (
          <Checkbox
            key={o.id}
            className="py-0.5"
            label={o.name}
            checked={value.includes(o.id)}
            onChange={(e) => onChange(e.target.checked ? [...value, o.id] : value.filter((v) => v !== o.id))}
          />
        ))}
      </div>
    </fieldset>
  );
}

function CreateUserDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (r: CreateUserResponse) => void }) {
  const [form, setForm] = useState<CreateUserRequest>({ username: '', email: '', role: 'Admin', password: null, organizationIds: [] });
  const [setPassword, setSetPassword] = useState(false);
  const [confirm, setConfirm] = useState('');
  useEffect(() => {
    if (open) {
      setForm({ username: '', email: '', role: 'Admin', password: null, organizationIds: [] });
      setSetPassword(false);
      setConfirm('');
    }
  }, [open]);
  const create = useApiMutation((req: CreateUserRequest) => api.post<CreateUserResponse>('/users', req), { invalidate: ['/users'], onSuccess: onCreated });
  const pwProblem = setPassword ? passwordProblem(form.password ?? '', confirm, form.username) : null;
  const invalid = !form.username.trim() || !form.email.trim() || !!pwProblem;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (invalid) return;
    create.mutate({
      ...form,
      username: form.username.trim(),
      email: form.email.trim(),
      password: setPassword ? form.password : null,
      organizationIds: form.role === 'SuperAdmin' ? [] : form.organizationIds,
    });
  }

  return (
    <Dialog open={open} onClose={onClose} title="New user">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <TextField label="Email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required maxLength={256} autoComplete="off" autoFocus
            hint="The user signs in with this address." />
          <TextField label="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required maxLength={64} autoComplete="off"
            hint="Shown in the console and the audit log." />
        </div>
        <SelectField label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as UserRole })} hint={ROLE_HELP[form.role]}>
          {USER_ROLES.map((r) => (
            <option key={r} value={r}>
              {humanize(r)}
            </option>
          ))}
        </SelectField>
        {form.role !== 'SuperAdmin' && <OrgAccessPicker value={form.organizationIds ?? []} onChange={(ids) => setForm({ ...form, organizationIds: ids })} />}
        <Checkbox
          label="Set an initial password now"
          hint="Otherwise a one-time link is generated so the user chooses their own password."
          checked={setPassword}
          onChange={(e) => setSetPassword(e.target.checked)}
        />
        {setPassword && (
          <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
            <TextField label="Password" type="password" autoComplete="new-password" value={form.password ?? ''} onChange={(e) => setForm({ ...form, password: e.target.value })} hint={PASSWORD_HINT} />
            <TextField label="Confirm password" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={setPassword && confirm && pwProblem ? pwProblem : null} />
          </div>
        )}
        <InlineError error={create.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={invalid}>
            Create user
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function EditUserDialog({ user, isSelf, onClose }: { user: UserDto | null; isSelf: boolean; onClose: () => void }) {
  const toast = useToast();
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<UserRole>('Admin');
  const [active, setActive] = useState(true);
  const [orgIds, setOrgIds] = useState<string[]>([]);
  useEffect(() => {
    if (user) {
      setEmail(user.email);
      setRole(user.role);
      setActive(user.isActive);
      setOrgIds(user.organizationIds);
    }
  }, [user]);

  const save = useApiMutation(
    async (u: UserDto) => {
      await api.put(`/users/${u.id}`, { email: email.trim() !== u.email ? email.trim() : null, role: role !== u.role ? role : null, isActive: active !== u.isActive ? active : null });
      const newIds = role === 'SuperAdmin' ? [] : orgIds;
      if (JSON.stringify([...newIds].sort()) !== JSON.stringify([...u.organizationIds].sort())) {
        await api.put(`/users/${u.id}/organizations`, { organizationIds: newIds });
      }
    },
    {
      invalidate: ['/users'],
      onSuccess: () => {
        toast.success('User updated.');
        onClose();
      },
    },
  );

  return (
    <Dialog open={user !== null} onClose={onClose} title={user ? `Edit ${user.username}` : ''}>
      {user && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate(user);
          }}
          className="flex flex-col gap-3.5"
        >
          <TextField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required maxLength={256}
            hint="The user signs in with this address. A change takes effect at their next sign-in." />
          <SelectField label="Role" value={role} onChange={(e) => setRole(e.target.value as UserRole)} hint={ROLE_HELP[role]} disabled={isSelf}>
            {USER_ROLES.map((r) => (
              <option key={r} value={r}>
                {humanize(r)}
              </option>
            ))}
          </SelectField>
          {isSelf && <p className="-mt-2 text-xs text-muted">You cannot change your own role or disable your own account.</p>}
          {role !== 'SuperAdmin' && <OrgAccessPicker value={orgIds} onChange={setOrgIds} />}
          <Checkbox label="Account enabled" hint="Disabled users cannot sign in; their sessions end." checked={active} onChange={(e) => setActive(e.target.checked)} disabled={isSelf} />
          {!active && user.isActive && <Alert tone="warn">Disabling the account signs the user out everywhere.</Alert>}
          {user.externalLoginCount > 0 && <LinkedSignIns userId={user.id} />}
          <InlineError error={save.error} />
          <div className="flex justify-end gap-2 pt-1">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" loading={save.isPending}>
              Save changes
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

/** The user's accounts at single sign-on providers. Removing a link stops that account from signing in as this user. */
function LinkedSignIns({ userId }: { userId: string }) {
  const toast = useToast();
  const links = useApi<ExternalLoginDto[]>(`/users/${userId}/external-logins`);
  const unlink = useApiMutation((l: ExternalLoginDto) => api.del<void>(`/users/${userId}/external-logins/${l.id}`), {
    invalidate: ['/users'],
    onSuccess: (_, l) => toast.success(`Unlinked from ${l.providerName}.`),
  });
  return (
    <fieldset className="flex flex-col gap-1">
      <legend className="mb-1 text-xs font-medium text-muted">Single sign-on</legend>
      {links.isPending && <Spinner />}
      <InlineError error={links.error ?? unlink.error} />
      {links.data?.map((l) => (
        <div key={l.id} className="flex items-center justify-between gap-2 rounded-md border border-line px-3 py-2 text-sm">
          <div className="min-w-0">
            <div className="font-medium">{l.providerName}</div>
            <div className="truncate text-xs text-muted" title={`${l.issuer} · subject ${l.subject}`}>
              {l.email ?? l.subject} · last used {formatRelative(l.lastUsedAt)}
            </div>
          </div>
          <Button size="sm" variant="danger-ghost" icon={<Unlink className="size-3.5" aria-hidden />} loading={unlink.isPending && unlink.variables?.id === l.id}
            onClick={() => unlink.mutate(l)}>
            Unlink
          </Button>
        </div>
      ))}
    </fieldset>
  );
}
