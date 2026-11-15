import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { KeyRound, Lock, LockOpen, Pencil, Trash2, UserCheck, UserX } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { InviteResult, User } from "../../api/types";
import { CodeBlock, OneTimeNotice } from "../../components/Copy";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { describeAssignment, UserStatusBadge } from "../../components/StatusBadges";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, ErrorState, InlineError, KeyValueList, PageHeader, Spinner, TextField } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { AssignmentEditor, draftComplete, fromDraft, toDraft, type DraftAssignment } from "./AssignmentEditor";

type Confirm = "disable" | "enable" | "unlock" | "reset-mfa" | "delete" | null;

export function UserDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const user = useApi<User>(`/users/${id}`);
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [editingName, setEditingName] = useState(false);
  const [link, setLink] = useState<{ url: string; invite: boolean } | null>(null);

  const action = useApiMutation(
    (kind: Exclude<Confirm, null>) =>
      kind === "delete" ? api.del(`/users/${id}`).then(() => null) : api.post<User>(`/users/${id}/${kind}`),
    {
      invalidate: ["/users", "/audit"],
      onSuccess: (_, kind) => {
        const name = user.data?.displayName ?? "The user";
        const messages: Record<Exclude<Confirm, null>, string> = {
          disable: `${name} is disabled and has been signed out.`,
          enable: `${name} can sign in again.`,
          unlock: `${name} is unlocked.`,
          "reset-mfa": `${name} will set up a new authenticator at next sign-in.`,
          delete: `${name} was deleted.`,
        };
        toast.success(messages[kind]);
        setConfirm(null);
        if (kind === "delete") navigate("/settings?tab=users", { replace: true });
      },
    },
  );

  const passwordLink = useApiMutation(() => api.post<InviteResult>(`/users/${id}/password-link`), {
    invalidate: ["/audit"],
    onSuccess: (res) => {
      const invite = !(user.data?.passwordSet ?? true);
      if (res.emailed) toast.success(`${invite ? "Invitation" : "Password reset link"} emailed to ${user.data?.email}.`);
      else if (res.link) setLink({ url: res.link, invite });
    },
  });

  if (user.isPending) return <Spinner />;
  if (user.isError) return <ErrorState error={user.error} onRetry={() => void user.refetch()} />;
  const u = user.data;
  const manage = u.canManage && !u.isSelf;

  return (
    <>
      <PageHeader
        breadcrumb={
          <>
            <Link to="/settings" className="hover:text-fg">
              Settings
            </Link>
            <span className="mx-1.5" aria-hidden>
              /
            </span>
            <Link to="/settings?tab=users" className="hover:text-fg">
              Users
            </Link>
          </>
        }
        title={
          <span className="inline-flex items-center gap-2">
            {u.displayName} <UserStatusBadge user={u} />
          </span>
        }
        subtitle={u.email}
        actions={
          manage && (
            <>
              {u.status === "active" && (
                <Button icon={<KeyRound className="size-4" aria-hidden />} loading={passwordLink.isPending} onClick={() => passwordLink.mutate(undefined)}>
                  {u.passwordSet ? "Send password reset" : "Resend invitation"}
                </Button>
              )}
              {u.locked && (
                <Button icon={<LockOpen className="size-4" aria-hidden />} onClick={() => setConfirm("unlock")}>
                  Unlock
                </Button>
              )}
              {u.status === "active" ? (
                <Button icon={<UserX className="size-4" aria-hidden />} onClick={() => setConfirm("disable")}>
                  Disable
                </Button>
              ) : (
                <Button icon={<UserCheck className="size-4" aria-hidden />} onClick={() => setConfirm("enable")}>
                  Enable
                </Button>
              )}
              <Button variant="danger-ghost" icon={<Trash2 className="size-4" aria-hidden />} onClick={() => setConfirm("delete")}>
                Delete
              </Button>
            </>
          )
        }
      />

      {u.isSelf && (
        <Alert tone="info" className="mb-5">
          This is your account. Change your name, password and second factor on the{" "}
          <Link to="/account" className="text-accent hover:underline">
            Account page
          </Link>
          . Another administrator manages your roles.
        </Alert>
      )}
      <InlineError error={passwordLink.error} />

      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        <Card title="Roles" className="xl:col-span-2">
          {manage ? (
            <RolesForm user={u} />
          ) : (
            <>
              <ul className="space-y-1 text-sm">
                {u.assignments.map((a, i) => (
                  <li key={i}>{describeAssignment(a)}</li>
                ))}
              </ul>
              {u.hiddenAssignments > 0 && <p className="mt-2 text-xs text-muted">Also holds {u.hiddenAssignments} role(s) in organizations you cannot see.</p>}
              {!u.isSelf && !u.canManage && <p className="mt-3 text-xs text-muted">Your role does not let you change this user's access.</p>}
            </>
          )}
        </Card>

        <Card
          title="Account"
          actions={
            manage && (
              <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditingName(true)}>
                Rename
              </Button>
            )
          }
        >
          <KeyValueList
            narrow
            items={[
              ["Email", u.email],
              ["Name", u.displayName],
              ["Password", u.passwordSet ? "Set" : "Invitation not accepted yet"],
              [
                "Second factor",
                u.mfaEnabled ? (
                  <span className="inline-flex items-center gap-2">
                    Authenticator app
                    {manage && (
                      <button type="button" className="text-xs text-accent hover:underline" onClick={() => setConfirm("reset-mfa")}>
                        Reset
                      </button>
                    )}
                  </span>
                ) : (
                  "Not set up yet"
                ),
              ],
              ["Sign-in", u.locked ? <span className="inline-flex items-center gap-1 text-danger"><Lock className="size-3.5" aria-hidden />Locked after failed attempts</span> : u.status === "active" ? "Allowed" : "Disabled"],
              ["Last sign-in", u.lastLoginAt ? `${formatRelative(u.lastLoginAt)} (${formatDateTime(u.lastLoginAt)})` : "Never"],
              ["Created", formatDateTime(u.createdAt)],
            ]}
          />
        </Card>
      </div>

      <RenameDialog user={u} open={editingName} onClose={() => setEditingName(false)} />

      <Dialog open={link !== null} onClose={() => setLink(null)} title={link?.invite ? "Send this invitation link" : "Send this password reset link"} dismissible={false}>
        {link && (
          <div className="flex flex-col gap-3.5">
            <OneTimeNotice title="Copy this link now. It is shown only once.">
              Email is not configured on this server, so send it to {u.email} yourself. The link works once
              {link.invite ? " and expires in 72 hours." : " and expires soon."}
            </OneTimeNotice>
            <CodeBlock code={link.url} />
            <div className="flex justify-end">
              <Button variant="primary" onClick={() => setLink(null)}>
                Done
              </Button>
            </div>
          </div>
        )}
      </Dialog>

      <ConfirmDialog
        open={confirm !== null}
        onClose={() => {
          setConfirm(null);
          action.reset();
        }}
        onConfirm={() => confirm && action.mutate(confirm)}
        loading={action.isPending}
        error={action.error}
        tone={confirm === "delete" || confirm === "disable" || confirm === "reset-mfa" ? "danger" : "primary"}
        confirmText={confirm === "delete" ? u.email : undefined}
        {...confirmCopy(confirm, u)}
      />
    </>
  );
}

function confirmCopy(kind: Confirm, u: User): { title: string; confirmLabel: string; children: ReactNode } {
  switch (kind) {
    case "disable":
      return { title: "Disable user", confirmLabel: "Disable", children: <p>{u.displayName} is signed out everywhere and cannot sign in until enabled again. Their roles are kept.</p> };
    case "enable":
      return { title: "Enable user", confirmLabel: "Enable", children: <p>{u.displayName} can sign in again with their existing password and authenticator.</p> };
    case "unlock":
      return { title: "Unlock user", confirmLabel: "Unlock", children: <p>Clears the failed sign-in count so {u.displayName} can try again now.</p> };
    case "reset-mfa":
      return {
        title: "Reset second factor",
        confirmLabel: "Reset second factor",
        children: (
          <p>
            Removes {u.displayName}'s authenticator and recovery codes and signs them out. They set up a new authenticator at their next sign-in, so
            only do this after confirming who is asking.
          </p>
        ),
      };
    case "delete":
      return {
        title: "Delete user",
        confirmLabel: "Delete user",
        children: <p>This permanently deletes {u.displayName}'s account and roles. Their entries in the audit log are kept. To keep the account but block sign-in, disable it instead.</p>,
      };
    default:
      return { title: "", confirmLabel: "Confirm", children: null };
  }
}

function RolesForm({ user }: { user: User }) {
  const toast = useToast();
  const [drafts, setDrafts] = useState<DraftAssignment[]>(() => user.assignments.map(toDraft));
  useEffect(() => setDrafts(user.assignments.map(toDraft)), [user]);
  const save = useApiMutation((list: DraftAssignment[]) => api.put<User>(`/users/${user.id}/roles`, { assignments: list.map(fromDraft) }), {
    invalidate: ["/users", "/audit"],
    onSuccess: () => toast.success(`Roles for ${user.displayName} saved.`),
  });
  const original = JSON.stringify(user.assignments.map(toDraft));
  const changed = JSON.stringify(drafts) !== original;

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate(drafts);
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <AssignmentEditor value={drafts.length ? drafts : [{ role: "", organizationId: "", siteId: "" }]} onChange={setDrafts} error={save.error} hideLegend />
      {user.hiddenAssignments > 0 && (
        <p className="text-xs text-muted">
          {user.displayName} also holds {user.hiddenAssignments} role(s) in organizations you cannot see. Those are kept as they are.
        </p>
      )}
      <InlineError error={save.error} fields={["assignments", ...drafts.map((_, i) => `assignments.${i}`)]} />
      <div className="flex justify-end gap-2">
        {changed && (
          <Button onClick={() => setDrafts(user.assignments.map(toDraft))} disabled={save.isPending}>
            Discard changes
          </Button>
        )}
        <Button type="submit" variant="primary" loading={save.isPending} disabled={!changed || drafts.length === 0 || !drafts.every(draftComplete)}>
          Save roles
        </Button>
      </div>
    </form>
  );
}

function RenameDialog({ user, open, onClose }: { user: User; open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [name, setName] = useState(user.displayName);
  useEffect(() => {
    if (open) setName(user.displayName);
  }, [open, user.displayName]);
  const save = useApiMutation((displayName: string) => api.patch<User>(`/users/${user.id}`, { displayName }), {
    invalidate: ["/users", "/audit"],
    onSuccess: () => {
      toast.success("Name updated.");
      onClose();
    },
  });
  return (
    <Dialog open={open} onClose={onClose} title="Rename user" size="sm">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(name.trim());
        }}
        className="flex flex-col gap-3.5"
      >
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} error={fieldError(save.error, "displayName")} required maxLength={200} autoFocus />
        <InlineError error={save.error} fields={["displayName"]} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!name.trim() || name.trim() === user.displayName}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
