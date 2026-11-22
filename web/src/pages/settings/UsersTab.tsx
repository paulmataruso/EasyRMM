import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { ChevronRight, UserPlus, Users } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation, useList, usePrefetch } from "../../api/hooks";
import type { InviteResult, User } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { CodeBlock, OneTimeNotice } from "../../components/Copy";
import { Dialog } from "../../components/Dialog";
import { OrganizationSelect, SearchInput } from "../../components/Filters";
import { describeAssignment, UserStatusBadge } from "../../components/StatusBadges";
import { useToast } from "../../components/Toast";
import { Button, EmptyState, ErrorState, InlineError, Spinner, TableWrap, TextField, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { useRowKeys } from "../../lib/rowKeys";
import { useUrlState } from "../../lib/urlState";
import { AssignmentEditor, blankDraft, draftComplete, fromDraft, type DraftAssignment } from "./AssignmentEditor";
import { whyNotEmailed } from "./mailProblem";

export function UsersTab() {
  const { can } = useAuth();
  const url = useUrlState();
  const navigate = useNavigate();
  const prefetch = usePrefetch();
  const tableRef = useRef<HTMLDivElement>(null);
  const q = url.get("q");
  const organizationId = url.get("organizationId");
  const after = url.get("after");
  const list = useList<User>("/users", { q, organizationId, after, limit: 50 }, { keepPrevious: true });
  const inviting = url.get("invite") === "1";
  const filtered = Boolean(q || organizationId);

  const warm = (id: string) => prefetch(`/users/${id}`);
  useRowKeys(tableRef, (link) => link.dataset.id && warm(link.dataset.id));

  return (
    <>
      <Toolbar>
        <SearchInput value={q} onChange={(v) => url.set({ q: v, after: null })} placeholder="Search by name or email" className="max-w-sm" />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, after: null })} />
        <div className="flex-1" />
        {can("user.manage") && (
          <Button variant="primary" icon={<UserPlus className="size-4" aria-hidden />} onClick={() => url.set({ invite: "1" })}>
            Invite user
          </Button>
        )}
      </Toolbar>

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.items.length === 0 ? (
        <EmptyState title={filtered ? "No users match these filters" : "No users to show"} icon={<Users className="size-8" aria-hidden />}>
          {filtered ? "Try a different name, email or organization." : "Users appear here when they hold a role in an organization you can see."}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <div ref={tableRef}>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>User</th>
                    <th className="hidden md:table-cell">Roles</th>
                    <th>Status</th>
                    <th className="hidden sm:table-cell">Last sign-in</th>
                  </tr>
                </thead>
                <tbody>
                  {list.items.map((u) => (
                    <tr key={u.id} className="cursor-pointer align-top" onClick={() => navigate(`/users/${u.id}`)} onMouseEnter={() => warm(u.id)}>
                      <td>
                        <Link
                          to={`/users/${u.id}`}
                          className="font-medium hover:text-accent"
                          data-row-link
                          data-id={u.id}
                          onClick={(e) => e.stopPropagation()}
                          onFocus={() => warm(u.id)}
                        >
                          {u.displayName}
                        </Link>
                        {u.isSelf && <span className="ml-1.5 text-xs text-muted">(you)</span>}
                        <p className="text-xs text-muted">{u.email}</p>
                      </td>
                      <td className="hidden text-sm md:table-cell">
                        <ul>
                          {u.assignments.map((a, i) => (
                            <li key={i}>{describeAssignment(a)}</li>
                          ))}
                        </ul>
                        {u.hiddenAssignments > 0 && <p className="text-xs text-subtle">and {u.hiddenAssignments} outside your view</p>}
                      </td>
                      <td>
                        <UserStatusBadge user={u} />
                      </td>
                      <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={u.lastLoginAt ? formatDateTime(u.lastLoginAt) : undefined}>
                        {formatRelative(u.lastLoginAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </TableWrap>
          <nav className="mt-3 flex items-center justify-between gap-2 text-sm text-muted" aria-label="Pagination">
            <span>
              Showing {list.items.length} user{list.items.length === 1 ? "" : "s"}
              {after ? " (later page)" : ""}
            </span>
            <div className="flex items-center gap-1">
              {after && (
                <Button size="sm" variant="ghost" onClick={() => url.set({ after: null })}>
                  First page
                </Button>
              )}
              {list.next && (
                <Button size="sm" variant="ghost" onClick={() => url.set({ after: list.next })}>
                  Next page
                  <ChevronRight className="size-4" aria-hidden />
                </Button>
              )}
            </div>
          </nav>
        </>
      )}

      <InviteDialog open={inviting && can("user.manage")} onClose={() => url.set({ invite: null })} defaultOrganizationId={organizationId} />
    </>
  );
}

function InviteDialog({ open, onClose, defaultOrganizationId }: { open: boolean; onClose: () => void; defaultOrganizationId: string }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [drafts, setDrafts] = useState<DraftAssignment[]>([blankDraft()]);
  const [result, setResult] = useState<InviteResult | null>(null);

  const invite = useApiMutation(
    () => api.post<InviteResult>("/users", { email: email.trim(), displayName: displayName.trim(), assignments: drafts.map(fromDraft) }),
    {
      invalidate: ["/users", "/audit"],
      onSuccess: (res) => {
        if (res.emailed) {
          toast.success(`Invitation emailed to ${email.trim()}.`);
          close();
        } else {
          setResult(res);
        }
      },
    },
  );

  useEffect(() => {
    if (!open) return;
    setEmail("");
    setDisplayName("");
    setDrafts([{ ...blankDraft(), role: defaultOrganizationId ? "technician" : "", organizationId: defaultOrganizationId }]);
    setResult(null);
    invite.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function close() {
    onClose();
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    invite.mutate(undefined);
  }

  if (result?.link) {
    return (
      <Dialog open={open} onClose={close} title="Send this invitation link" size="md" dismissible={false}>
        <div className="flex flex-col gap-3.5">
          <OneTimeNotice title="Copy this link now. It is shown only once.">
            {whyNotEmailed(result.mailProblem, email.trim(), result.mailReason)} The link works once and expires in 72 hours.
          </OneTimeNotice>
          <CodeBlock code={result.link} />
          <div className="flex justify-end gap-2">
            {result.user && (
              <Button onClick={() => navigate(`/users/${result.user?.id}`)}>Open user</Button>
            )}
            <Button variant="primary" onClick={close}>
              Done
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onClose={close} title="Invite user" description="They choose a password from the invitation link, then set up an authenticator app." size="lg">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <TextField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} error={fieldError(invite.error, "email")} required autoFocus />
          <TextField label="Name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} error={fieldError(invite.error, "displayName")} required maxLength={200} />
        </div>
        <AssignmentEditor value={drafts} onChange={setDrafts} error={invite.error} />
        <InlineError error={invite.error} fields={["email", "displayName", "assignments", ...drafts.map((_, i) => `assignments.${i}`)]} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="primary" loading={invite.isPending} disabled={!email.trim() || !displayName.trim() || !drafts.every(draftComplete)}>
            Send invitation
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
