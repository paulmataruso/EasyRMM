import { useCallback, useState } from "react";
import { Lock, Search } from "lucide-react";
import { useAuth } from "../../../../auth/AuthContext";
import { Alert, Badge, Button, Card, InlineError, Input, Select, TableWrap } from "../../../../components/ui";
import { EditUserDialog, CreateUserDialog } from "./UserDialogs";
import { UserActionDialog, type UserAction } from "./UserActionDialog";
import { ResetPasswordDialog } from "./ResetPasswordDialog";
import type { DirectoryStatus, UserPage, UserRow } from "./types";
import { useWinmod } from "./useWinmod";

const STATES = [
  ["all", "All accounts"],
  ["disabled", "Disabled"],
  ["locked", "Locked out"],
  ["password_expired", "Password expired"],
  ["never_logged_on", "Never signed in"],
] as const;

/** The users of the domain, a page at a time; the help-desk actions are on the rows that are not protected. */
export function UsersCard({ deviceId, status, writable = true }: { deviceId: string; status: DirectoryStatus; writable?: boolean }) {
  const { can } = useAuth();
  const run = useWinmod(deviceId);
  const [rows, setRows] = useState<UserRow[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [match, setMatch] = useState("");
  const [state, setState] = useState<(typeof STATES)[number][0]>("all");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [acting, setActing] = useState<{ user: UserRow; action: UserAction } | null>(null);
  const [resetting, setResetting] = useState<UserRow | null>(null);
  const [editing, setEditing] = useState<UserRow | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(
    async (after?: string) => {
      setBusy(true);
      setError(null);
      setProblem(null);
      try {
        const params: Record<string, unknown> = { scope: "subtree", pageSize: 100 };
        if (match.trim()) params.match = match.trim();
        if (state !== "all") params.state = state;
        if (after) params.after = after;
        const r = await run<UserPage>("user_list", params);
        if (!r.ok || !r.data) {
          setProblem(r.failure?.message ?? "The controller did not answer.");
          return;
        }
        const page = r.data;
        setRows((old) => (after && old ? [...old, ...page.items] : page.items));
        setNext(page.next);
      } catch (e) {
        setError(e);
      } finally {
        setBusy(false);
      }
    },
    [run, match, state],
  );

  const help = can("ad.helpdesk") && !status.readOnly && writable;
  const manage = can("ad.manage") && !status.readOnly && writable;

  return (
    <Card title="Users">
      <form
        className="mb-3 flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void load();
        }}
      >
        <Input
          aria-label="Search users by name"
          placeholder="Name, sign-in name or UPN starts with…"
          value={match}
          onChange={(e) => setMatch(e.target.value)}
          className="max-w-xs"
          maxLength={64}
        />
        <Select aria-label="Show" value={state} onChange={(e) => setState(e.target.value as typeof state)} className="w-auto">
          {STATES.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </Select>
        <Button type="submit" size="sm" icon={<Search className="size-3.5" aria-hidden />} loading={busy}>
          {rows ? "Search" : "List users"}
        </Button>
        {manage && (
          <Button size="sm" onClick={() => setCreating(true)}>
            Create user
          </Button>
        )}
      </form>
      <InlineError error={error} />
      {problem && <Alert tone="warn">{problem}</Alert>}
      {rows && rows.length === 0 && <p className="text-sm text-muted">No account matches.</p>}
      {rows && rows.length > 0 && (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Sign-in name</th>
                <th scope="col">State</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((u) => (
                <tr key={u.id}>
                  <td>{u.name}</td>
                  <td className="font-mono text-xs">{u.sam}</td>
                  <td className="space-x-1">
                    <Badge tone={u.enabled ? "ok" : "neutral"}>{u.enabled ? "Enabled" : "Disabled"}</Badge>
                    {u.lockedOut && <Badge tone="danger">Locked out</Badge>}
                    {u.passwordExpired && <Badge tone="warn">Password expired</Badge>}
                    {u.protection === "protected" && (
                      <Badge tone="info" icon={<Lock className="size-3" aria-hidden />} title={`Protected: ${u.reason}. EasyRMM never changes it.`}>
                        Protected
                      </Badge>
                    )}
                    {u.protection === "service" && <Badge tone="warn" title={`Looks like a service account: ${u.reason}`}>Service account</Badge>}
                  </td>
                  <td className="text-right">
                    {help && u.protection !== "protected" && (u.protection !== "service" || manage) && (
                      <span className="inline-flex flex-wrap justify-end gap-1">
                        {u.lockedOut && (
                          <Button size="sm" onClick={() => setActing({ user: u, action: "user_unlock" })}>
                            Unlock
                          </Button>
                        )}
                        <Button size="sm" onClick={() => setResetting(u)}>
                          Reset password
                        </Button>
                        <Button size="sm" onClick={() => setActing({ user: u, action: u.enabled ? "user_disable" : "user_enable" })}>
                          {u.enabled ? "Disable" : "Enable"}
                        </Button>
                        {manage && (
                          <Button size="sm" onClick={() => setEditing(u)}>
                            Edit
                          </Button>
                        )}
                        {manage && (
                          <Button size="sm" variant="danger-ghost" onClick={() => setActing({ user: u, action: "user_delete" })}>
                            Delete
                          </Button>
                        )}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {next && (
        <Button className="mt-3" size="sm" onClick={() => void load(next)} loading={busy}>
          Show more
        </Button>
      )}
      <UserActionDialog
        deviceId={deviceId}
        recycleBin={status.recycleBinEnabled}
        target={acting}
        onClose={(changed) => {
          setActing(null);
          if (changed) void load();
        }}
      />
      <CreateUserDialog deviceId={deviceId} minLength={status.passwordPolicy.minLength} open={creating} onClose={(c) => { setCreating(false); if (c) void load(); }} />
      <EditUserDialog deviceId={deviceId} user={editing} canMove={manage} onClose={(c) => { setEditing(null); if (c) void load(); }} />
      <ResetPasswordDialog
        deviceId={deviceId}
        minLength={status.passwordPolicy.minLength}
        user={resetting}
        onClose={(changed) => {
          setResetting(null);
          if (changed) void load();
        }}
      />
    </Card>
  );
}
