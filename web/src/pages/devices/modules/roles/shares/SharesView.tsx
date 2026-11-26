import { useState } from "react";
import { Lock, Plus } from "lucide-react";
import type { Device } from "../../../../../api/types";
import { useAuth } from "../../../../../auth/AuthContext";
import { Alert, Badge, Button, Card, EmptyState, InlineError, KeyValueList, Segmented, SelectField, TableWrap, TextField } from "../../../../../components/ui";
import { formatDuration } from "../../../../../lib/format";
import { ModuleTab } from "../../ModuleTab";
import { failureText, useWinmodChange, useWinmodRead } from "../../winmod";
import { ActionDialog, FormDialog } from "../kit";
import type { OpenFileList, Share, ShareAccess, ShareList, SessionList, SharesStatus } from "./types";

const M = "file_shares";
type Dialog =
  | { kind: "create" }
  | { kind: "edit"; share: Share }
  | { kind: "remove"; share: Share }
  | { kind: "grant"; share: Share }
  | { kind: "revoke"; share: Share; account: string }
  | { kind: "block"; share: Share; account: string; blocked: boolean }
  | { kind: "closeSession"; id: string; user: string }
  | { kind: "closeFile"; id: string; path: string; user: string };

const flag = (v: boolean | null) => (v === null ? "—" : v ? "Yes" : "No");

/** The File shares module (ADR-0076, section 6): shares and their permissions, open sessions and files. */
export function SharesView({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const manage = canAt("shares.manage", { organizationId: device.organizationId, siteId: device.siteId });
  const [started, setStarted] = useState(false);
  const [panel, setPanel] = useState<"shares" | "open">("shares");
  const [selected, setSelected] = useState<string | null>(null);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const status = useWinmodRead<SharesStatus>(device.id, `${M}.status`, {}, started);
  const shares = useWinmodRead<ShareList>(device.id, `${M}.share_list`, {}, started);
  const access = useWinmodRead<ShareAccess>(device.id, `${M}.share_access_get`, { name: selected ?? "" }, started && selected !== null);
  const sessions = useWinmodRead<SessionList>(device.id, `${M}.session_list`, {}, started && panel === "open");
  const files = useWinmodRead<OpenFileList>(device.id, `${M}.openfile_list`, {}, started && panel === "open");
  const change = useWinmodChange(device.id, M);

  const reads = [status, shares, ...(selected ? [access] : []), ...(panel === "open" ? [sessions, files] : [])];
  const refresh = () => (started ? reads.forEach((r) => void r.refetch()) : setStarted(true));
  const failure = reads.map((r) => r.data?.failure).find(Boolean);
  const lost = reads.map((r) => r.data?.lost).find(Boolean);
  const st = status.data?.data ?? null;
  const list = shares.data?.data ?? null;
  const open = (d: Dialog) => {
    change.reset();
    setDialog(d);
  };
  const close = () => setDialog(null);

  return (
    <ModuleTab
      name="File shares"
      asOf={st ? (status.data?.finishedAt ?? null) : null}
      onRefresh={refresh}
      refreshing={reads.some((r) => r.isFetching)}
      unavailable={failure ? failureText(failure) : (lost ?? undefined)}
    >
      <InlineError error={reads.map((r) => r.error).find(Boolean)} />
      {st && (
        <Card title="Server">
          <KeyValueList
            items={[
              ["Service", <Badge key="s" tone={st.serviceState === "running" ? "ok" : "danger"}>{st.serviceState}</Badge>],
              ["Shares", `${st.userShareCount} (${st.shareCount} with the administrative ones)`],
              ["Sessions", String(st.sessionCount)],
              ["Open files", String(st.openFileCount)],
              ["SMB1 enabled", flag(st.smb1Enabled)],
              ["Signing required", flag(st.signingRequired)],
              ["Encryption required", flag(st.encryptionRequired)],
            ]}
          />
          <p className="mt-2 text-xs text-muted">The server&apos;s SMB settings are shown, not changed, here.</p>
        </Card>
      )}
      {list && (
        <Segmented
          label="View"
          value={panel}
          onChange={setPanel}
          options={[
            { value: "shares", label: "Shares" },
            { value: "open", label: "Sessions and open files" },
          ]}
        />
      )}
      {list && panel === "shares" && (
        <Card
          title="Shares"
          padded={false}
          actions={manage && <Button size="sm" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => open({ kind: "create" })}>Share a folder</Button>}
        >
          {list.shares.length === 0 ? (
            <EmptyState compact title="No shares">This server shares nothing.</EmptyState>
          ) : (
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col" className="hidden md:table-cell">Folder</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {list.shares.map((s) => (
                    <tr key={s.name} aria-selected={s.name === selected}>
                      <td className="font-medium">
                        {s.name}
                        {s.encrypted && <Badge className="ml-2">encrypted</Badge>}
                      </td>
                      <td className="hidden break-all md:table-cell">{s.path}</td>
                      <td className="text-right whitespace-nowrap">
                        <Button size="sm" variant="ghost" onClick={() => setSelected(s.name)}>Permissions</Button>
                        {s.protected ? (
                          <Badge icon={<Lock className="size-3" aria-hidden />} title="Windows needs this share; the console does not change it">Protected</Badge>
                        ) : (
                          manage && (
                            <>
                              <Button size="sm" variant="ghost" onClick={() => open({ kind: "edit", share: s })}>Edit</Button>
                              <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "remove", share: s })}>Remove</Button>
                            </>
                          )
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>
      )}
      {panel === "shares" && selected && access.data?.data && (
        <Card
          title={`Permissions of ${selected}`}
          padded={false}
          actions={
            manage && !list?.shares.find((s) => s.name === selected)?.protected && (
              <Button size="sm" onClick={() => open({ kind: "grant", share: list!.shares.find((s) => s.name === selected)! })}>Grant access</Button>
            )
          }
        >
          <TableWrap className="rounded-none border-0">
            <table className="table-base">
              <thead>
                <tr>
                  <th scope="col">Account</th>
                  <th scope="col">Access</th>
                  <th scope="col"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {access.data.data.entries.map((e, i) => {
                  const share = list?.shares.find((s) => s.name === selected);
                  return (
                    <tr key={`${e.account}|${e.type}|${i}`}>
                      <td>{e.account}</td>
                      <td>{e.type === "Deny" ? <Badge tone="danger">Blocked</Badge> : e.right}</td>
                      <td className="text-right whitespace-nowrap">
                        {manage && share && !share.protected && (
                          <>
                            {e.type === "Deny" ? (
                              <Button size="sm" variant="ghost" onClick={() => open({ kind: "block", share, account: e.account, blocked: true })}>Unblock</Button>
                            ) : (
                              <>
                                <Button size="sm" variant="ghost" onClick={() => open({ kind: "block", share, account: e.account, blocked: false })}>Block</Button>
                                <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "revoke", share, account: e.account })}>Revoke</Button>
                              </>
                            )}
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
          <p className="border-t border-line px-4 py-2 text-xs text-muted">
            Share permissions are one of two gates: what a person can do to a file is the more restrictive of this and the folder&apos;s own permissions, which this console does not change.
          </p>
        </Card>
      )}
      {panel === "open" && (
        <>
          <Card title="Sessions" padded={false}>
            {(sessions.data?.data?.sessions.length ?? 0) === 0 ? (
              <EmptyState compact title="No sessions">{sessions.data?.data ? "Nobody is connected." : "Reading the sessions…"}</EmptyState>
            ) : (
              <TableWrap className="rounded-none border-0">
                <table className="table-base">
                  <thead>
                    <tr>
                      <th scope="col">User</th>
                      <th scope="col">Computer</th>
                      <th scope="col" className="hidden sm:table-cell">Connected</th>
                      <th scope="col"><span className="sr-only">Actions</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.data!.data!.sessions.map((s) => (
                      <tr key={s.id}>
                        <td>{s.user}</td>
                        <td>{s.client}</td>
                        <td className="hidden sm:table-cell">{formatDuration(s.secondsActive)}</td>
                        <td className="text-right">
                          {manage && <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "closeSession", id: s.id, user: s.user })}>Close</Button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </Card>
          <Card title="Open files" padded={false}>
            {(files.data?.data?.files.length ?? 0) === 0 ? (
              <EmptyState compact title="No open files">{files.data?.data ? "No file is open over the network." : "Reading the open files…"}</EmptyState>
            ) : (
              <TableWrap className="rounded-none border-0">
                <table className="table-base">
                  <thead>
                    <tr>
                      <th scope="col">File</th>
                      <th scope="col">User</th>
                      <th scope="col"><span className="sr-only">Actions</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {files.data!.data!.files.map((f) => (
                      <tr key={f.id}>
                        <td className="break-all">{f.path}</td>
                        <td>{f.user}</td>
                        <td className="text-right">
                          {manage && <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "closeFile", id: f.id, path: f.path, user: f.user })}>Close</Button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </Card>
        </>
      )}
      <SharesDialogs dialog={dialog} device={device} change={change} close={close} />
    </ModuleTab>
  );
}

function SharesDialogs({ dialog, device, change, close }: { dialog: Dialog | null; device: Device; change: ReturnType<typeof useWinmodChange>; close: () => void }) {
  if (!dialog) return null;
  const common = { device, change, onClose: close };
  switch (dialog.kind) {
    case "create":
      return <CreateShare {...common} />;
    case "edit":
      return <EditShare share={dialog.share} {...common} />;
    case "grant":
      return <Grant share={dialog.share} {...common} />;
    case "remove":
      return (
        <ActionDialog {...common} title="Remove share" label="Remove share" danger op={{ action: `${M}.share_remove`, params: { name: dialog.share.name }, confirmed: true }}>
          Remove the share <strong>{dialog.share.name}</strong>? The files stay where they are. People lose access at once and open files are dropped. This needs a second factor.
        </ActionDialog>
      );
    case "revoke":
      return (
        <ActionDialog {...common} title="Revoke access" label="Revoke" op={{ action: `${M}.share_access_revoke`, params: { name: dialog.share.name, account: dialog.account }, confirmed: true }}>
          Remove {dialog.account}&apos;s own entry from <strong>{dialog.share.name}</strong>?
        </ActionDialog>
      );
    case "block":
      return (
        <ActionDialog
          {...common}
          title={dialog.blocked ? "Unblock account" : "Block account"}
          label={dialog.blocked ? "Unblock" : "Block"}
          op={{ action: `${M}.${dialog.blocked ? "share_access_unblock" : "share_access_block"}`, params: { name: dialog.share.name, account: dialog.account }, confirmed: true }}
        >
          {dialog.blocked ? "Lift the block on" : "Block"} {dialog.account} {dialog.blocked ? "for" : "from"} <strong>{dialog.share.name}</strong>?
        </ActionDialog>
      );
    case "closeSession":
      return (
        <ActionDialog {...common} title="Close session" label="Close session" danger op={{ action: `${M}.session_close`, params: { id: dialog.id }, confirmed: true }}>
          Disconnect {dialog.user}? They reconnect at once, and files they have open can lose unsaved changes.
        </ActionDialog>
      );
    case "closeFile":
      return (
        <ActionDialog {...common} title="Close open file" label="Close file" danger op={{ action: `${M}.openfile_close`, params: { id: dialog.id }, confirmed: true }}>
          Close <strong>{dialog.path}</strong>, opened by {dialog.user}? <strong>Unsaved changes in the file can be lost.</strong>
        </ActionDialog>
      );
  }
}

type DialogProps = { device: Device; change: ReturnType<typeof useWinmodChange>; onClose: () => void };

function CreateShare(p: DialogProps) {
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [description, setDescription] = useState("");
  return (
    <FormDialog
      {...p}
      title="Share a folder"
      description="Only the administrators can read it until you grant access."
      label="Create share"
      valid={name.trim() !== "" && /^[A-Za-z]:\\/.test(path.trim())}
      build={() => ({ action: `${M}.share_create`, confirmed: true, params: { name: name.trim(), path: path.trim(), ...(description.trim() ? { description: description.trim() } : {}) } })}
    >
      <TextField label="Share name" value={name} onChange={(e) => setName(e.target.value)} hint="Names ending in $ are hidden shares, which this console does not create." required />
      <TextField label="Folder on this computer" value={path} onChange={(e) => setPath(e.target.value)} hint="For example D:\Shares\Data. Not a drive root or the Windows folder." required />
      <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
    </FormDialog>
  );
}

function EditShare({ share, ...p }: DialogProps & { share: Share }) {
  const [description, setDescription] = useState(share.description);
  const [enumeration, setEnumeration] = useState(share.folderEnumeration || "AccessBased");
  const [encrypt, setEncrypt] = useState(share.encrypted);
  return (
    <FormDialog
      {...p}
      title="Change share"
      description={share.name}
      label="Save"
      valid
      build={() => ({ action: `${M}.share_set`, confirmed: true, params: { name: share.name, description, enumeration, encrypt } })}
    >
      <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
      <SelectField label="Folders people cannot open" value={enumeration} onChange={(e) => setEnumeration(e.target.value)}>
        <option value="AccessBased">Hidden from them</option>
        <option value="Unrestricted">Shown</option>
      </SelectField>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={encrypt} onChange={(e) => setEncrypt(e.target.checked)} /> Encrypt data in transit
      </label>
    </FormDialog>
  );
}

function Grant({ share, ...p }: DialogProps & { share: Share }) {
  const [account, setAccount] = useState("");
  const [right, setRight] = useState("Read");
  return (
    <FormDialog
      {...p}
      title="Grant share access"
      description={share.name}
      label="Grant"
      valid={account.trim() !== ""}
      build={() => ({ action: `${M}.share_access_grant`, confirmed: true, params: { name: share.name, account: account.trim(), right } })}
    >
      <TextField label="User or group" value={account} onChange={(e) => setAccount(e.target.value)} hint="DOMAIN\name, or a name on this computer." required />
      <SelectField label="Access" value={right} onChange={(e) => setRight(e.target.value)}>
        <option>Read</option>
        <option>Change</option>
        <option>Full</option>
      </SelectField>
      <Alert tone="info">Change or full control for Everyone, Anonymous Logon or Authenticated Users (and full control for Users) is refused.</Alert>
    </FormDialog>
  );
}
