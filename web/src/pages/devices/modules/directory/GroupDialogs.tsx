import { useEffect, useState } from "react";
import { Alert, Button, Input, Select, TextField } from "../../../../components/ui";
import { ActionDialog, Done } from "./ActionDialog";
import { OuPicker } from "./OuPicker";
import type { GroupMember, GroupRow, UserPage, UserRow } from "./types";
import { confirmFor, useWinmod } from "./useWinmod";

export function CreateGroupDialog({ deviceId, open, onClose }: { deviceId: string; open: boolean; onClose: (c: boolean) => void }) {
  const run = useWinmod(deviceId);
  const [ou, setOu] = useState("");
  const [name, setName] = useState("");
  const [scope, setScope] = useState("global");
  const [category, setCategory] = useState("security");
  const [description, setDescription] = useState("");
  useEffect(() => {
    if (open) {
      setName("");
      setDescription("");
    }
  }, [open]);
  return (
    <ActionDialog
      open={open}
      title="Create a group"
      verb="Create group"
      ready={ou !== "" && name.trim() !== ""}
      submit={() => run("group_create", { ou, name: name.trim(), scope, category, ...(description.trim() ? { description: description.trim() } : {}) }, confirmFor("group_create", name.trim()))}
      done={() => <Done>The group was created.</Done>}
      onClose={onClose}
    >
      <OuPicker deviceId={deviceId} value={ou} onChange={setOu} />
      <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} autoComplete="off" />
      <div className="grid grid-cols-2 gap-3">
        <label className="text-xs text-muted">
          Scope
          <Select value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value="global">Global</option>
            <option value="domain_local">Domain local</option>
            <option value="universal">Universal</option>
          </Select>
        </label>
        <label className="text-xs text-muted">
          Kind
          <Select value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="security">Security</option>
            <option value="distribution">Distribution</option>
          </Select>
        </label>
      </div>
      <TextField label="Description (optional)" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={200} />
    </ActionDialog>
  );
}

/** Add a member (found by name) to a group, from the group's member list. */
export function AddMemberDialog({ deviceId, group, onClose }: { deviceId: string; group: GroupRow | null; onClose: (c: boolean) => void }) {
  const run = useWinmod(deviceId);
  const [q, setQ] = useState("");
  const [found, setFound] = useState<UserRow[]>([]);
  const [pick, setPick] = useState<UserRow | null>(null);
  useEffect(() => {
    setQ("");
    setFound([]);
    setPick(null);
  }, [group]);
  if (!group) return null;
  const search = async () => {
    const r = await run<UserPage>("user_list", { scope: "subtree", match: q.trim(), pageSize: 20 });
    setFound(r.ok && r.data ? r.data.items.filter((u) => u.protection === "none") : []);
  };
  return (
    <ActionDialog
      open
      title={`Add a member to ${group.name}`}
      description="Whoever is added gets everything the group grants."
      verb="Add member"
      ready={pick !== null}
      confirmWord={group.sam}
      submit={() => run("group_add_member", { id: group.id, member: pick!.id }, confirmFor("group_add_member", group.id))}
      done={() => <Done>The member was added.</Done>}
      onClose={onClose}
    >
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); void search(); }}>
        <Input aria-label="Find a user" placeholder="Name or sign-in name starts with…" value={q} onChange={(e) => setQ(e.target.value)} />
        <Button type="submit" size="sm">Find</Button>
      </form>
      <ul className="flex flex-col gap-1 text-sm">
        {found.map((u) => (
          <li key={u.id}>
            <label className="flex items-center gap-2">
              <input type="radio" name="member" checked={pick?.id === u.id} onChange={() => setPick(u)} /> {u.name} <span className="text-xs text-muted">({u.sam})</span>
            </label>
          </li>
        ))}
      </ul>
    </ActionDialog>
  );
}

export function RemoveMemberDialog({ deviceId, group, member, onClose }: { deviceId: string; group: GroupRow; member: GroupMember | null; onClose: (c: boolean) => void }) {
  const run = useWinmod(deviceId);
  if (!member) return null;
  return (
    <ActionDialog
      open
      title={`Remove ${member.name} from ${group.name}`}
      description="They lose what the group grants."
      verb="Remove"
      danger
      submit={() => run("group_remove_member", { id: group.id, member: member.id }, confirmFor("group_remove_member", group.id))}
      done={() => <Done>The member was removed.</Done>}
      onClose={onClose}
    >
      <Alert tone="warn">A protected account or group is refused by the controller, whatever is sent here.</Alert>
    </ActionDialog>
  );
}

export function DeleteGroupDialog({ deviceId, group, recycleBin, onClose }: { deviceId: string; group: GroupRow | null; recycleBin: boolean; onClose: (c: boolean) => void }) {
  const run = useWinmod(deviceId);
  if (!group) return null;
  return (
    <ActionDialog
      open
      title={`Delete ${group.name}`}
      verb="Delete group"
      danger
      confirmWord={group.sam}
      submit={() => run("group_delete", { id: group.id }, confirmFor("group_delete", group.id))}
      done={() => <Done>The group was deleted.</Done>}
      onClose={onClose}
    >
      <Alert tone="warn">
        {recycleBin ? "The Recycle Bin is on, so the group can be restored with the directory's own tools." : "The Recycle Bin is off: the group is permanently gone once the controllers have replicated."}
      </Alert>
    </ActionDialog>
  );
}
