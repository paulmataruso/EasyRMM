import { useEffect, useState } from "react";
import { CopyButton } from "../../../../components/Copy";
import { Alert, Mono, Segmented, TextField } from "../../../../components/ui";
import { ActionDialog, Done } from "./ActionDialog";
import { OuPicker } from "./OuPicker";
import type { UserDetail, UserRow } from "./types";
import { confirmFor, useWinmod } from "./useWinmod";

/** Create a user: the container, the names, and a typed or generated first password (shown once, never kept). */
export function CreateUserDialog({ deviceId, minLength, open, onClose }: { deviceId: string; minLength: number; open: boolean; onClose: (c: boolean) => void }) {
  const run = useWinmod(deviceId);
  const [ou, setOu] = useState("");
  const [f, setF] = useState({ sam: "", name: "", upn: "", givenName: "", surname: "", displayName: "" });
  const [how, setHow] = useState<"generate" | "type">("generate");
  const [password, setPassword] = useState("");
  const [mustChange, setMustChange] = useState(true);
  useEffect(() => {
    if (open) {
      setF({ sam: "", name: "", upn: "", givenName: "", surname: "", displayName: "" });
      setPassword("");
      setHow("generate");
      setMustChange(true);
    }
  }, [open]);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const long = Math.max(8, minLength);
  return (
    <ActionDialog<{ id: string }>
      open={open}
      title="Create a user"
      description="The account is created enabled, with the password below."
      verb="Create user"
      ready={ou !== "" && /^[A-Za-z0-9._-]{1,20}$/.test(f.sam) && f.name.trim() !== "" && (how === "generate" || password.length >= long)}
      confirmWord={f.sam || "the sign-in name"}
      submit={async () => {
        const params: Record<string, unknown> = { ou, sam: f.sam, name: f.name.trim(), mustChange };
        for (const k of ["upn", "givenName", "surname", "displayName"] as const) if (f[k].trim()) params[k] = f[k].trim();
        if (how === "type") params.password = password;
        const r = await run<{ id: string }>("user_create", params, confirmFor("user_create", f.sam));
        setPassword("");
        return r;
      }}
      done={(r) => (
        <div className="flex flex-col gap-3">
          <Done>The user was created.</Done>
          {r.generated?.password && (
            <div className="flex flex-col gap-2">
              <p className="text-sm">Give them this password. It is shown now and not again.</p>
              <div className="flex flex-wrap items-center gap-2">
                <Mono className="rounded border border-line bg-surface px-2 py-1 text-base select-all">{r.generated.password}</Mono>
                <CopyButton text={r.generated.password} />
              </div>
            </div>
          )}
        </div>
      )}
      onClose={onClose}
    >
      <OuPicker deviceId={deviceId} value={ou} onChange={setOu} />
      <TextField label="Sign-in name (up to 20 letters, digits . _ -)" value={f.sam} onChange={set("sam")} maxLength={20} autoComplete="off" />
      <TextField label="Full name" value={f.name} onChange={set("name")} maxLength={64} autoComplete="off" />
      <TextField label="User principal name (optional)" value={f.upn} onChange={set("upn")} autoComplete="off" />
      <div className="grid grid-cols-2 gap-3">
        <TextField label="First name" value={f.givenName} onChange={set("givenName")} />
        <TextField label="Last name" value={f.surname} onChange={set("surname")} />
      </div>
      <TextField label="Display name" value={f.displayName} onChange={set("displayName")} />
      <Segmented label="Password" value={how} onChange={setHow} options={[{ value: "generate", label: "Generate one" }, { value: "type", label: "Type one" }]} />
      {how === "type" && <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" hint={`At least ${long} characters.`} />}
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={mustChange} onChange={(e) => setMustChange(e.target.checked)} /> They must change it at the next sign-in
      </label>
    </ActionDialog>
  );
}

const FIELDS = [
  ["givenName", "First name"],
  ["surname", "Last name"],
  ["displayName", "Display name"],
  ["description", "Description"],
  ["mail", "Email"],
  ["telephone", "Telephone"],
  ["title", "Title"],
  ["department", "Department"],
  ["company", "Company"],
  ["office", "Office"],
] as const;

/** Edit a user's descriptive attributes (an empty value clears it) and move the account to another container. */
export function EditUserDialog({ deviceId, user, canMove, onClose }: { deviceId: string; user: UserRow | null; canMove: boolean; onClose: (c: boolean) => void }) {
  const run = useWinmod(deviceId);
  const [orig, setOrig] = useState<UserDetail | null>(null);
  const [vals, setVals] = useState<Record<string, string>>({});
  const [problem, setProblem] = useState<string | null>(null);
  const [moving, setMoving] = useState(false);
  const [target, setTarget] = useState("");
  useEffect(() => {
    setOrig(null);
    setProblem(null);
    setMoving(false);
    if (!user) return;
    let live = true;
    void run<UserDetail>("user_get", { id: user.id }).then((r) => {
      if (!live) return;
      if (r.ok && r.data) {
        setOrig(r.data);
        setVals(Object.fromEntries(FIELDS.map(([k]) => [k, (r.data as unknown as Record<string, string>)[k] ?? ""])));
      } else setProblem(r.failure?.message ?? "The account could not be read.");
    });
    return () => {
      live = false;
    };
  }, [user, run]);
  if (!user) return null;
  const changed = orig ? FIELDS.filter(([k]) => vals[k] !== (orig as unknown as Record<string, string>)[k]).map(([k]) => k) : [];
  return (
    <ActionDialog
      open
      title={`Edit ${user.name}`}
      description={moving ? "Move the account to another container." : "Change what the directory says about this person."}
      verb={moving ? "Move" : "Save"}
      ready={orig !== null && (moving ? target !== "" && target !== orig.ou : changed.length > 0)}
      submit={() =>
        moving
          ? run("user_move", { id: user.id, targetOu: target }, confirmFor("user_move", user.id))
          : run("user_set", { id: user.id, ...Object.fromEntries(changed.map((k) => [k, vals[k]])) }, confirmFor("user_set", user.id))
      }
      done={() => <Done>Saved.</Done>}
      onClose={onClose}
    >
      {problem && <Alert tone="warn">{problem}</Alert>}
      {!orig && !problem && <p className="text-sm text-muted">Reading…</p>}
      {orig && canMove && (
        <Segmented label="What" value={moving ? "move" : "edit"} onChange={(v) => setMoving(v === "move")} options={[{ value: "edit", label: "Attributes" }, { value: "move", label: "Move" }]} />
      )}
      {orig && !moving && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {FIELDS.map(([k, label]) => (
            <TextField key={k} label={label} value={vals[k] ?? ""} onChange={(e) => setVals({ ...vals, [k]: e.target.value })} maxLength={128} />
          ))}
        </div>
      )}
      {orig && moving && (
        <>
          <p className="text-xs text-muted">Now in {orig.ou}</p>
          <OuPicker deviceId={deviceId} value={target} onChange={setTarget} />
        </>
      )}
    </ActionDialog>
  );
}
