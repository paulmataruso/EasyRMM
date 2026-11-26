import { useState } from "react";
import { Lock } from "lucide-react";
import type { Device } from "../../../api/types";
import { useToast } from "../../../components/Toast";
import { Badge, Button, Input } from "../../../components/ui";
import { ConfirmChange, Managed, ReadPanel, appliedMessage } from "./shared";
import type { CfaRead, Change, PathItem } from "./types";
import { runAction, useRead } from "./winmod";

const OURS = "EasyRMM needs this so Defender does not block its own files";

function List({
  title,
  items,
  canWeaken,
  canManage,
  addLabel,
  onRemove,
  onAdd,
}: {
  title: string;
  items: PathItem[];
  canWeaken: boolean;
  canManage: boolean;
  addLabel: string;
  onRemove: (path: string) => void;
  onAdd: (path: string) => void;
}) {
  const [path, setPath] = useState("");
  return (
    <section aria-label={title}>
      <h4 className="text-sm font-semibold">{title}</h4>
      <ul className="divide-y divide-border">
        {[...items].sort((a, b) => Number(b.ours) - Number(a.ours)).map((i) => (
          <li key={i.path} className="flex items-center gap-3 py-1.5 text-sm">
            <span className="min-w-0 flex-1 break-all font-mono text-xs">{i.path}</span>
            {i.ours ? (
              <Badge tone="info" title={OURS} icon={<Lock className="size-3" aria-hidden />}>
                EasyRMM
              </Badge>
            ) : (
              canWeaken && (
                <Button size="sm" variant="danger-ghost" onClick={() => onRemove(i.path)}>
                  Remove
                </Button>
              )
            )}
          </li>
        ))}
        {items.length === 0 && <li className="py-1.5 text-sm text-muted">None.</li>}
      </ul>
      {canManage && (
        <form
          className="mt-2 flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (path.trim()) onAdd(path.trim());
            setPath("");
          }}
        >
          <Input aria-label={addLabel} placeholder={addLabel} value={path} onChange={(e) => setPath(e.target.value)} className="max-w-md" />
          <Button size="sm" type="submit" disabled={!path.trim()}>
            Add
          </Button>
        </form>
      )}
    </section>
  );
}

/** Controlled Folder Access (ransomware protection): the mode, the protected folders and the allowed programs. */
export function CfaPanel({ device, canManage, canWeaken }: { device: Device; canManage: boolean; canWeaken: boolean }) {
  const toast = useToast();
  const read = useRead<CfaRead>(device.id, "cfa_read");
  const [pending, setPending] = useState<{ action: string; params: Record<string, string>; subject: string; text: string; danger: boolean } | null>(null);
  const run = async (action: string, params: Record<string, string>, confirm?: string) => {
    const { data } = await runAction<Change>(device.id, action, params, confirm);
    const m = appliedMessage(data);
    if (m.ok) toast.success("Done.");
    else toast.error(m.text);
    read.load();
  };
  const tier3 = (action: string, params: Record<string, string>, subject: string, text: string) => setPending({ action, params, subject, text, danger: true });
  return (
    <ReadPanel title="Controlled Folder Access" read={read} readLabel="Read folder access">
      {(d) =>
        !d.supported ? (
          <p className="text-sm text-muted">This computer does not support Controlled Folder Access.</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <span>
                Mode: <strong>{d.mode}</strong>
              </span>
              <Managed by={d.managedBy} />
              {canManage && !d.managedBy && d.mode !== "Enabled" && (
                <Button size="sm" onClick={() => void run("cfa_set", { mode: "Enabled" }).catch((e: Error) => toast.error(e.message))}>
                  Turn on
                </Button>
              )}
              {canWeaken && !d.managedBy && d.mode === "Enabled" && (
                <Button size="sm" variant="danger-ghost" onClick={() => tier3("cfa_weaken", { mode: "AuditMode" }, "AuditMode", "Controlled Folder Access will only audit, not block.")}>
                  Set to audit only
                </Button>
              )}
              {canWeaken && !d.managedBy && d.mode !== "Disabled" && (
                <Button size="sm" variant="danger-ghost" onClick={() => tier3("cfa_weaken", { mode: "Disabled" }, "Disabled", "Controlled Folder Access will be turned off.")}>
                  Turn off
                </Button>
              )}
            </div>
            <List
              title="Protected folders"
              items={d.protectedFolders}
              canManage={canManage}
              canWeaken={canWeaken}
              addLabel="Folder to protect, such as D:\Data"
              onAdd={(p) => void run("cfa_folder_add", { path: p }).catch((e: Error) => toast.error(e.message))}
              onRemove={(p) => tier3("cfa_folder_remove", { path: p }, p, `The folder ${p} will no longer be protected.`)}
            />
            <List
              title="Allowed programs"
              items={d.allowedApplications}
              canManage={canWeaken}
              canWeaken={canWeaken}
              addLabel="Program to allow, such as D:\Tools\tool.exe"
              onAdd={(p) => tier3("cfa_app_add", { path: p }, p, `${p} will be allowed to change protected folders.`)}
              onRemove={(p) => tier3("cfa_app_remove", { path: p }, p, `${p} will no longer be allowed through Controlled Folder Access.`)}
            />
            <ConfirmChange
              open={pending !== null}
              onClose={() => setPending(null)}
              title="Lower protection"
              confirmLabel="Confirm"
              danger
              effect={<p>{pending?.text} This needs your second factor and is recorded in the audit log.</p>}
              run={async () => {
                if (pending) await run(pending.action, pending.params, `defender.${pending.action}:${pending.subject}`);
              }}
            />
          </>
        )
      }
    </ReadPanel>
  );
}
