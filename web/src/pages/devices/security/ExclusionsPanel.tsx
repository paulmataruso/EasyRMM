import { useState, type FormEvent } from "react";
import { Lock } from "lucide-react";
import type { Device } from "../../../api/types";
import { useToast } from "../../../components/Toast";
import { Alert, Badge, Button, Input, Select, TextField } from "../../../components/ui";
import { ConfirmChange, Managed, ReadPanel, appliedMessage } from "./shared";
import { TAMPER_NOTE } from "./text";
import type { Change, Exclusion, ExclusionKind, ExclusionsRead } from "./types";
import { runAction, useRead } from "./winmod";

const KINDS: { kind: ExclusionKind; key: "path" | "process" | "extension" | "asrOnly"; title: string }[] = [
  { kind: "path", key: "path", title: "Paths" },
  { kind: "process", key: "process", title: "Processes" },
  { kind: "extension", key: "extension", title: "Extensions" },
  { kind: "asr_only", key: "asrOnly", title: "Attack Surface Reduction only" },
];

/**
 * Defender's exclusions. EasyRMM's own come first, locked, with no way to remove them; an administrator's can be removed;
 * adding one stops scanning and so needs a Site Administrator, a reason and the second factor.
 */
export function ExclusionsPanel({ device, canWeaken, canSeeSensitive }: { device: Device; canWeaken: boolean; canSeeSensitive: boolean }) {
  const toast = useToast();
  const read = useRead<ExclusionsRead>(device.id, "exclusions_read");
  const [adding, setAdding] = useState<{ kind: ExclusionKind; value: string; reason: string } | null>(null);
  const [form, setForm] = useState({ kind: "path" as ExclusionKind, value: "", reason: "" });
  const [removing, setRemoving] = useState<{ kind: ExclusionKind; value: string } | null>(null);
  const done = (c: Change, ok: string) => {
    const m = appliedMessage(c);
    if (m.ok) toast.success(ok);
    else toast.error(m.text);
    read.load();
  };
  if (!canSeeSensitive) {
    return (
      <ReadPanel title="Exclusions" read={read} readLabel="Read exclusions">
        {() => null}
      </ReadPanel>
    );
  }
  return (
    <ReadPanel
      title="Exclusions"
      read={read}
      readLabel="Read exclusions"
      extra={<p className="text-sm text-muted">EasyRMM's own exclusions are locked: they keep Defender from blocking the agents.</p>}
    >
      {(d) => (
        <>
          {d.tamperProtected && <Alert tone="info">Tamper Protection is on: it blocks every exclusion change. {TAMPER_NOTE}</Alert>}
          {d.localMergeDisabled && <Alert tone="warn">Policy ignores local exclusions on this computer, so adding one here would do nothing.</Alert>}
          {KINDS.map(({ kind, key, title }) => {
            const rows: Exclusion[] = [...d[key]].sort((a, b) => Number(b.ours) - Number(a.ours));
            return (
              <section key={kind} aria-label={title}>
                <h4 className="text-sm font-semibold">{title}</h4>
                {d.unavailable.includes(kind) ? (
                  <p className="text-sm text-muted">Defender will not show this list (it needs Tamper Protection to be off or an administrator).</p>
                ) : (
                  <ul className="divide-y divide-border">
                    {rows.map((x) => (
                      <li key={x.value} className="flex flex-wrap items-center gap-3 py-1.5 text-sm">
                        <span className="min-w-0 flex-1 break-all font-mono text-xs">{x.value}</span>
                        {x.ours && (
                          <Badge tone="info" title="EasyRMM needs this so Defender does not block its own files" icon={<Lock className="size-3" aria-hidden />}>
                            EasyRMM
                          </Badge>
                        )}
                        <Managed by={x.managedBy} />
                        {!x.ours && !x.managedBy && (
                          <Button size="sm" variant="danger-ghost" onClick={() => setRemoving({ kind, value: x.value })}>
                            Remove
                          </Button>
                        )}
                      </li>
                    ))}
                    {rows.length === 0 && <li className="py-1.5 text-sm text-muted">None.</li>}
                  </ul>
                )}
              </section>
            );
          })}
          {canWeaken && (
            <form
              aria-label="Add an exclusion"
              className="flex flex-wrap items-end gap-2"
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                setAdding(form);
              }}
            >
              <Select aria-label="Kind" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as ExclusionKind })} className="w-48">
                {KINDS.map((k) => (
                  <option key={k.kind} value={k.kind}>
                    {k.title}
                  </option>
                ))}
              </Select>
              <Input aria-label="Value" placeholder="D:\Folder, a full .exe path or an extension" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} className="w-72" />
              <TextField label="" aria-label="Reason" placeholder="Why (3 to 200 characters)" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} className="w-64" />
              <Button type="submit" disabled={!form.value.trim() || form.reason.trim().length < 3}>
                Add exclusion
              </Button>
            </form>
          )}
          <ConfirmChange
            open={adding !== null}
            onClose={() => setAdding(null)}
            title="Add an exclusion"
            confirmLabel="Add exclusion"
            danger
            effect={
              <p>
                Defender will stop scanning <strong className="break-all">{adding?.value}</strong>. This needs your second factor, and the reason is recorded in the
                audit log. A drive, a system folder, a scripting program or a program file type is refused.
              </p>
            }
            run={async () => {
              if (!adding) return;
              const { data } = await runAction<Change>(
                device.id,
                "exclusion_add",
                { kind: adding.kind, value: adding.value, reason: adding.reason },
                `defender.exclusion_add:${adding.value}`,
              );
              done(data, "Exclusion added.");
              setForm({ ...form, value: "", reason: "" });
            }}
          />
          <ConfirmChange
            open={removing !== null}
            onClose={() => setRemoving(null)}
            title="Remove an exclusion"
            confirmLabel="Remove exclusion"
            effect={
              <p>
                Defender will scan <strong className="break-all">{removing?.value}</strong> again. EasyRMM's own exclusions cannot be removed here.
              </p>
            }
            run={async () => {
              if (!removing) return;
              const { data } = await runAction<Change>(device.id, "exclusion_remove", { kind: removing.kind, value: removing.value }, `defender.exclusion_remove:${removing.value}`);
              done(data, "Exclusion removed.");
            }}
          />
        </>
      )}
    </ReadPanel>
  );
}
