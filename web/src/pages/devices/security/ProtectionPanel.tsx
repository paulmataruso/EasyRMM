import { useState } from "react";
import type { Device } from "../../../api/types";
import { useToast } from "../../../components/Toast";
import { Alert, Badge, Button, Input, Select } from "../../../components/ui";
import { ConfirmChange, Managed, ReadPanel, appliedMessage } from "./shared";
import { FIELD_RULES, GROUP_LABEL, TAMPER_NOTE, humanize, weakens } from "./text";
import type { Change, DefenderPreferences, PrefField } from "./types";
import { runAction, useRead } from "./winmod";

function display(f: PrefField): string {
  if (f.unavailable) return "Defender will not say";
  if (f.value === null || f.value === undefined) return "Not set";
  return String(f.value);
}

/** A setting's control: the value as it is, an editor and Apply, or the lock when something else owns it. */
function FieldRow({ device, f, canManage, canWeaken, reload }: { device: Device; f: PrefField; canManage: boolean; canWeaken: boolean; reload: () => void }) {
  const toast = useToast();
  const rule = FIELD_RULES[f.name];
  const [draft, setDraft] = useState(String(f.value ?? ""));
  const [confirming, setConfirming] = useState(false);
  if (!rule || !f.supported) return null;
  const value = rule.kind === "bool" ? draft === "true" || draft === "True" ? "true" : "false" : draft;
  const lowers = weakens(f.name, value);
  const locked = f.managedBy !== null && f.managedBy !== "unknown_owner";
  const changed = String(f.value ?? "").toLowerCase() !== value.toLowerCase();
  const allowed = lowers ? canWeaken : canManage;
  const apply = async () => {
    const action = lowers ? "preferences_weaken" : "preferences_set";
    const { data } = await runAction<Change>(device.id, action, { field: f.name, value }, lowers ? `defender.preferences_weaken:${f.name}` : undefined);
    const m = appliedMessage(data);
    if (m.ok) toast.success(`${humanize(f.name)} changed.`);
    else toast.error(m.text);
    reload();
  };
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2">
      <span className="min-w-56 flex-1 text-sm">{humanize(f.name)}</span>
      <span className="w-40 text-sm text-muted">{display(f)}</span>
      <Managed by={f.managedBy} />
      {!locked && canManage && (
        <span className="flex items-center gap-2">
          {rule.kind === "bool" && (
            <Select aria-label={`${humanize(f.name)} value`} value={value} onChange={(e) => setDraft(e.target.value)} className="w-24">
              <option value="true">true</option>
              <option value="false">false</option>
            </Select>
          )}
          {rule.kind === "enum" && (
            <Select aria-label={`${humanize(f.name)} value`} value={draft} onChange={(e) => setDraft(e.target.value)} className="w-40">
              {!rule.values?.includes(draft) && <option value={draft}>{draft || "—"}</option>}
              {rule.values?.map((v) => (
                <option key={v}>{v}</option>
              ))}
            </Select>
          )}
          {(rule.kind === "int" || rule.kind === "minutes") && (
            <Input
              aria-label={`${humanize(f.name)} value`}
              type="number"
              min={rule.min}
              max={rule.max}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              className="w-24"
            />
          )}
          <Button size="sm" disabled={!changed || !allowed} onClick={() => (lowers ? setConfirming(true) : void apply().catch((e: Error) => toast.error(e.message)))}>
            Apply
          </Button>
          {lowers && !canWeaken && <Badge tone="warn">Needs a Site Administrator</Badge>}
        </span>
      )}
      <ConfirmChange
        open={confirming}
        onClose={() => setConfirming(false)}
        title={`Lower protection: ${humanize(f.name)}`}
        confirmLabel="Lower protection"
        danger
        effect={
          <p>
            Setting <strong>{humanize(f.name)}</strong> to <strong>{value}</strong> lowers this computer's protection. It needs your second factor, and it is
            recorded in the audit log.
          </p>
        }
        run={apply}
      />
    </li>
  );
}

/** The protection settings (Get-MpPreference), grouped; a lock where Group Policy, Intune or Tamper Protection owns one. */
export function ProtectionPanel({ device, canManage, canWeaken }: { device: Device; canManage: boolean; canWeaken: boolean }) {
  const read = useRead<DefenderPreferences>(device.id, "preferences_read");
  return (
    <ReadPanel title="Protection settings" read={read} readLabel="Read settings">
      {(d) => {
        const groups = Object.keys(GROUP_LABEL).filter((g) => d.fields.some((f) => f.group === g && f.supported));
        return (
          <>
            {d.tamperProtected && <Alert tone="info">Tamper Protection is on: it blocks changes to protected settings and exclusions. {TAMPER_NOTE}</Alert>}
            {groups.map((g) => (
              <section key={g} aria-label={GROUP_LABEL[g]}>
                <h4 className="text-sm font-semibold">{GROUP_LABEL[g]}</h4>
                <ul className="divide-y divide-border">
                  {d.fields
                    .filter((f) => f.group === g)
                    .map((f) => (
                      <FieldRow key={f.name} device={device} f={f} canManage={canManage} canWeaken={canWeaken} reload={read.load} />
                    ))}
                </ul>
              </section>
            ))}
          </>
        );
      }}
    </ReadPanel>
  );
}
