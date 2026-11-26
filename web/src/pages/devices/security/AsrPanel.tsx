import { useState } from "react";
import type { Device } from "../../../api/types";
import { useToast } from "../../../components/Toast";
import { Badge, Button, Select } from "../../../components/ui";
import { ConfirmChange, Managed, ReadPanel, appliedMessage } from "./shared";
import { ASR_MODES, ASR_RULES, asrWeakens } from "./text";
import type { AsrRead, AsrRuleState, Change } from "./types";
import { runAction, useRead } from "./winmod";

function RuleRow({ device, r, canManage, canWeaken, reload }: { device: Device; r: AsrRuleState; canManage: boolean; canWeaken: boolean; reload: () => void }) {
  const toast = useToast();
  const [mode, setMode] = useState(r.mode === "Not configured" ? "Enabled" : r.mode);
  const [confirming, setConfirming] = useState(false);
  const lowers = asrWeakens(mode);
  const locked = r.managedBy !== null && r.managedBy !== "unknown_owner";
  const apply = async () => {
    const { data } = await runAction<Change>(device.id, lowers ? "asr_weaken" : "asr_set", { id: r.id, mode }, lowers ? `defender.asr_weaken:${r.id}` : undefined);
    const m = appliedMessage(data);
    if (m.ok) toast.success("Rule changed.");
    else toast.error(m.text);
    reload();
  };
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2">
      <span className="min-w-64 flex-1 text-sm">
        {r.known ? r.name : <Badge tone="warn">Unrecognized rule</Badge>}
        <span className="ml-2 font-mono text-xs text-muted">{r.id}</span>
      </span>
      <span className="w-24 text-sm text-muted">{r.mode}</span>
      <Managed by={r.managedBy} />
      {r.known && !locked && canManage && (
        <span className="flex items-center gap-2">
          <Select aria-label={`${r.name} mode`} value={mode} onChange={(e) => setMode(e.target.value)} className="w-32">
            {ASR_MODES.map((m) => (
              <option key={m}>{m}</option>
            ))}
          </Select>
          <Button size="sm" disabled={mode === r.mode || (lowers && !canWeaken)} onClick={() => (lowers ? setConfirming(true) : void apply().catch((e: Error) => toast.error(e.message)))}>
            Apply
          </Button>
        </span>
      )}
      <ConfirmChange
        open={confirming}
        onClose={() => setConfirming(false)}
        title="Lower protection"
        confirmLabel="Lower protection"
        danger
        effect={
          <p>
            Setting the rule <strong>{r.name}</strong> to <strong>{mode}</strong> stops it blocking. This needs your second factor and is recorded in the audit log.
          </p>
        }
        run={apply}
      />
    </li>
  );
}

/** The Attack Surface Reduction rules and their modes. Turning one on first checks that EasyRMM's own folders are excluded. */
export function AsrPanel({ device, canManage, canWeaken }: { device: Device; canManage: boolean; canWeaken: boolean }) {
  const read = useRead<AsrRead>(device.id, "asr_read");
  return (
    <ReadPanel title="Attack Surface Reduction" read={read} readLabel="Read rules">
      {(d) =>
        !d.supported ? (
          <p className="text-sm text-muted">This computer does not support Attack Surface Reduction rules.</p>
        ) : (
          <ul className="divide-y divide-border">
            {[
              ...d.rules,
              ...ASR_RULES.filter((c) => !d.rules.some((r) => r.id === c.id)).map(
                (c): AsrRuleState => ({ id: c.id, name: c.name, known: true, mode: "Not configured", managedBy: null }),
              ),
            ].map((r) => (
              <RuleRow key={r.id} device={device} r={r} canManage={canManage} canWeaken={canWeaken} reload={read.load} />
            ))}
          </ul>
        )
      }
    </ReadPanel>
  );
}
