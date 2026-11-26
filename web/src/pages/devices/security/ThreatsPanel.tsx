import { useState } from "react";
import type { Device } from "../../../api/types";
import { useToast } from "../../../components/Toast";
import { Badge, Button } from "../../../components/ui";
import { formatDateTime } from "../../../lib/format";
import { ConfirmChange, ReadPanel } from "./shared";
import { SEVERITY_TEXT } from "./text";
import type { QuarantineRead, ThreatsRead } from "./types";
import { runAction, useRead } from "./winmod";

/** Threats Defender knows (no file paths), removing the active ones, and the quarantine with restore. */
export function ThreatsPanel({ device, canManage, canWeaken, canSeeSensitive }: { device: Device; canManage: boolean; canWeaken: boolean; canSeeSensitive: boolean }) {
  const toast = useToast();
  const threats = useRead<ThreatsRead>(device.id, "threats_read");
  const quarantine = useRead<QuarantineRead>(device.id, "quarantine_read");
  const [removing, setRemoving] = useState(false);
  const [restoring, setRestoring] = useState<string | null>(null);
  return (
    <>
      <ReadPanel title="Threats" read={threats}>
        {(d) => (
          <>
            {d.threats.length === 0 ? (
              <p className="text-sm text-muted">Defender knows no threats on this computer.</p>
            ) : (
              <ul className="divide-y divide-border">
                {d.threats.map((t) => (
                  <li key={t.id} className="flex flex-wrap items-center gap-3 py-1.5 text-sm">
                    <span className="min-w-0 flex-1">{t.name}</span>
                    {t.severity !== null && <Badge tone={t.severity >= 4 ? "danger" : "warn"}>{SEVERITY_TEXT[t.severity] ?? `Severity ${t.severity}`}</Badge>}
                    <Badge tone={t.active ? "danger" : "neutral"}>{t.active ? "Active" : "Handled"}</Badge>
                    {t.detectedAt && <span className="text-xs text-muted">{formatDateTime(t.detectedAt)}</span>}
                  </li>
                ))}
              </ul>
            )}
            {canManage && d.threats.some((t) => t.active) && (
              <div>
                <Button size="sm" variant="danger" onClick={() => setRemoving(true)}>
                  Remove active threats
                </Button>
              </div>
            )}
          </>
        )}
      </ReadPanel>
      <ConfirmChange
        open={removing}
        onClose={() => setRemoving(false)}
        title="Remove active threats"
        confirmLabel="Remove threats"
        effect={<p>Defender will remove every active threat it knows on this computer, which can delete or quarantine files.</p>}
        run={async () => {
          await runAction(device.id, "threats_remove", { device: device.name }, `defender.threats_remove:${device.name}`);
          toast.success("Defender removed the active threats.");
          threats.load();
        }}
      />
      {canSeeSensitive && (
        <ReadPanel title="Quarantine" read={quarantine}>
          {(d) =>
            d.items.length === 0 ? (
              <p className="text-sm text-muted">Nothing is in quarantine.</p>
            ) : (
              <ul className="divide-y divide-border">
                {d.items.map((i, n) => (
                  <li key={`${i.name}-${n}`} className="flex flex-wrap items-center gap-3 py-1.5 text-sm">
                    <span className="min-w-0 flex-1">
                      {i.name}
                      <span className="ml-2 break-all font-mono text-xs text-muted">{i.path}</span>
                    </span>
                    {canWeaken && (
                      <Button size="sm" variant="danger-ghost" onClick={() => setRestoring(i.name)}>
                        Restore
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </ReadPanel>
      )}
      <ConfirmChange
        open={restoring !== null}
        onClose={() => setRestoring(null)}
        title="Restore a quarantined item"
        confirmLabel="Restore"
        danger
        effect={
          <p>
            Restoring <strong>{restoring}</strong> puts the file back where Defender found it, and Defender will detect it again. Only do this for a file you know is safe.
            It needs your second factor.
          </p>
        }
        run={async () => {
          if (!restoring) return;
          await runAction(device.id, "quarantine_restore", { name: restoring }, `defender.quarantine_restore:${restoring}`);
          toast.success("Restored to its original location.");
          quarantine.load();
        }}
      />
    </>
  );
}
