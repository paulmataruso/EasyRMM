import { useState } from "react";
import type { Device } from "../../../api/types";
import { useToast } from "../../../components/Toast";
import { Alert, Button, Card, Input } from "../../../components/ui";
import { failureText } from "./shared";
import type { ScanDone, SignaturesUpdated } from "./types";
import { runAction } from "./winmod";

/** Quick, full and custom scans, cancelling one, and updating signatures. A scan holds a job slot until it ends. */
export function ScansPanel({ device }: { device: Device }) {
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const [path, setPath] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const go = async (label: string, action: string, params: Record<string, unknown>, done: (d: never) => string) => {
    setBusy(label);
    setNote(null);
    try {
      const { data } = await runAction(device.id, action, params);
      const text = done(data as never);
      setNote(text);
      toast.success(text);
    } catch (e) {
      toast.error(failureText(e));
    } finally {
      setBusy(null);
    }
  };
  return (
    <Card title="Scans and updates">
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted">
          A scan runs on the computer until it ends; Defender throttles it. A scan job holds one of the agent's job slots meanwhile. Scheduled scans are a setting under
          Protection settings, and Defender ignores them while it is in passive mode.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <Button loading={busy === "quick"} disabled={busy !== null} onClick={() => void go("quick", "scan_quick", {}, (d: ScanDone) => `The quick scan finished (${d.finishedAt}).`)}>
            Quick scan
          </Button>
          <Button loading={busy === "full"} disabled={busy !== null} onClick={() => void go("full", "scan_full", {}, (d: ScanDone) => `The full scan finished (${d.finishedAt}).`)}>
            Full scan
          </Button>
          <Button
            loading={busy === "update"}
            disabled={busy !== null}
            onClick={() => void go("update", "signatures_update", {}, (d: SignaturesUpdated) => (d.updated ? `Signatures updated to ${d.after}.` : "Signatures were already current."))}
          >
            Update signatures
          </Button>
          <Button disabled={busy === null} onClick={() => void runAction(device.id, "scan_cancel", {}).then(() => toast.success("The scan was asked to stop."), (e) => toast.error(failureText(e)))}>
            Cancel the running scan
          </Button>
        </div>
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void go("custom", "scan_custom", { path: path.trim() }, (d: ScanDone) => `The scan of ${path.trim()} finished (${d.finishedAt}).`);
          }}
        >
          <Input aria-label="Path to scan" placeholder="D:\Folder or \\server\share" value={path} onChange={(e) => setPath(e.target.value)} className="max-w-md" />
          <Button type="submit" disabled={busy !== null || !path.trim()} loading={busy === "custom"}>
            Scan this path
          </Button>
        </form>
        {note && <Alert tone="info">{note}</Alert>}
      </div>
    </Card>
  );
}
