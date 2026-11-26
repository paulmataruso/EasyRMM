import { Alert, buttonClasses, Card } from "../../../components/ui";
import { API_BASE } from "../../../api/client";
import { EXPORTS, NOT_POSTED } from "./cmmcText";

/** The exports. Each is recorded in the audit log with its SHA-256. A draft can be exported; the file says its state. */
export function ExportsPanel({ base }: { base: string }) {
  return (
    <Card title="Exports">
      <ul className="flex flex-col gap-3">
        {EXPORTS.map((e) => (
          <li key={e.format} className="flex flex-wrap items-center gap-3">
            <a className={buttonClasses(e.format === "bundle" ? "primary" : "secondary")} href={`${API_BASE}${base}/export?format=${e.format}`} download>
              {e.label}
            </a>
            <span className="text-sm text-muted">{e.hint}</span>
          </li>
        ))}
      </ul>
      <Alert tone="info" className="mt-4">
        {NOT_POSTED}
      </Alert>
    </Card>
  );
}
