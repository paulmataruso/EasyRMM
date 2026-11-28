import { Link } from "react-router";
import type { AgentSettingsDocument, Device } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Alert, Badge, Card, type Tone } from "../../components/ui";
import { formatRelative } from "../../lib/format";
import { AgentSettingsPanel } from "./AgentSettingsPanel";

/** The line and tone the console shows for a device's settings document (ADR-0058, slice 3). */
export function documentLine(doc: AgentSettingsDocument): { tone: Tone; text: string } {
  switch (doc.state) {
    case "applied":
      return { tone: "ok", text: `Applied ${formatRelative(doc.appliedAt)} (version ${doc.version})` };
    case "waiting":
      return { tone: "warn", text: "Waiting for the device: it is offline" };
    case "pending":
      return { tone: "warn", text: `Waiting for the device to confirm version ${doc.version}` };
    case "not_applied":
      return { tone: "danger", text: `Not applied (${doc.notAppliedHeartbeats} heartbeats since it was issued)` };
    case "unsupported":
      return { tone: "neutral", text: "This agent's version does not take settings" };
    case "none":
      return { tone: "neutral", text: "Nothing has been sent to this device yet" };
  }
}

function DocumentStatus({ doc }: { doc: AgentSettingsDocument }) {
  const line = documentLine(doc);
  const problems = Object.entries(doc.problems);
  return (
    <Card title="Settings on this device">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge tone={line.tone}>{line.text}</Badge>
        {doc.state === "unsupported" && (
          <Link to="/settings?tab=agent-updates" className="text-accent hover:underline">
            Update the agent
          </Link>
        )}
      </div>
      {doc.state === "not_applied" && (
        <Alert tone="danger" className="mt-3">
          The agent keeps checking in without confirming the settings sent to it. It may be running something older than it says, or refusing a value.
        </Alert>
      )}
      {problems.length > 0 && (
        <ul className="mt-3 list-disc pl-5 text-sm text-muted">
          {problems.map(([k, v]) => (
            <li key={k}>
              <code>{k}</code>: {v}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** The "Settings" tab of a device with the EasyRMM agent: how its settings document stands, and each key's value and editor. */
export function DeviceSettingsTab({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const configure = canAt("device.configure", { organizationId: device.organizationId, siteId: device.siteId });
  return (
    <AgentSettingsPanel
      base={`/devices/${device.id}/agent-settings`}
      scope="device"
      editable={configure}
      header={(l) => (l.document ? <DocumentStatus doc={l.document} /> : null)}
    />
  );
}
