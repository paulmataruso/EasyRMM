// A Windows device's Microsoft Defender exclusions and the hashes of what is installed on it (ADR-0070).
import { useApi } from "../../api/hooks";
import type { DefenderKindName, DefenderState, DeviceDefender, InstalledStatus } from "../../api/types";
import { Badge, Card, ErrorState, KeyValueList, Mono, Spinner, TableWrap, type Tone } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { HashCell, SOURCE_NAMES } from "../settings/AgentFilesTab";

export const STATE_WORDS: Record<DefenderState, { label: string; tone: Tone }> = {
  effective: { label: "Working", tone: "ok" },
  present_not_effective: { label: "Listed, not in effect", tone: "warn" },
  not_locked: { label: "A folder is not locked down", tone: "danger" },
  refused: { label: "Defender refused", tone: "danger" },
  unavailable: { label: "Cannot be read", tone: "warn" },
  not_applicable: { label: "Not applicable", tone: "neutral" },
  not_needed: { label: "Not needed", tone: "neutral" },
};

export const KIND_NAMES: Record<DefenderKindName, string> = {
  path: "Folders",
  process: "Programs",
  asr: "Attack Surface Reduction",
  cfa: "Controlled Folder Access",
};

export const FILE_STATUS: Record<InstalledStatus, { label: string; tone: Tone }> = {
  match: { label: "Matches the list", tone: "ok" },
  mismatch: { label: "Differs from the list", tone: "danger" },
  not_current: { label: "Not the current build", tone: "warn" },
  no_expected: { label: "No expected value", tone: "neutral" },
};

/** The Defender and installed-file cards of a Windows device's page. Nothing is shown for a device that never reported. */
export function DefenderPanel({ deviceId }: { deviceId: string }) {
  const q = useApi<DeviceDefender>(`/devices/${deviceId}/defender`, undefined, { refetchInterval: 60_000 });
  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />;
  const { defender, defenderAt, installed } = q.data;
  if (!defender && !installed) return null;
  return (
    <>
      {defender && (
        <Card title="Microsoft Defender exclusions">
          <KeyValueList
            items={[
              [
                "Status",
                <span key="s">
                  <Badge tone={STATE_WORDS[defender.state].tone}>{STATE_WORDS[defender.state].label}</Badge>
                  {defender.reason && <span className="mt-1 block text-xs text-muted">{defender.reason}</span>}
                </span>,
              ],
              ...(defender.kinds.length > 0
                ? [
                    [
                      "Kinds",
                      <ul key="k" className="space-y-1">
                        {defender.kinds.map((k) => (
                          <li key={k.kind}>
                            <span aria-label={`${KIND_NAMES[k.kind]}: ${STATE_WORDS[k.state].label}`}>
                              <span aria-hidden>{k.state === "effective" ? "✓" : k.state === "not_needed" ? "–" : "✗"} </span>
                              {KIND_NAMES[k.kind]}
                            </span>
                            {k.reason && <span className="block text-xs text-muted">{k.reason}</span>}
                          </li>
                        ))}
                      </ul>,
                    ] as [string, React.ReactNode],
                  ]
                : []),
              ...(defender.folders.length > 0
                ? [
                    [
                      "Folders",
                      <ul key="f" className="space-y-1">
                        {defender.folders.map((f) => (
                          <li key={f.path}>
                            <span aria-label={`${f.path}: ${f.reason ? "not excluded" : f.listed ? "excluded" : "not listed"}`}>
                              <span aria-hidden>{f.listed && !f.reason ? "✓" : "✗"} </span>
                              <Mono>{f.path}</Mono>
                            </span>
                            {f.reason && <span className="block text-xs text-muted">{f.reason}</span>}
                          </li>
                        ))}
                      </ul>,
                    ] as [string, React.ReactNode],
                  ]
                : []),
              ["Reported", <span key="r" title={formatDateTime(defenderAt)}>{formatRelative(defenderAt)}</span>],
            ]}
          />
          <p className="mt-3 text-xs text-muted">
            Reported by the device. Exclusions are added only to folders locked down to SYSTEM and Administrators, and removed when the agent is uninstalled.
          </p>
        </Card>
      )}
      {installed && (
        <Card title="Installed files" padded={false}>
          <div className="space-y-1 p-4 pb-3 text-sm text-muted">
            <p>
              <strong className="font-medium text-fg">Reported by the device</strong>{" "}
              {installed.observedAt ? <span title={formatDateTime(installed.observedAt)}>{formatRelative(installed.observedAt)}</span> : null}. Shown next to what this
              server expects for the version the device reports; nothing is acted on.
            </p>
            <p>
              EasyRMM agent {installed.agentVersion || "—"}
              {installed.meshAgentVersion ? `, MeshAgent ${installed.meshAgentVersion}` : ""}
              {installed.patchAgentVersion ? `, EasyPatch agent ${installed.patchAgentVersion}` : ""}
            </p>
            {installed.patchNote && <p>{installed.patchNote}</p>}
          </div>
          <TableWrap className="rounded-none border-x-0 border-b-0">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface-2 text-xs text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">File</th>
                  <th className="px-4 py-2 font-medium">SHA-256 on the device</th>
                  <th className="px-4 py-2 font-medium">Expected</th>
                  <th className="px-4 py-2 font-medium">Result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {installed.files.map((f) => (
                  <tr key={`${f.program}/${f.name}`}>
                    <td className="px-4 py-2 align-top">
                      <Mono>{f.name}</Mono>
                    </td>
                    <td className="px-4 py-2 align-top">
                      <HashCell value={f.sha256} />
                    </td>
                    <td className="px-4 py-2 align-top">
                      {f.expected ? (
                        <>
                          <HashCell value={f.expected.sha256} />
                          <span className="block text-xs text-muted">
                            {SOURCE_NAMES[f.expected.source]}, {formatDateTime(f.expected.computedAt)}
                          </span>
                          {f.expected.stale && <Badge tone="warn">Stale</Badge>}
                        </>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2 align-top">
                      <Badge tone={FILE_STATUS[f.status].tone}>{FILE_STATUS[f.status].label}</Badge>
                    </td>
                  </tr>
                ))}
                {installed.missing.map((m) => (
                  <tr key={`missing/${m.name}`}>
                    <td className="px-4 py-2 align-top">
                      <Mono>{m.name}</Mono>
                    </td>
                    <td className="px-4 py-2 align-top text-muted">Not reported</td>
                    <td className="px-4 py-2 align-top">
                      <HashCell value={m.expected.sha256} />
                    </td>
                    <td className="px-4 py-2 align-top">
                      <Badge tone="danger">Missing</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </Card>
      )}
    </>
  );
}
