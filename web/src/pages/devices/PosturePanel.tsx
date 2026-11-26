import { useApi } from "../../api/hooks";
import type { DevicePosture, PostureSummary } from "../../api/types";
import { Badge, Card } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { postureBadge, POSTURE_PHRASES, stateText } from "./postureText";

/** The Devices list's security column (ADR-0082): the score and the word, or a dash where posture does not cover the device. */
export function PostureCell({ posture }: { posture: PostureSummary | null }) {
  if (!posture) {
    return (
      <span className="text-muted" title="Security posture covers Windows and Linux devices with the EasyRMM agent.">
        —
      </span>
    );
  }
  const b = postureBadge(posture);
  return (
    <>
      <Badge tone={b.tone} title={b.title} className="tabular-nums">
        {b.label}
      </Badge>
      {posture.checkedAt && (
        <span className="block text-xs text-muted" title={formatDateTime(posture.checkedAt)}>
          {formatRelative(posture.checkedAt)}
        </span>
      )}
    </>
  );
}

/**
 * A device's security posture with its reasons: the controls that do not meet, then the ones that cannot be told,
 * heaviest first. Hardening, patching and compliance results are judged by the same rules (ADR-0082).
 */
export function PosturePanel({ deviceId }: { deviceId: string }) {
  // A check finishing moves the posture; the card follows within seconds, as the Hardening tab beside it does.
  const q = useApi<DevicePosture>(`/devices/${deviceId}/posture`, undefined, { refetchInterval: 10_000 });
  const p = q.data?.posture;
  if (!q.data || !p) return null;
  const b = postureBadge(p);
  return (
    <Card className="mb-4" title="Security posture">
      <div className="flex flex-wrap items-center gap-3">
        <Badge tone={b.tone} title={b.title} className="tabular-nums">
          {b.label}
        </Badge>
        <span className="text-sm">{POSTURE_PHRASES[p.word]}</span>
        {p.checkedAt && (
          <span className="text-xs text-muted" title={formatDateTime(p.checkedAt)}>
            Newest result {formatRelative(p.checkedAt)}
          </span>
        )}
      </div>
      <p className="mt-1 text-xs text-muted">
        The score is the weight of the controls in place over the weight of those that apply. A result that is unknown or older than the
        organization&apos;s freshness window counts as not passing.
      </p>
      {p.reasons.length === 0 ? (
        <p className="mt-3 text-sm text-muted">Every control that applies is in place.</p>
      ) : (
        <ul className="mt-3 divide-y divide-border text-sm">
          {p.reasons.map((r) => (
            <li key={r.controlId} className="flex flex-wrap items-baseline gap-x-3 py-1.5">
              <span className="font-medium">{r.label}</span>
              <Badge tone={r.word === "does not meet" ? "danger" : "warn"}>{r.word === "does not meet" ? "Does not meet" : "Cannot tell"}</Badge>
              <span className="text-muted">{stateText(r.state)}</span>
              {r.detail && <span className="text-muted">{r.detail}</span>}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
