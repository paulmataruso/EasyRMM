import type { AssessmentDetail } from "../../../api/types";
import { Alert, Badge, StatTile } from "../../../components/ui";
import { GATE_WORDS, NOT_POSTED } from "./cmmcText";

/**
 * The SPRS score range (ADR-0078, section 12). The lower bound counts every requirement not yet assessed as failing, the
 * upper bound as passing, and a single number is shown only when they are equal. The gate is the Level 2 conditional-status
 * rule read both ways: it is a reading, not a status, and EasyRMM grants nothing.
 */
export function ScoreCard({ detail }: { detail: AssessmentDetail }) {
  const { score, gate } = detail;
  const g = GATE_WORDS[gate.outcome];
  return (
    <div className="mt-3 flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {score.number !== null ? (
          <StatTile label="Score" value={score.number} hint="Every requirement is assessed" />
        ) : (
          <>
            <StatTile label="Score if unassessed fail" value={score.low} hint="Lower bound" />
            <StatTile label="Score if unassessed pass" value={score.high} hint="Upper bound" />
          </>
        )}
        <StatTile label="Met or not applicable" value={score.met} />
        <StatTile label="Not met" value={score.notMet} />
        <StatTile label="Not assessed" value={score.unassessed} hint={score.number === null ? "No single number is shown until none are left" : undefined} />
      </div>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-muted">
          Reading of the plan-of-action rule (a score of at least {gate.minScore}, no item above one point except the encryption exception, none of the six that are barred):
        </span>
        <Badge tone={g.tone}>{g.label}</Badge>
        <span className="text-muted">
          Level 1 practices met: {score.l1Met} of {score.l1Of}
        </span>
      </div>
      {gate.low.blockers.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">
            {gate.low.blockers.length} requirement(s) could not be on a plan of action if they fail
          </summary>
          <ul className="mt-1 list-disc pl-5">
            {gate.low.blockers.map((b) => (
              <li key={b.reqId}>
                <span className="font-mono text-xs">{b.reqId}</span> {b.reason}
              </li>
            ))}
          </ul>
        </details>
      )}
      {gate.overdue.length > 0 && <Alert tone="warn">Open plan of action items past their 180 days: {gate.overdue.join(", ")}.</Alert>}
      {score.sspMissing && (
        <Alert tone="warn">
          The system security plan requirement is not met. Without a plan the methodology cannot complete an assessment, whatever the number says.
        </Alert>
      )}
      <p className="text-xs text-muted">
        {detail.note} {NOT_POSTED}
      </p>
    </div>
  );
}
