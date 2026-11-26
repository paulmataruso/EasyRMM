// Words for a device's security posture (ADR-0082). Posture shares the compliance engine's words, so a computer
// "meets", "does not meet" or "cannot be told" whether the control is hardening, patching or a compliance check.
// The console never says "compliant" of a computer (ADR-0054, ADR-0078 section 9).
import type { PostureSummary, PostureWord } from "../../api/types";
import type { Tone } from "../../components/ui";

export const POSTURE_PHRASES: Record<PostureWord, string> = {
  meets: "Meets its security policy",
  "does not meet": "Does not meet its security policy",
  "cannot tell": "Cannot tell whether it meets its security policy",
};

/** The Devices list's security filter. */
export const POSTURE_FILTERS: { value: string; label: string }[] = [
  { value: "does_not_meet", label: "Does not meet" },
  { value: "cannot_tell", label: "Cannot tell" },
  { value: "meets", label: "Meets" },
];

/** A device's posture in a few words for a list cell: the score when there is one, with the word as the badge's tone. */
export function postureBadge(p: Pick<PostureSummary, "word" | "percent" | "failing" | "cannotTell">): { label: string; tone: Tone; title: string } {
  const tone: Tone = p.word === "meets" ? "ok" : p.word === "does not meet" ? "danger" : "warn";
  const parts: string[] = [POSTURE_PHRASES[p.word]];
  if (p.failing > 0) parts.push(`${p.failing.toLocaleString()} ${p.failing === 1 ? "control does" : "controls do"} not meet it`);
  if (p.cannotTell > 0) parts.push(`${p.cannotTell.toLocaleString()} ${p.cannotTell === 1 ? "control" : "controls"} cannot be told (unknown or stale, which never count as passing)`);
  const label = p.percent === null ? "Cannot tell" : `${p.percent}%`;
  return { label: p.word === "cannot tell" && p.percent !== null ? `${p.percent}% · cannot tell` : label, tone, title: parts.join(". ") + "." };
}

/** What a control's state means in the reasons list. */
export function stateText(state: string): string {
  switch (state) {
    case "stale":
      return "Result too old to count";
    case "unknown":
      return "Not known";
    case "not_supported":
      return "Not supported here";
    case "not_in_place":
      return "Not in place";
    case "partly":
      return "Partly in place";
    case "half_applied":
      return "Half applied";
    case "failed":
      return "Failed";
    case "managed_elsewhere":
      return "Managed elsewhere";
    default:
      return state;
  }
}
