import type { FixState, FixTier, RequirementStatus } from "../../api/types";

// The words of the compliance screens (ADR-0078, section 9). A result says a control "meets", "does not meet" or
// "cannot tell"; a requirement says what could be checked. The console never says "compliant" or "certified", and shows
// no text of a restricted benchmark: only our own titles and the ids a framework gives its own requirements.

export type Tone = "ok" | "warn" | "danger" | "info" | "neutral";

export const RESULT_WORDS: Record<string, { label: string; tone: Tone }> = {
  meets: { label: "Meets", tone: "ok" },
  "does not meet": { label: "Does not meet", tone: "danger" },
  "cannot tell": { label: "Cannot tell", tone: "neutral" },
};

export const REQUIREMENT_STATUS: Record<RequirementStatus, { label: string; tone: Tone }> = {
  checked_meets: { label: "Checked: all in-scope computers meet", tone: "ok" },
  checked_not_meets: { label: "Checked: does not meet", tone: "danger" },
  not_assessed: { label: "Not assessed", tone: "neutral" },
  not_applicable: { label: "Not applicable", tone: "neutral" },
};

export const FIX_STATES: Record<FixState, { label: string; tone: Tone; title: string }> = {
  open: { label: "Waiting", tone: "warn", title: "Nobody has agreed to the fix yet." },
  awaiting_approval: { label: "Waiting for approval", tone: "info", title: "Agreed to, and waiting for a second person to approve." },
  applying: { label: "Applying", tone: "info", title: "The change is being made on the computer." },
  applied: { label: "Applied, checking", tone: "info", title: "The computer made the change. The control is being checked again." },
  verified: { label: "Applied and verified", tone: "ok", title: "The check after the change found the control meets." },
  not_verified: { label: "Applied, not verified", tone: "warn", title: "The check after the change could not say, or found the control still does not meet." },
  failed: { label: "Failed", tone: "danger", title: "The change did not stand, and the old value was put back." },
  undoing: { label: "Undoing", tone: "info", title: "The change is being put back." },
  undone: { label: "Undone", tone: "neutral", title: "The change was put back." },
  declined: { label: "Set aside", tone: "neutral", title: "Accepted as a risk or deferred, with a reason." },
  resolved: { label: "Meets now", tone: "ok", title: "The control meets without a fix from here." },
};

export const TIERS: Record<FixTier, { label: string; tone: Tone; title: string }> = {
  T1: { label: "Safe", tone: "ok", title: "Reversible, with no effect on services." },
  T2: { label: "Can break a workflow", tone: "warn", title: "Can break a workflow or someone's access." },
  T3: { label: "Can cut access", tone: "danger", title: "Can lock people out, lose data, or cannot be undone from here." },
};

/** Whether a set of items may be agreed to in one dialog (section 6): safe ones together; one control of tier 2 on several computers; tier 3 alone. */
export function bulkProblem(items: { tier: FixTier; controlId: string }[]): string | null {
  if (items.length <= 1) return null;
  const tiers = new Set(items.map((i) => i.tier));
  if (tiers.size > 1) return "Choose items of one tier: each tier is agreed to in its own way.";
  const tier = items[0]!.tier;
  if (tier === "T3") return "A change that can cut access is made on one computer at a time.";
  if (tier === "T2" && new Set(items.map((i) => i.controlId)).size > 1) return "A change that can break a workflow is made for one control at a time; it may cover several computers.";
  return null;
}

/** An observed or expected value as text. */
export function valueText(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (typeof o.value === "string") return o.value;
    if (typeof o.want === "string") return o.want;
    if (typeof o.state === "string") return o.state.replace(/_/g, " ");
  }
  return "";
}
