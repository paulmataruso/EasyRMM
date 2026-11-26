import type { AssessmentState, Determination } from "../../../api/types";

// The words of the CMMC workspace (ADR-0078, sections 9 and 12). A requirement is met, not met, not applicable or not
// assessed; the screens never say "compliant" or "certified", never post a score anywhere, and call the workspace an aid.

export type Tone = "ok" | "warn" | "danger" | "info" | "neutral";

export const STATE_WORDS: Record<AssessmentState, { label: string; tone: Tone; hint: string }> = {
  draft: { label: "Draft", tone: "info", hint: "Can be changed." },
  in_review: { label: "In review", tone: "warn", hint: "Waiting for approval. Send it back to draft to change it." },
  approved: { label: "Approved", tone: "ok", hint: "Frozen. A new draft is made from it to change anything." },
  archived: { label: "Archived", tone: "neutral", hint: "Frozen and set aside." },
};

export const DETERMINATION_WORDS: Record<Determination, { label: string; tone: Tone }> = {
  met: { label: "Met", tone: "ok" },
  not_met: { label: "Not met", tone: "danger" },
  not_applicable: { label: "Not applicable", tone: "neutral" },
  not_assessed: { label: "Not assessed", tone: "warn" },
};

export const ORIGIN_WORDS: Record<string, string> = { scan: "From a scan", attested: "Attested or shown by evidence", manual: "A person's own call" };

export const SOURCE_WORDS: Record<string, string> = { scan: "Scan", attestation: "Attestation", upload: "Evidence", interview: "Interview" };

export const CATEGORIES: { id: string; label: string }[] = [
  { id: "cui", label: "Holds or handles controlled information" },
  { id: "security_protection", label: "Protects the systems that do" },
  { id: "contractor_risk_managed", label: "Managed by our own risk decision" },
  { id: "specialized", label: "Specialized equipment" },
  { id: "out_of_scope", label: "Out of scope" },
];

export const POAM_STATUS: Record<string, { label: string; tone: Tone }> = {
  draft: { label: "Draft", tone: "info" },
  open: { label: "Open", tone: "warn" },
  in_progress: { label: "In progress", tone: "warn" },
  closed: { label: "Closed", tone: "ok" },
  accepted: { label: "Accepted", tone: "neutral" },
};

export const RESPONSIBILITY: Record<string, string> = { customer: "Customer", msp: "MSP", inherited: "Inherited", shared: "Shared" };

export const GATE_WORDS: Record<string, { label: string; tone: Tone }> = {
  within: { label: "Within the rule", tone: "ok" },
  possible: { label: "Possible, if the unassessed requirements are met", tone: "warn" },
  outside: { label: "Outside the rule", tone: "danger" },
};

export const EXPORTS: { format: string; label: string; hint: string }[] = [
  { format: "bundle", label: "Everything (ZIP)", hint: "The plan, the plan of action, the CSV files, the PDF and a list of each file's SHA-256." },
  { format: "pdf", label: "Report (PDF)", hint: "Score range, scope, requirements, plan of action and the system security plan." },
  { format: "oscal-ssp", label: "System security plan (OSCAL JSON)", hint: "NIST OSCAL 1.1.2." },
  { format: "oscal-poam", label: "Plan of action (OSCAL JSON)", hint: "NIST OSCAL 1.1.2. Needs at least one item." },
  { format: "requirements-csv", label: "Requirements (CSV)", hint: "One row per requirement." },
  { format: "poam-csv", label: "Plan of action (CSV)", hint: "One row per item." },
];

export const NOT_POSTED = "EasyRMM never posts a score to SPRS. A person does that, after their own review.";
export const POAM_NOTE =
  "A plan of action does not make a requirement met: until it is implemented it scores as not met. Each item must be closed within 180 days.";

/** Bytes, for an evidence file. */
export function bytes(n: number | null): string {
  if (n === null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}
