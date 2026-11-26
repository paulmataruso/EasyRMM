import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AssessmentDetail, PoamBoard, RequirementDetail, RequirementRow, SspDocument } from "../../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes, type FakeRequest } from "../../../test/fakeApi";
import { org, site } from "../../../test/fixtures";
import { renderApp } from "../../../test/render";
import { bytes, DETERMINATION_WORDS, EXPORTS, GATE_WORDS, POAM_NOTE, STATE_WORDS, SOURCE_WORDS, CATEGORIES } from "./cmmcText";

// The CMMC workspace (ADR-0078, slice C5): the assessments list, the score range, the per-requirement view, attestation,
// the plan-of-action board and the wording rules.

const ASSESSMENT = {
  id: "a1",
  organizationId: "o1",
  framework: "cmmc-l2",
  frameworkVersion: "2.0",
  title: "Spring assessment",
  assessor: "",
  state: "draft" as const,
  approvedAt: null,
  supersedes: null,
  scanId: null,
  createdAt: "2026-11-26T09:00:00Z",
  updatedAt: "2026-11-26T09:00:00Z",
  frozen: false,
};

const DETAIL = (over: Partial<AssessmentDetail> = {}): AssessmentDetail => ({
  ...ASSESSMENT,
  score: { low: 40, high: 104, number: null, notMet: 2, unassessed: 30, met: 78, sspMissing: false, l1Met: 15, l1Of: 17 },
  gate: { minScore: 88, low: { score: 40, scoreOk: false, blockers: [{ reqId: "3.1.1", reason: "Its value is 5 points." }], within: false }, high: { score: 104, scoreOk: true, blockers: [], within: false }, overdue: [], outcome: "possible" },
  counts: { met: 78, not_met: 2, not_assessed: 30 },
  disclaimer: "Assessment aid. It reports what EasyRMM could check and what people have stated. It is not an assessment, an audit, a certification or legal advice.",
  note: "The score follows the DoD assessment methodology's values.",
  ...over,
});

const REQS: RequirementRow[] = [
  { reqId: "AC.L2-3.1.1", nistId: "3.1.1", title: "Authorized access only", family: "AC", class: "technical", weight: 5, status: "not_met", origin: "scan", partial: false, hasPartial: false, responsibility: "customer", ownerUser: null, nextReview: null, statement: "", objectives: 1, objectivesMet: 0, evidence: 0 },
  { reqId: "AC.L2-3.1.3", nistId: "3.1.3", title: "Control the flow", family: "AC", class: "organisational", weight: 1, status: "not_assessed", origin: "scan", partial: false, hasPartial: false, responsibility: "customer", ownerUser: null, nextReview: null, statement: "", objectives: 1, objectivesMet: 0, evidence: 1 },
  { reqId: "AT.L2-3.2.1", nistId: "3.2.1", title: "Awareness", family: "AT", class: "organisational", weight: 5, status: "met", origin: "attested", partial: false, hasPartial: false, responsibility: "customer", ownerUser: null, nextReview: null, statement: "We train.", objectives: 1, objectivesMet: 1, evidence: 0 },
];

const REQ_DETAIL: RequirementDetail = {
  ...REQS[1],
  text: "Control the flow of CUI in accordance with approved authorizations.",
  objectiveList: [{ id: "*", text: "The requirement as a whole.", methods: ["examine"], controls: [], whole: true, determination: "not_assessed", source: "", method: "", note: "", decidedAt: null, expired: false }],
  attestations: [],
  evidenceList: [{ id: "e1", kind: "upload", title: "Network diagram", mediaType: "text/plain", fileName: "d.txt", size: 2048, url: "", sha256: "ab".repeat(32), collectedAt: "2026-11-26T09:00:00Z", collector: null, expiresAt: null, supersededBy: null, expired: false }],
};

const POAM: PoamBoard = {
  note: POAM_NOTE,
  items: [
    { id: "p1", reqId: "AC.L2-3.1.1", nistId: "3.1.1", title: "Authorized access only", weakness: "Not met.", points: 5, eligible: false, eligibilityReason: "Its value is 5 points, and a plan of action item may carry at most 1.", status: "draft", openedOn: "2026-11-26", closesBy: "2027-05-25", overdue: false, resources: "", scheduledCompletion: null, milestones: [], requirementStatus: "not_met" },
    { id: "p2", reqId: "AC.L2-3.1.3", nistId: "3.1.3", title: "Control the flow", weakness: "Not met.", points: 1, eligible: true, eligibilityReason: "At most one point.", status: "draft", openedOn: "2026-11-26", closesBy: "2027-05-25", overdue: false, resources: "", scheduledCompletion: null, milestones: [], requirementStatus: "not_met" },
  ],
};

const SSP: SspDocument = {
  id: "d1",
  kind: "ssp",
  templateId: "ssp-v1",
  title: "System security plan",
  version: 1,
  exists: true,
  sections: [
    { position: 0, sectionId: "identification", heading: "System identification", body: "", generated: false, hint: "Name the system." },
    { position: 1, sectionId: "scope", heading: "Scope and boundary", body: "The scope has not been recorded yet.", generated: true, hint: "" },
  ],
};

const ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "compliance.view", "compliance.scan", "compliance.edit", "compliance.attest", "compliance.approve", "compliance.export", "compliance.fix", "compliance.fix_high", "compliance.fix_approve", "device.harden"],
});
const VIEWER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "compliance.view"] });

const A = "/organizations/:id/compliance/assessments/:aid";

function routes(session = ADMIN, detail = DETAIL(), extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    ...unreportedRoutes(),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "Northwind Traders", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /sites/:id": ok(site("s1", "o1", "Head office")),
    "GET /organizations/:id/sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /patching": ok({ configured: false }),
    "GET /audit": ok({ items: [] }),
    "GET /organizations/:id/compliance/settings": ok({ enabled: true, freshnessDays: 30, scanSchedule: null, scanProfile: null }),
    "GET /organizations/:id/compliance/summary": ok({ enabled: true, devices: 0, meets: 0, doesNotMeet: 0, cannotTell: 0, stale: 0, failingDevices: 0, lastScan: null, disclaimer: "Assessment aid." }),
    "GET /organizations/:id/compliance/fixes": ok({ items: [] }),
    "GET /organizations/:id/compliance/fix-settings": ok({ requireApproval: [] }),
    "GET /organizations/:id/compliance/packs": ok({ items: [] }),
    "GET /compliance/profiles": ok({ items: [] }),
    "GET /organizations/:id/compliance/assessments": ok({ items: [ASSESSMENT] }),
    [`GET ${A}`]: ok(detail),
    [`GET ${A}/requirements`]: ok({ items: REQS }),
    [`GET ${A}/requirements/:req`]: ok(REQ_DETAIL),
    [`GET ${A}/poam`]: ok(POAM),
    [`GET ${A}/ssp`]: ok(SSP),
    [`GET ${A}/scope`]: ok({ items: [], unlisted: 0 }),
    "GET /organizations/:id/compliance/evidence": ok({ items: REQ_DETAIL.evidenceList }),
    "GET /devices": ok({ items: [] }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

async function open(session = ADMIN, detail = DETAIL(), extra: Record<string, unknown> = {}) {
  installFakeApi(routes(session, detail, extra));
  renderApp("/organizations/o1?tab=compliance");
  const main = within(await screen.findByRole("main"));
  await userEvent.click(await main.findByRole("button", { name: "Spring assessment" }));
  return main;
}

describe("the CMMC workspace", () => {
  it("lists the assessments with their state, and starts one", async () => {
    let body: unknown;
    installFakeApi(
      routes(ADMIN, DETAIL(), {
        "POST /organizations/:id/compliance/assessments": (r: FakeRequest) => {
          body = r.body;
          return { status: 201, body: { ...ASSESSMENT, id: "a2", title: "Autumn" } };
        },
        "GET /organizations/:id/compliance/assessments/a2": ok(DETAIL({ id: "a2", title: "Autumn" })),
      }),
    );
    renderApp("/organizations/o1?tab=compliance");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByRole("button", { name: "Spring assessment" })).toBeInTheDocument();
    expect(main.getByText("Draft")).toBeInTheDocument();
    await userEvent.type(main.getByLabelText("Title for a new assessment"), "Autumn");
    await userEvent.click(main.getByRole("button", { name: "Start an assessment" }));
    await waitFor(() => expect(body).toEqual({ title: "Autumn", framework: "cmmc-l2" }));
  });

  it("shows the score as a range, with no single number while requirements are unassessed", async () => {
    const main = await open();
    expect(await main.findByText("Score if unassessed fail")).toBeInTheDocument();
    expect(main.getByText("Score if unassessed pass")).toBeInTheDocument();
    expect(main.getByText("40")).toBeInTheDocument();
    expect(main.getByText("104")).toBeInTheDocument();
    expect(main.queryByText("Score")).toBeNull();
    expect(main.getByText(GATE_WORDS.possible.label)).toBeInTheDocument();
    expect(main.getByText(/never posts a score to SPRS/)).toBeInTheDocument();
  });

  it("shows one number once nothing is left unassessed", async () => {
    const main = await open(ADMIN, DETAIL({ score: { low: 97, high: 97, number: 97, notMet: 3, unassessed: 0, met: 107, sspMissing: false, l1Met: 17, l1Of: 17 } }));
    expect(await main.findByText("Score")).toBeInTheDocument();
    expect(main.getByText("97")).toBeInTheDocument();
    expect(main.queryByText("Score if unassessed fail")).toBeNull();
  });

  it("filters the requirements and opens one with its objectives and evidence", async () => {
    const main = await open();
    const table = await main.findByRole("table", { name: "Requirements" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    await userEvent.click(main.getByRole("radio", { name: "Not met" }));
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    await userEvent.click(main.getByRole("radio", { name: "All" }));
    await userEvent.click(within(table).getByRole("button", { name: /3\.1\.3/ }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(await dialog.findByText("The requirement as a whole")).toBeInTheDocument();
    expect(dialog.getByText("Network diagram")).toBeInTheDocument();
    expect(dialog.getByRole("link", { name: "Download" })).toHaveAttribute("href", "/api/v1/organizations/o1/compliance/evidence/e1/download");
  });

  it("signs an attestation with the statement, and a viewer sees no way to attest or edit", async () => {
    let sent: unknown;
    const main = await open(ADMIN, DETAIL(), {
      [`POST ${A}/requirements/:req/attestations`]: (r: FakeRequest) => {
        sent = r.body;
        return { status: 201, body: { id: "t1" } };
      },
    });
    await userEvent.click(await main.findByRole("button", { name: /3\.1\.3/ }));
    const dialog = within(await screen.findByRole("dialog"));
    const sign = await dialog.findByRole("button", { name: "Sign the attestation" });
    expect(sign).toBeDisabled();
    await userEvent.type(dialog.getByLabelText("Your statement"), "We control the flow with firewall rules.");
    await userEvent.click(sign);
    await waitFor(() => expect(sent).toEqual({ statement: "We control the flow with firewall rules." }));
  });

  it("gives a viewer no controls to change anything", async () => {
    const main = await open(VIEWER);
    await userEvent.click(await main.findByRole("button", { name: /3\.1\.3/ }));
    const dialog = within(await screen.findByRole("dialog"));
    await dialog.findByText("The requirement as a whole");
    expect(dialog.queryByRole("button", { name: "Sign the attestation" })).toBeNull();
    expect(dialog.queryByRole("button", { name: "Save" })).toBeNull();
    expect(dialog.queryByRole("button", { name: "Mark met" })).toBeNull();
  });

  it("shows the plan of action with eligibility, and offers no Confirm for an item the rule bars", async () => {
    const main = await open();
    await userEvent.click(await main.findByRole("tab", { name: "Plan of action" }));
    expect(await main.findByText(POAM_NOTE)).toBeInTheDocument();
    const draft = within(main.getByRole("region", { name: "Draft (2)" }));
    expect(draft.getByText("Not allowed on a plan")).toBeInTheDocument();
    expect(draft.getAllByRole("button", { name: "Confirm" })).toHaveLength(1);
  });

  it("freezes the workspace when approved: a new draft is offered and nothing can be edited", async () => {
    const main = await open(ADMIN, DETAIL({ state: "approved", frozen: true, approvedAt: "2026-11-26T10:00:00Z" }));
    expect(await main.findByRole("button", { name: "Start a new draft from this" })).toBeInTheDocument();
    expect(main.queryByRole("button", { name: "Send for review" })).toBeNull();
    await userEvent.click(main.getByRole("tab", { name: "Plan of action" }));
    await main.findByText(POAM_NOTE);
    expect(main.queryByRole("button", { name: "Draft items for what is not met" })).toBeNull();
    await userEvent.click(main.getByRole("tab", { name: "System security plan" }));
    expect(await main.findByLabelText("System identification")).toBeDisabled();
  });

  it("moves through the workflow with the permissions it needs", async () => {
    let to = "";
    const main = await open(ADMIN, DETAIL(), {
      [`POST ${A}/transition`]: (r: FakeRequest) => {
        to = (r.body as { to: string }).to;
        return ok({ ...ASSESSMENT, state: "in_review" });
      },
    });
    await userEvent.click(await main.findByRole("button", { name: "Send for review" }));
    await waitFor(() => expect(to).toBe("in_review"));
  });

  it("offers the exports as downloads, and says nothing is posted", async () => {
    const main = await open();
    await userEvent.click(await main.findByRole("tab", { name: "Exports" }));
    for (const e of EXPORTS) {
      expect(await main.findByRole("link", { name: e.label })).toHaveAttribute("href", `/api/v1/organizations/o1/compliance/assessments/a1/export?format=${e.format}`);
    }
    expect(main.getByText(/never posts a score to SPRS/)).toBeInTheDocument();
  });

  it("edits the system security plan: only a section a person writes is saved", async () => {
    let sent: { body: string } | undefined;
    const main = await open(ADMIN, DETAIL(), {
      [`PUT ${A}/ssp/sections/:pos`]: (r: FakeRequest) => {
        sent = r.body as { body: string };
        return { status: 204 };
      },
    });
    await userEvent.click(await main.findByRole("tab", { name: "System security plan" }));
    await userEvent.type(await main.findByLabelText("System identification"), "Our systems.");
    await userEvent.click(main.getByRole("button", { name: "Save this section" }));
    await waitFor(() => expect(sent?.body).toBe("Our systems."));
    expect(main.getByText("Written from the assessment")).toBeInTheDocument();
  });

  it("never says compliant or certified, in any of its words", async () => {
    const main = await open();
    await main.findByText("Requirements");
    const text = [
      document.body.textContent ?? "",
      ...Object.values(STATE_WORDS).flatMap((w) => [w.label, w.hint]),
      ...Object.values(DETERMINATION_WORDS).map((w) => w.label),
      ...Object.values(GATE_WORDS).map((w) => w.label),
      ...Object.values(SOURCE_WORDS),
      ...CATEGORIES.map((c) => c.label),
      ...EXPORTS.flatMap((e) => [e.label, e.hint]),
      POAM_NOTE,
    ]
      .join(" ")
      .toLowerCase();
    for (const banned of ["compliant", "certified", "audit-ready"]) expect(text).not.toContain(banned);
  });
});

describe("the words", () => {
  it("shows a size the way a person reads it", () => {
    expect(bytes(null)).toBe("");
    expect(bytes(12)).toBe("12 B");
    expect(bytes(2048)).toBe("2.0 KiB");
    expect(bytes(64 * 1024 * 1024)).toBe("64.0 MiB");
  });
});
