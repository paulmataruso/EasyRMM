import { describe, expect, it } from "vitest";

// The module pages hold no manual-read button and no hand-styled button (ADR-0073 section 5 as amended; DESIGN.md,
// ADR-0072): what a tab shows it reads by itself, and every button is the console's own Button.
const pages = import.meta.glob(
  ["./**/*.tsx", "../backup/*.tsx", "../security/*.tsx", "../../organizations/tabs/WindowsModulesTab.tsx"],
  { query: "?raw", import: "default", eager: true },
) as Record<string, string>;
const sources = Object.entries(pages).filter(([name]) => !/\.test\.tsx$/.test(name));

describe("the module pages", () => {
  it("are found", () => {
    expect(sources.length).toBeGreaterThan(20);
  });
  it("have no Read now button, or any other manual read", () => {
    for (const [name, text] of sources) {
      expect(text, name).not.toMatch(/Read now/);
      expect(text, name).not.toMatch(/>\s*(List users|List groups|List computers|Show who is in them)\s*</);
      expect(text, name).not.toMatch(/onRefresh|canRefresh/);
    }
  });
  it("use the shared Button, never a hand-styled one", () => {
    for (const [name, text] of sources) {
      expect(text, name).not.toMatch(/<button[\s>]/);
    }
  });
});
