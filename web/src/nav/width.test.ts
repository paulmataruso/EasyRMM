import { describe, expect, it } from "vitest";
import { rowWidth, sidebarWidth, textMeasure, treeWidth, type Measure } from "./width";

// Ten pixels a character, whatever the font.
const tens: Measure = (text) => text.length * 10;

describe("sidebar width", () => {
  it("adds up a row from its indent, icons, name, count and quick-connect button", () => {
    // Scrolling area 16, indent 4, chevron, icon and gaps 44, name 30, end 6.
    expect(rowWidth({ text: "abc", level: 1 }, tens)).toBe(100);
    // Deeper rows are indented further.
    expect(rowWidth({ text: "abc", level: 3 }, tens)).toBe(124);
    // A plain count, then a pill (never narrower than 20), then the quick-connect button.
    expect(rowWidth({ text: "abc", level: 1, badge: { text: "3/3", pill: false } }, tens)).toBe(136);
    expect(rowWidth({ text: "abc", level: 1, badge: { text: "7", pill: true } }, tens)).toBe(100 + 6 + 22);
    expect(rowWidth({ text: "abc", level: 1, badge: { text: "", pill: true } }, tens)).toBe(100 + 6 + 20);
    expect(rowWidth({ text: "abc", level: 3, quick: true }, tens)).toBe(124 + 30);
  });

  it("asks for the widest row and the scroll bar, in whole pixels", () => {
    const half: Measure = (text) => text.length * 10.5;
    expect(treeWidth([{ text: "a", level: 1 }, { text: "a much longer name", level: 2 }, { text: "b", level: 3 }], half, 15)).toBe(
      Math.ceil(16 + 16 + 44 + 18 * 10.5 + 6 + 15),
    );
    expect(treeWidth([], tens)).toBe(0);
  });

  it("stays between the main menu's width and a limit", () => {
    expect(sidebarWidth(300)).toBe("clamp(15rem, 300px, min(24rem, 33.3vw))");
    expect(sidebarWidth(300, true)).toBe("clamp(16rem, 300px, 85vw)");
  });

  it("estimates text without a canvas, and measures each text once", () => {
    const m = textMeasure("sans-serif");
    expect(m("abcd", "row")).toBe(32);
    expect(m("abcd", "badge")).toBe(28);
    expect(m("abcd", "row")).toBe(32);
  });
});
