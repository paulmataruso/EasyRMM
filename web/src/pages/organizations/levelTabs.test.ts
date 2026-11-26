import { describe, expect, it } from "vitest";
import type { Permission } from "../../api/types";
import {
  activeTab,
  LEVEL_TABS,
  visibleTabs,
  type Level,
  type LevelTab,
} from "./levelTabs";

// The tab registry (ADR-0072, S4): order, levels, permission gating at the selection's level, and ?tab= resolution.

const ids = (
  level: Level,
  held: Permission[],
  patchingConfigured = false,
  tabs: readonly LevelTab[] = LEVEL_TABS,
) =>
  visibleTabs(
    { level, can: (p) => held.includes(p), patchingConfigured },
    tabs,
  ).map((t) => t.id);

describe("visibleTabs", () => {
  it("shows only Overview to a viewer with no further permission", () => {
    expect(ids("organization", [])).toEqual(["overview"]);
    expect(ids("site", [])).toEqual(["overview"]);
  });

  it("orders the organization's tabs and hides what the viewer may not see", () => {
    expect(ids("organization", ["doc.view", "patch.view"], true)).toEqual([
      "overview",
      "contacts",
      "patch-policy",
    ]);
    expect(ids("organization", ["doc.view"], true)).toEqual([
      "overview",
      "contacts",
    ]);
    expect(ids("organization", ["patch.view"], true)).toEqual([
      "overview",
      "patch-policy",
    ]);
  });

  it("shows Contacts at the organization only, and Patch policy at the site only with the engine set up", () => {
    expect(ids("site", ["doc.view", "patch.view"], true)).toEqual([
      "overview",
      "patch-policy",
    ]);
    expect(ids("site", ["doc.view", "patch.view"], false)).toEqual([
      "overview",
    ]);
    expect(ids("organization", ["patch.view"], false)).toEqual(["overview"]);
  });

  it("shows Windows modules at the organization and the site to whoever may view the organization", () => {
    expect(ids("organization", ["org.view"])).toEqual([
      "overview",
      "windows-modules",
    ]);
    expect(ids("site", ["org.view"])).toEqual(["overview", "windows-modules"]);
  });

  it("checks the permission at the level asked: the same holder differs per level", () => {
    const tabs: LevelTab[] = [
      {
        id: "overview",
        label: "Overview",
        permission: null,
        levels: ["organization", "site", "group"],
      },
      {
        id: "x",
        label: "X",
        permission: "user.view",
        levels: ["organization", "site"],
      },
    ];
    const at = (level: Level) =>
      visibleTabs(
        {
          level,
          can: (p) => p === "user.view" && level === "organization",
          patchingConfigured: false,
        },
        tabs,
      ).map((t) => t.id);
    expect(at("organization")).toEqual(["overview", "x"]);
    expect(at("site")).toEqual(["overview"]);
    expect(at("group")).toEqual(["overview"]);
  });

  it("keeps ids unique and Overview first", () => {
    expect(new Set(LEVEL_TABS.map((t) => t.id)).size).toBe(LEVEL_TABS.length);
    expect(LEVEL_TABS[0]?.id).toBe("overview");
    expect(LEVEL_TABS.every((t) => t.id === "overview" || t.component)).toBe(
      true,
    );
  });
});

describe("activeTab", () => {
  const visible = visibleTabs({
    level: "organization",
    can: () => true,
    patchingConfigured: true,
  });
  it("honours ?tab= for a shown tab", () => {
    expect(activeTab(visible, "contacts").id).toBe("contacts");
  });
  it("falls back to Overview for no, unknown or hidden tabs", () => {
    expect(activeTab(visible, null).id).toBe("overview");
    expect(activeTab(visible, "nope").id).toBe("overview");
    const site = visibleTabs({
      level: "site",
      can: () => true,
      patchingConfigured: true,
    });
    expect(activeTab(site, "contacts").id).toBe("overview");
  });
});
