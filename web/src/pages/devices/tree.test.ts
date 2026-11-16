import { describe, expect, it } from "vitest";
import { device, org, site } from "../../test/fixtures";
import { ancestors, buildTree, filterTree, indexTree, initialExpanded, selectedKey, visibleRows, type TreeNode } from "./tree";

const names = (nodes: TreeNode[]) => nodes.map((n) => n.name);

const ORGS = [org("o2", "contoso"), org("o1", "Northwind Traders"), org("o3", "Empty Org")];
const SITES = [
  site("s2", "o1", "Warehouse 10"),
  site("s1", "o1", "Head office"),
  site("s4", "o1", "Warehouse 9"),
  site("s3", "o2", "Clinic", { organizationName: "contoso" }),
];
const DEVICES = [
  device("d2", "front-desk", { online: false }),
  device("d1", "ACCOUNTS", { hostname: "acc-01.northwind.local" }),
  device("d3", "LAB-07", { organizationId: "o2", organizationName: "contoso", siteId: "s3", siteName: "Clinic" }),
  // A device whose site the sites list did not return (created since): it still gets a home.
  device("d4", "NEW-PC", { organizationId: "o1", siteId: "s9", siteName: "Branch" }),
];

describe("device tree", () => {
  it("groups devices under their sites and organizations, sorted naturally, with counts", () => {
    const roots = buildTree(ORGS, SITES, DEVICES);
    expect(names(roots)).toEqual(["contoso", "Empty Org", "Northwind Traders"]);
    const northwind = roots[2]!;
    expect(names(northwind.children)).toEqual(["Branch", "Head office", "Warehouse 9", "Warehouse 10"]);
    expect(names(northwind.children[1]!.children)).toEqual(["ACCOUNTS", "front-desk"]);
    expect([northwind.total, northwind.online]).toEqual([3, 2]);
    expect([northwind.children[1]!.total, northwind.children[1]!.online]).toEqual([2, 1]);
    expect(roots[1]!.children).toEqual([]);
    expect(roots[1]!.total).toBe(0);

    const index = indexTree(roots);
    expect(index.get("d:d1")?.parent).toBe("s:s1");
    expect(ancestors(index, "d:d1")).toEqual(["s:s1", "o:o1"]);
    expect(ancestors(index, "o:o1")).toEqual([]);
    expect(ancestors(index, "d:missing")).toEqual([]);
  });

  it("opens everything in a small fleet and only organizations in a larger one", () => {
    const roots = buildTree(ORGS, SITES, DEVICES);
    expect(initialExpanded(roots)).toEqual(new Set(["o:o2", "s:s3", "o:o3", "o:o1", "s:s9", "s:s1", "s:s4", "s:s2"]));

    const many = Array.from({ length: 101 }, (_, i) => device(`m${i}`, `PC-${i}`));
    expect(initialExpanded(buildTree(ORGS, SITES, many))).toEqual(new Set(["o:o1", "o:o2", "o:o3"]));
    const orgs = Array.from({ length: 11 }, (_, i) => org(`x${i}`, `Org ${i}`));
    expect(initialExpanded(buildTree(orgs, [], many)).size).toBe(0);
  });

  it("filters by name and hostname, keeping the way to each match", () => {
    const roots = buildTree(ORGS, SITES, DEVICES);
    expect(filterTree(roots, "  ").roots).toBe(roots);

    const byHost = filterTree(roots, "ACC-01");
    expect(byHost.matches).toBe(1);
    expect(names(byHost.roots)).toEqual(["Northwind Traders"]);
    expect(names(byHost.roots[0]!.children)).toEqual(["Head office"]);
    expect(names(byHost.roots[0]!.children[0]!.children)).toEqual(["ACCOUNTS"]);
    expect(byHost.expand).toEqual(new Set(["o:o1", "s:s1"]));
    // Filtering does not change the tree it was given.
    expect(roots[2]!.children).toHaveLength(4);

    // A matching site keeps all its devices; a matching organization keeps everything and shows its sites.
    const bySite = filterTree(roots, "warehouse");
    expect(bySite.matches).toBe(2);
    expect(names(bySite.roots[0]!.children)).toEqual(["Warehouse 9", "Warehouse 10"]);
    const byOrg = filterTree(roots, "contoso");
    expect(byOrg.roots[0]!.children[0]!.children).toHaveLength(1);
    expect(byOrg.expand.has("o:o2")).toBe(true);

    expect(filterTree(roots, "nothing like it")).toMatchObject({ roots: [], matches: 0 });
  });

  it("lists the visible rows with their position among siblings", () => {
    const roots = buildTree(ORGS, SITES, DEVICES);
    const rows = visibleRows(roots, (k) => k === "o:o1" || k === "s:s1");
    expect(rows.map((r) => `${r.node.key}@${r.position}/${r.siblings}`)).toEqual([
      "o:o2@1/3",
      "o:o3@2/3",
      "o:o1@3/3",
      "s:s9@1/4",
      "s:s1@2/4",
      "d:d1@1/2",
      "d:d2@2/2",
      "s:s4@3/4",
      "s:s2@4/4",
    ]);
  });

  it("knows which node the page is about", () => {
    expect(selectedKey("/devices", "")).toBe("all");
    expect(selectedKey("/devices", "?organizationId=o1&status=online")).toBe("o:o1");
    expect(selectedKey("/devices", "?organizationId=o1&siteId=s2")).toBe("s:s2");
    expect(selectedKey("/devices/d1", "")).toBe("d:d1");
    expect(selectedKey("/devices/add", "")).toBeNull();
    expect(selectedKey("/devices/d1/remote/terminal", "")).toBeNull();
    expect(selectedKey("/organizations", "")).toBeNull();
  });
});
