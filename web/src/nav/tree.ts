import type { Device, DeviceTreeCount, DeviceTreeGroup, Organization, Site } from "../api/types";

/**
 * The navigation tree (ADR-0069): organizations, their sites, each site's device groups and the devices, the same on
 * every view. Built from the list endpoints so it shows every organization, site and group the caller can see,
 * including those without devices. A site's devices that belong to no group sit directly under it, after its groups.
 */
export type TreeKind = "org" | "site" | "group" | "device";

export interface TreeNode {
  /** "o:<id>", "s:<id>", "g:<id>" or "d:<id>". */
  key: string;
  kind: TreeKind;
  id: string;
  name: string;
  /** A device is at level 4 under a group and at level 3 directly under a site. */
  level: 1 | 2 | 3 | 4;
  parent: string | null;
  organizationId: string;
  /** The site of a site, group or device. */
  siteId?: string;
  /** The group of a group or device (null: a device in none). */
  groupId?: string | null;
  /** Only the nodes of devices loaded so far. */
  children: TreeNode[];
  /** Whether the node has anything to open, loaded or not. */
  expandable: boolean;
  /** Devices at or below this node, and how many of them are online. */
  total: number;
  online: number;
  /** Devices directly under a site (in no group) or group: the ones loaded when it opens. */
  own: number;
  device?: Device;
}

export const orgKey = (id: string) => `o:${id}`;
export const siteKey = (id: string) => `s:${id}`;
export const groupKey = (id: string) => `g:${id}`;
export const deviceKey = (id: string) => `d:${id}`;

const collator = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });
const byName = (a: TreeNode, b: TreeNode) => collator.compare(a.name, b.name) || a.id.localeCompare(b.id);

export interface TreeShape {
  groups?: DeviceTreeGroup[];
  /** The server's device counts; without them the devices given are counted. */
  counts?: DeviceTreeCount[];
}

/** The counts of a list of devices, in the server's form. */
export function countDevices(devices: Device[]): DeviceTreeCount[] {
  const out = new Map<string, DeviceTreeCount>();
  for (const d of devices) {
    const key = `${d.siteId}/${d.deviceGroupId ?? ""}`;
    const n = out.get(key) ?? { siteId: d.siteId, groupId: d.deviceGroupId, total: 0, online: 0 };
    n.total += 1;
    if (d.online) n.online += 1;
    out.set(key, n);
  }
  return [...out.values()];
}

/** `devices` are those loaded so far; every device counts toward its node's totals through `shape.counts` either way. */
export function buildTree(orgs: Organization[], sites: Site[], devices: Device[], shape: TreeShape = {}): TreeNode[] {
  const orgNodes = new Map<string, TreeNode>();
  const siteNodes = new Map<string, TreeNode>();
  const groupNodes = new Map<string, TreeNode>();
  const counts = shape.counts ?? countDevices(devices);

  const org = (id: string, name: string) => {
    let n = orgNodes.get(id);
    if (!n) {
      n = { key: orgKey(id), kind: "org", id, name, level: 1, parent: null, organizationId: id, children: [], expandable: false, total: 0, online: 0, own: 0 };
      orgNodes.set(id, n);
    }
    return n;
  };
  const site = (id: string, organizationId: string, organizationName: string, name: string) => {
    let n = siteNodes.get(id);
    if (!n) {
      const parent = org(organizationId, organizationName);
      n = { key: siteKey(id), kind: "site", id, name, level: 2, parent: parent.key, organizationId, siteId: id, children: [], expandable: false, total: 0, online: 0, own: 0 };
      siteNodes.set(id, n);
      parent.children.push(n);
    }
    return n;
  };

  for (const o of orgs) org(o.id, o.name);
  for (const s of sites) site(s.id, s.organizationId, s.organizationName, s.name);
  // A device whose site the sites list did not return (created since) still gets a home.
  for (const d of devices) site(d.siteId, d.organizationId, d.organizationName, d.siteName);
  for (const g of shape.groups ?? []) {
    const parent = siteNodes.get(g.siteId) ?? site(g.siteId, g.organizationId, "", "");
    const n: TreeNode = {
      key: groupKey(g.id),
      kind: "group",
      id: g.id,
      name: g.name,
      level: 3,
      parent: parent.key,
      organizationId: g.organizationId,
      siteId: g.siteId,
      groupId: g.id,
      children: [],
      expandable: false,
      total: 0,
      online: 0,
      own: 0,
    };
    groupNodes.set(g.id, n);
    parent.children.push(n);
  }
  for (const c of counts) {
    const parent = siteNodes.get(c.siteId);
    if (!parent) continue;
    parent.total += c.total;
    parent.online += c.online;
    const g = c.groupId ? groupNodes.get(c.groupId) : undefined;
    const home = g ?? parent;
    home.own += c.total;
    if (g) {
      g.total += c.total;
      g.online += c.online;
    }
  }
  for (const d of devices) {
    const parent = siteNodes.get(d.siteId)!;
    const group = d.deviceGroupId ? groupNodes.get(d.deviceGroupId) : undefined;
    const home = group ?? parent;
    home.children.push({
      key: deviceKey(d.id),
      kind: "device",
      id: d.id,
      name: d.name,
      level: group ? 4 : 3,
      parent: home.key,
      organizationId: d.organizationId,
      siteId: d.siteId,
      groupId: group?.id ?? null,
      children: [],
      expandable: false,
      total: 1,
      online: d.online ? 1 : 0,
      own: 0,
      device: d,
    });
  }

  const roots = [...orgNodes.values()].sort(byName);
  for (const o of roots) {
    // Groups first, then the site's own devices; each by name.
    o.children.sort(byName);
    for (const s of o.children) {
      s.children.sort((a, b) => (a.kind === b.kind ? byName(a, b) : a.kind === "group" ? -1 : 1));
      for (const g of s.children) if (g.kind === "group") g.children.sort(byName);
    }
    o.total = o.children.reduce((n, s) => n + s.total, 0);
    o.online = o.children.reduce((n, s) => n + s.online, 0);
  }
  for (const n of [...siteNodes.values(), ...groupNodes.values(), ...roots]) {
    n.expandable = n.children.length > 0 || n.own > 0;
  }
  return roots;
}

/** Every node by key. */
export function indexTree(roots: TreeNode[]): Map<string, TreeNode> {
  const index = new Map<string, TreeNode>();
  const walk = (nodes: TreeNode[]) => {
    for (const n of nodes) {
      index.set(n.key, n);
      walk(n.children);
    }
  };
  walk(roots);
  return index;
}

/** The keys of a node's ancestors, nearest first. */
export function ancestors(index: Map<string, TreeNode>, key: string): string[] {
  const out: string[] = [];
  for (let n = index.get(key)?.parent; n; n = index.get(n)?.parent) out.push(n);
  return out;
}

/**
 * What opens by default: everything in a small fleet; in a larger one the organizations, while there are few
 * enough of them to scan; otherwise nothing.
 */
export function initialExpanded(roots: TreeNode[]): Set<string> {
  const devices = roots.reduce((n, o) => n + o.total, 0);
  const open = new Set<string>();
  if (devices <= 100) {
    for (const o of roots) {
      open.add(o.key);
      for (const s of o.children) {
        open.add(s.key);
        for (const g of s.children) if (g.kind === "group") open.add(g.key);
      }
    }
  } else if (roots.length <= 10) {
    for (const o of roots) open.add(o.key);
  }
  return open;
}

function matches(n: TreeNode, q: string): boolean {
  return n.name.toLowerCase().includes(q) || (n.device?.hostname.toLowerCase().includes(q) ?? false);
}

/**
 * Narrows the tree to nodes matching the query (by name, and by hostname for devices), keeping each match's
 * ancestors and, for an organization or site that matches, everything under it. `expand` opens the way to every
 * match.
 */
export function filterTree(roots: TreeNode[], query: string): { roots: TreeNode[]; matches: number; expand: Set<string> } {
  const q = query.trim().toLowerCase();
  if (!q) return { roots, matches: 0, expand: new Set() };
  let count = 0;
  const expand = new Set<string>();
  const prune = (nodes: TreeNode[]): TreeNode[] => {
    const out: TreeNode[] = [];
    for (const n of nodes) {
      if (matches(n, q)) {
        count++;
        out.push(n);
        if (n.parent) expand.add(n.parent);
        continue;
      }
      const children = prune(n.children);
      if (children.length > 0) {
        out.push({ ...n, children });
        expand.add(n.key);
      }
    }
    return out;
  };
  const pruned = prune(roots);
  // A matching organization has no parent to open; open it so its sites show.
  for (const o of pruned) if (matches(o, q)) expand.add(o.key);
  return { roots: pruned, matches: count, expand };
}

export interface TreeRow {
  node: TreeNode;
  /** Position among its siblings, for aria-posinset and aria-setsize. */
  position: number;
  siblings: number;
}

/** The rows a reader sees, in order, given which nodes are open. */
export function visibleRows(roots: TreeNode[], isOpen: (key: string) => boolean): TreeRow[] {
  const rows: TreeRow[] = [];
  const walk = (nodes: TreeNode[]) => {
    nodes.forEach((node, i) => {
      rows.push({ node, position: i + 1, siblings: nodes.length });
      if (node.expandable && isOpen(node.key)) walk(node.children);
    });
  };
  walk(roots);
  return rows;
}

