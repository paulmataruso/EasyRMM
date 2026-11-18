import type { Device, Organization, Site } from "../api/types";

/**
 * The navigation tree: organizations, their sites, and (in sections that list them) each site's devices. Built from
 * the three list endpoints so it shows every organization and site the caller can see, including those without
 * devices.
 */
export type TreeKind = "org" | "site" | "device";

export interface TreeNode {
  /** "o:<id>", "s:<id>" or "d:<id>". */
  key: string;
  kind: TreeKind;
  id: string;
  name: string;
  level: 1 | 2 | 3;
  parent: string | null;
  organizationId: string;
  children: TreeNode[];
  /** Devices at or below this node, and how many of them are online. */
  total: number;
  online: number;
  device?: Device;
}

export const orgKey = (id: string) => `o:${id}`;
export const siteKey = (id: string) => `s:${id}`;
export const deviceKey = (id: string) => `d:${id}`;

const collator = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });
const byName = (a: TreeNode, b: TreeNode) => collator.compare(a.name, b.name) || a.id.localeCompare(b.id);

/**
 * `leaf` decides which devices appear under their sites; every device counts toward its site's and organization's
 * totals either way.
 */
export function buildTree(orgs: Organization[], sites: Site[], devices: Device[], leaf: (d: Device) => boolean = () => true): TreeNode[] {
  const orgNodes = new Map<string, TreeNode>();
  const siteNodes = new Map<string, TreeNode>();

  const org = (id: string, name: string) => {
    let n = orgNodes.get(id);
    if (!n) {
      n = { key: orgKey(id), kind: "org", id, name, level: 1, parent: null, organizationId: id, children: [], total: 0, online: 0 };
      orgNodes.set(id, n);
    }
    return n;
  };
  const site = (id: string, organizationId: string, organizationName: string, name: string) => {
    let n = siteNodes.get(id);
    if (!n) {
      const parent = org(organizationId, organizationName);
      n = { key: siteKey(id), kind: "site", id, name, level: 2, parent: parent.key, organizationId, children: [], total: 0, online: 0 };
      siteNodes.set(id, n);
      parent.children.push(n);
    }
    return n;
  };

  for (const o of orgs) org(o.id, o.name);
  for (const s of sites) site(s.id, s.organizationId, s.organizationName, s.name);
  for (const d of devices) {
    const parent = site(d.siteId, d.organizationId, d.organizationName, d.siteName);
    parent.total += 1;
    if (d.online) parent.online += 1;
    if (!leaf(d)) continue;
    parent.children.push({
      key: deviceKey(d.id),
      kind: "device",
      id: d.id,
      name: d.name,
      level: 3,
      parent: parent.key,
      organizationId: d.organizationId,
      children: [],
      total: 1,
      online: d.online ? 1 : 0,
      device: d,
    });
  }

  const roots = [...orgNodes.values()].sort(byName);
  for (const o of roots) {
    o.children.sort(byName);
    for (const s of o.children) s.children.sort(byName);
    o.total = o.children.reduce((n, s) => n + s.total, 0);
    o.online = o.children.reduce((n, s) => n + s.online, 0);
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
      for (const s of o.children) open.add(s.key);
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
      if (node.children.length > 0 && isOpen(node.key)) walk(node.children);
    });
  };
  walk(roots);
  return rows;
}

