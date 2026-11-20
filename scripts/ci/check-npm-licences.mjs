#!/usr/bin/env node
// Checks the licences of a console's production npm packages (what ships in its bundle) against an
// allow-list of permissive licences (ADR-0037: no copyleft dependencies). Run from a directory where
// `npm ci` has run:
//
//   node scripts/ci/check-npm-licences.mjs web
//
// Prints one line per package and exits 1 if any licence is missing or not allowed. Uses only Node's
// standard library and npm itself.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const allowed = new Set(["MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "MPL-2.0"]);

/** The licence ids a package.json declares: an SPDX expression ("MIT OR Apache-2.0") or the old forms. */
export function licenceIds(pkg) {
  const raw = pkg.license ?? pkg.licenses;
  if (typeof raw === "string") return [raw];
  if (Array.isArray(raw)) return raw.map((l) => (typeof l === "string" ? l : l?.type)).filter(Boolean);
  if (raw && typeof raw === "object" && typeof raw.type === "string") return [raw.type];
  return [];
}

/** Whether an SPDX expression is satisfied by the allow-list: any OR branch whose AND parts are all allowed. */
export function permitted(expression) {
  const clean = expression.replace(/[()]/g, " ").trim();
  return clean
    .split(/\s+OR\s+/i)
    .some((branch) => branch.split(/\s+AND\s+/i).every((id) => allowed.has(id.trim())));
}

function check(dir) {
  const root = resolve(dir);
  const out = execFileSync("npm", ["ls", "--omit=dev", "--all", "--parseable"], { cwd: root, encoding: "utf8" });
  const paths = [...new Set(out.split("\n").map((l) => l.trim()).filter(Boolean))].slice(1); // first line is the project
  let failures = 0;
  for (const path of paths) {
    const pkg = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
    const ids = licenceIds(pkg);
    const ok = ids.length > 0 && ids.every(permitted);
    if (!ok) failures++;
    console.log(`${ok ? "ok  " : "FAIL"} ${dir}: ${pkg.name}@${pkg.version} ${ids.join(", ") || "(no licence)"}`);
  }
  return failures;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const dirs = process.argv.slice(2);
  if (dirs.length === 0) {
    console.error("usage: check-npm-licences.mjs <dir>...");
    process.exit(2);
  }
  const failures = dirs.reduce((n, d) => n + check(d), 0);
  if (failures > 0) {
    console.error(`${failures} package(s) with a missing or disallowed licence`);
    process.exit(1);
  }
}
