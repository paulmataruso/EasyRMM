#!/usr/bin/env python3
"""Checks the licences of EasyPatch's NuGet packages against an allow-list of permissive licences.

ADR-0037: no copyleft dependencies. Run after `dotnet restore` (or build) of the projects named:

    python3 scripts/ci/check-nuget-licences.py easypatch/backend/API easypatch/backend/Worker ...

Each project's obj/project.assets.json lists the packages it restored, direct and transitive; each
package's .nuspec in the global packages folder states its licence as an SPDX expression. A package
that states only a licence URL fails: read the licence, then replace or exempt the package here.
Prints one line per package and exits 1 if any licence is missing or not allowed. Standard library
only.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# PostgreSQL: the PostgreSQL Licence (Npgsql), permissive and OSI-approved.
ALLOWED = {"MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "MPL-2.0", "PostgreSQL"}



def permitted(expression: str) -> bool:
    """Whether an SPDX expression is satisfied: some OR branch whose AND parts are all allowed."""
    clean = re.sub(r"[()]", " ", expression).strip()
    return any(
        all(part.strip() in ALLOWED for part in re.split(r"\s+AND\s+", branch, flags=re.I))
        for branch in re.split(r"\s+OR\s+", clean, flags=re.I)
    )


def licence_of(nuspec: Path) -> str:
    """The SPDX expression a .nuspec declares, or "" if it declares none."""
    root = ET.parse(nuspec).getroot()
    meta = next((c for c in root if c.tag.endswith("metadata")), None)
    if meta is None:
        return ""
    for child in meta:
        if child.tag.endswith("}license") or child.tag == "license":
            if child.get("type") == "expression" and child.text:
                return child.text.strip()
    return ""


def main(projects: list[str]) -> int:
    if not projects:
        print("usage: check-nuget-licences.py <project dir>...", file=sys.stderr)
        return 2
    seen: dict[str, str] = {}
    for project in projects:
        assets = json.loads((Path(project) / "obj" / "project.assets.json").read_text())
        folders = [Path(f) for f in assets.get("packageFolders", {})]
        for name, lib in assets["libraries"].items():
            if lib.get("type") != "package" or name in seen:
                continue
            nuspec = next(
                (f / lib["path"] / p for f in folders for p in lib.get("files", []) if p.endswith(".nuspec") and (f / lib["path"] / p).is_file()),
                None,
            )
            seen[name] = licence_of(nuspec) if nuspec else ""
    failures = 0
    for name in sorted(seen):
        licence = seen[name]
        ok = bool(licence) and permitted(licence)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {licence or '(no licence found)'}")
    if failures:
        print(f"{failures} package(s) with a missing or disallowed licence", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
