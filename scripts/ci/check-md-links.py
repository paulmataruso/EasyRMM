"""Checks the relative links and anchors in the repository's Markdown.

Usage: python3 -I scripts/ci/check-md-links.py [repository root]

Reads every tracked .md file except under .claude/. Checks Markdown links
and src, href and srcset attributes outside code fences and inline code:
a relative target must exist inside the repository, and a #fragment must
name a heading (as GitHub makes anchors from them) or an <a name|id> in the
target. Links with a scheme (https:, mailto:) are not fetched. Prints each
broken link and exits 1 if there is one.
"""
import os
import re
import subprocess
import sys

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
listed = subprocess.run(["git", "-C", root, "ls-files", "-z", "*.md"], capture_output=True, text=True, check=True)
files = [f for f in listed.stdout.split("\0") if f and not f.startswith(".claude/")]

LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
ATTR = re.compile(r"(?:src|href|srcset)=\"([^\"]+)\"")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
ANCHOR_TAG = re.compile(r"<a\s+(?:name|id)=\"([^\"]+)\"")
FENCE = ("```", "~~~")


def slug(text):
    """GitHub's anchor for a heading."""
    text = re.sub(r"`", "", text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.strip().lower()
    return "".join(ch for ch in text if ch.isalnum() or ch in "-_ ").replace(" ", "-")


anchor_cache = {}


def anchors(path):
    if path not in anchor_cache:
        found, counts, fence = set(), {}, False
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.lstrip().startswith(FENCE):
                    fence = not fence
                    continue
                if fence:
                    continue
                found.update(ANCHOR_TAG.findall(line))
                m = HEADING.match(line)
                if m:
                    s = slug(m.group(2))
                    n = counts.get(s, 0)
                    counts[s] = n + 1
                    found.add(s if n == 0 else f"{s}-{n}")
        anchor_cache[path] = found
    return anchor_cache[path]


problems = 0
for f in files:
    full = os.path.join(root, f)
    fence = False
    with open(full, encoding="utf-8") as fh:
        lines = fh.readlines()
    for no, line in enumerate(lines, 1):
        if line.lstrip().startswith(FENCE):
            fence = not fence
            continue
        if fence:
            continue
        text = re.sub(r"`[^`]*`", "", line)
        targets = LINK.findall(text)
        for attr in ATTR.findall(text):
            targets += [t.strip().split(" ")[0] for t in attr.split(",")]
        for t in targets:
            if re.match(r"^[a-z][a-z0-9+.-]*:", t) or t.startswith("//"):
                continue
            path, _, frag = t.partition("#")
            if path:
                dest = os.path.normpath(os.path.join(os.path.dirname(full), path))
                if dest != root and not dest.startswith(root + os.sep):
                    print(f"{f}:{no}: leaves the repository: {t}")
                    problems += 1
                    continue
                if not os.path.exists(dest):
                    print(f"{f}:{no}: missing: {t}")
                    problems += 1
                    continue
            else:
                dest = full
            if frag and dest.endswith(".md") and os.path.isfile(dest) and frag not in anchors(dest):
                print(f"{f}:{no}: no anchor #{frag} in {os.path.relpath(dest, root)}")
                problems += 1

print(f"{len(files)} Markdown files, {problems} broken link(s)")
sys.exit(1 if problems else 0)
