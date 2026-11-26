#!/usr/bin/env bash
# Builds scripts/<action>.ps1 from src/: head + lib + guard (where the action needs it) + the action's body. The
# generated files are what the server embeds and pins; edit src/ and run this, which also rewrites the hashes in
# pins.go (review that diff: a changed pin is a changed script).
#
# The AST check follows a tainted value (anything made from $p) by variable name through the whole script, so a
# helper's local that shares a name with a body's variable would be flagged. lib.txt and guard.txt are therefore
# written with plain names and every variable in them gets an "fn_" prefix here ($p, $_ and $version are kept).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p scripts
prefix() {
  python3 -I -c '
import re, sys
keep = {"p", "_", "version", "true", "false", "null", "ErrorActionPreference"}
def sub(m):
    return m.group(0) if m.group(1) in keep else "$fn_" + m.group(1)
sys.stdout.write(re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", sub, sys.stdin.read()))
'
}
for body in src/*.body; do
  name=$(basename "$body" .body)
  { cat src/head.txt
    { cat src/lib.txt
      case "$name" in status|ou_tree|health_read|group_members|computer_list) ;; *) echo; cat src/guard.txt ;; esac
    } | prefix
    echo; cat "$body"; } > "scripts/$name.ps1"
done
{
  printf 'package activedirectory\n\n// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed\n// script is a changed line.\nvar pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials\n'
  for f in scripts/*.ps1; do printf '\t"%s": "%s",\n' "$(basename "$f" .ps1)" "$(sha256sum "$f" | cut -d' ' -f1)"; done
  printf '}\n\nfunc pin(name string) string { return pins[name] }\n'
} > pins.go
gofmt -w pins.go
