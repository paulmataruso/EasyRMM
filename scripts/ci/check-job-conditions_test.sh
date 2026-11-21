#!/usr/bin/env bash
# Tests for check-job-conditions.py: workflows whose jobs are, or are not,
# skipped by a job they never needed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# run <want exit> <want in output> <workflow text>
run() {
  local want=$1 text=$2 out status=0
  cat > "$work/w.yml"
  out=$(python3 -I "$here/check-job-conditions.py" "$work/w.yml" 2>&1) || status=$?
  [ "$status" -eq "$want" ] || fail "exit $status, want $want: $out"
  [[ $out == *"$text"* ]] || fail "output lacks \"$text\": $out"
}

# The jobs before: one a change may skip, and a result that checks them all.
head='jobs:
  maybe:
    if: github.event_name == '"'"'push'"'"'
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
  result:
    if: always()
    needs: [maybe]
    runs-on: ubuntu-latest
    steps: [{run: "true"}]'

# What the edge publish did: no status check after result.
run 1 "its if has no !cancelled() or always()" <<EOF
$head
  publish:
    needs: [result]
    if: needs.result.result == 'success'
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
EOF

# Further down, through a job that is itself right, still counts.
run 1 "job tag comes after result" <<EOF
$head
  publish:
    needs: [result]
    if: \${{ !cancelled() && needs.result.result == 'success' }}
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
  tag:
    needs: [publish]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
EOF

# A status check that would let it run after a need failed.
run 1 "does not check needs.maybe.result" <<EOF
$head
  publish:
    needs: [result, maybe]
    if: \${{ !cancelled() && needs.result.result == 'success' }}
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
EOF

# Right: a status check and every need's result.
run 0 "no job skipped" <<EOF
$head
  publish:
    needs: [result, maybe]
    if: >-
      !cancelled() && needs.result.result == 'success' &&
      needs.maybe.result == 'success'
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
EOF

# A job after a skippable one, with no result job between, is skipped with
# it on purpose and is not judged.
run 0 "no job skipped" <<EOF
jobs:
  maybe:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
  after:
    needs: [maybe]
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
EOF

# No workflow named.
status=0
python3 -I "$here/check-job-conditions.py" > /dev/null 2>&1 || status=$?
[ "$status" -eq 2 ] || fail "no arguments: exit $status, want 2"

if [ "$failures" -ne 0 ]; then
  echo "check-job-conditions.py: $failures failure(s)" >&2
  exit 1
fi
echo "check-job-conditions.py: all tests passed"
