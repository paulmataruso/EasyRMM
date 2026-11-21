#!/usr/bin/env python3
"""Checks that no workflow job is skipped by a job it never needed.

    python3 -I scripts/ci/check-job-conditions.py <workflow.yml>...

GitHub runs a job whose `if` has no status check (`always()`,
`!cancelled()`, `success()`, `failure()`) only when every job before it
succeeded: not only the jobs it needs, but theirs, all the way back. A job
that checks the result of everything, as `CI result` does with `always()`,
is there because some of what it needs may be skipped; so a job after it
with no status check is skipped too, silently, whenever one of them is.
The edge build was not published for a change that skipped the machine
tests that way.

So every job that comes after a job using `always()` must:
  * use `!cancelled()` or `always()` in its `if`, and
  * check `needs.<job>.result` for each job it needs, so that the status
    check does not let it run after one of them failed.
"""

import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("check-job-conditions: PyYAML is needed (python3-yaml)")

STATUS = re.compile(r"(!\s*cancelled|always)\(\)")


def needs_of(job):
    n = job.get("needs") or []
    return [n] if isinstance(n, str) else list(n)


def check(path):
    with open(path, encoding="utf-8") as f:
        workflow = yaml.safe_load(f) or {}
    jobs = workflow.get("jobs") or {}
    problems = []

    def ancestors(name, seen):
        for n in needs_of(jobs.get(name, {})):
            if n not in seen:
                seen.add(n)
                ancestors(n, seen)
        return seen

    for name, job in jobs.items():
        tolerant = sorted(a for a in ancestors(name, set()) if "always()" in str(jobs.get(a, {}).get("if", "")))
        if not tolerant:
            continue
        cond = str(job.get("if", ""))
        if not STATUS.search(cond):
            problems.append(
                f"{path}: job {name} comes after {', '.join(tolerant)}, which may run past skipped jobs, "
                "but its if has no !cancelled() or always(): GitHub skips it whenever any job before it was skipped"
            )
            continue
        for n in needs_of(job):
            if not re.search(rf"needs\.{re.escape(n)}\.result\b", cond):
                problems.append(
                    f"{path}: job {name} uses a status check but does not check needs.{n}.result, "
                    f"so it would run after {n} failed"
                )
    return problems


def main(paths):
    if not paths:
        print("usage: check-job-conditions.py <workflow.yml>...", file=sys.stderr)
        return 2
    problems = [p for path in paths for p in check(path)]
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print(f"check-job-conditions: {len(paths)} workflow(s), no job skipped by a job it never needed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
