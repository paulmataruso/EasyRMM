#!/usr/bin/env bash
# Enforces per-package statement coverage floors from a Go cover profile.
#
# Floors are deliberately per package: security-critical packages carry a
# higher bar, and a high average elsewhere cannot hide an untested
# authorization module. Raise floors as coverage improves; never lower one to
# make a build pass.
set -euo pipefail

profile="${1:-coverage.txt}"
module="github.com/paulmataruso/easyrmm"

# package (relative to the module)        minimum %
floors=(
  # Security-critical: authorization, secrets, sessions/CSRF, tenant access.
  "server/internal/rbac                    90"
  "server/internal/secrets                 90"
  "server/internal/httpapi                 95"
  "server/internal/access                  95"
  "server/internal/auth                    85"
  "server/internal/users                   88"
  "server/internal/tenancy                 88"
  "server/internal/audit                   85"
  # Agent identity: enrollment, request signatures, and their HTTP surface.
  "internal/agentproto                     95"
  "server/internal/agents                  88"
  # Reads the signatures operators upload (ADR-0049).
  "server/internal/agents/authenticode     90"
  "server/internal/httpapi/agentapi        88"
  # Everything else.
  "server/internal/database                85"
  "server/internal/config                  90"
  "server/internal/apperr                  85"
  "server/internal/mailer                  90"
  "server/internal/webui                   95"
  "server/internal/app                     85"
  "server/internal/httpapi/authapi         85"
  "server/internal/httpapi/tenancyapi      85"
  "server/internal/httpapi/usersapi        85"
  "server/internal/httpapi/auditapi        85"
  "server/internal/httpapi/remoteapi       85"
  "server/internal/httpapi/devicesapi      85"
  "server/internal/httpapi/enrollapi       85"
  "server/internal/devices                 88"
  # Scripts and jobs, inventory, monitoring and alerts, and their APIs.
  "server/internal/jobs                    85"
  "server/internal/inventory               85"
  "server/internal/monitoring              85"
  "server/internal/httpapi/jobsapi         90"
  "server/internal/httpapi/inventoryapi    90"
  "server/internal/httpapi/alertsapi       90"
  # Audit forwarding: every tenant's records leave the server through it.
  "server/internal/auditfwd                88"
  "server/internal/httpapi/auditfwdapi     90"
  # Reports: their CSV exports take tenants' data out of EasyRMM.
  "server/internal/reports                 90"
  "server/internal/httpapi/reportsapi      90"
  # EasyPatch: it holds a token that installs software on every linked
  # endpoint, and decides which EasyRMM user may act on which endpoint.
  "server/internal/easypatch               90"
  "server/internal/httpapi/easypatchapi    95"
  # Single sign-on: a way in that skips the password, and sometimes the
  # second factor.
  "server/internal/sso                     85"
  "server/internal/httpapi/ssoapi          90"
  # The updater's hold: it decides whether the server answers anything
  # (ADR-0052).
  "server/internal/updater                 95"
  # Outbound connections a Super Administrator configures: no cloud
  # metadata or link-local addresses.
  "server/internal/netguard                95"
  # Agent updates: they replace the program every endpoint runs.
  "server/internal/httpapi/agentupdatesapi 90"
  # Removing devices: it deletes a device and has its agents uninstall
  # themselves (ADR-0050).
  "server/internal/httpapi/removalapi      90"
  # Remote access: the MeshCentral client, and the service and gateway that
  # decide who reaches MeshCentral.
  "server/internal/meshcentral             85"
  "server/internal/remote                  88"
  "server/cmd/easyrmm-server               80"
  # The endpoint agent. Its end-to-end run in a container is not
  # instrumented; these floors come from its unit tests.
  "agent/client                            90"
  "agent/runner                            90"
  "agent/host                              85"
  "agent/meshagent                         80"
  "agent/state                             75"
  "agent/cmd/easyrmm-agent                 75"
  "agent/jobs                              80"
  "agent/update                            80"
  "agent/removal                           85"
  "agent/easypatch                         85"
  "agent/inventory                         90"
  "agent/metrics                           90"
  # Parses what disks answer (ADR-0065); the transports' system calls run
  # only in the machine tests.
  "agent/hardware                          97"
)

if [[ ! -f "$profile" ]]; then
  echo "coverage profile $profile not found" >&2
  exit 1
fi

# Sum statements and covered statements per package directory. With
# -coverpkg every test binary reports every package, so the same block can
# appear several times: count each block once, covered if any run hit it.
summary=$(awk -v mod="$module/" '
  /^mode:/ { next }
  {
    block = $1
    stmts[block] = $2
    if ($3 > 0) hit[block] = 1
  }
  END {
    for (b in stmts) {
      split(b, loc, ":"); file = loc[1]
      sub(mod, "", file)
      n = split(file, parts, "/"); dir = parts[1]
      for (i = 2; i < n; i++) dir = dir "/" parts[i]
      total[dir] += stmts[b]
      if (b in hit) covered[dir] += stmts[b]
    }
    for (d in total) printf "%s %.1f\n", d, (covered[d] / total[d]) * 100
  }
' "$profile" | sort)

echo "Package coverage:"
echo "$summary" | awk '{ printf "  %-40s %6.1f%%\n", $1, $2 }'

fail=0
for entry in "${floors[@]}"; do
  read -r pkg min <<<"$entry"
  actual=$(echo "$summary" | awk -v p="$pkg" '$1 == p { print $2 }')
  if [[ -z "$actual" ]]; then
    echo "FAIL: no coverage data for $pkg (floor ${min}%)" >&2
    fail=1
    continue
  fi
  if awk -v a="$actual" -v m="$min" 'BEGIN { exit !(a + 0 < m + 0) }'; then
    echo "FAIL: $pkg coverage ${actual}% is below the ${min}% floor" >&2
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "Coverage floors met."
