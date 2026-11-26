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
  # The registry editor's shared rules (ADR-0067): what is refused and masked.
  "internal/registryrules                  95"
  # The event viewer's shared rules (ADR-0068): what is sensitive, the query, the server's check of a result.
  "internal/eventrules                     80"
  "server/internal/agents                  88"
  # The development-only dev scope guard.
  "server/internal/devscope                95"
  # Reads the signatures operators upload (ADR-0049).
  "server/internal/agents/authenticode     90"
  "server/internal/httpapi/agentapi        88"
  # The agents' WebSocket channel (ADR-0059).
  "server/internal/agentchannel            90"
  # Everything else.
  "server/internal/database                85"
  "server/internal/config                  90"
  "server/internal/apperr                  85"
  "server/internal/mailer                  90"
  "server/internal/webui                   95"
  "server/internal/app                     85"
  # The certificate service (ADR-0055): storage, scheduler, gate, checks, MeshCentral's slot.
  "server/internal/tlscert                 88"
  "server/internal/httpapi/tlsapi          80"
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
  # The Windows management modules' catalog, parameter checks and results (ADR-0073).
  "server/internal/winmod                  90"
  # Active Directory (ADR-0075): catalog, result types, replication alert.
  "server/internal/winmod/activedirectory 90"
  # The server-role modules (ADR-0076): guards, catalogs and alert kinds.
  "server/internal/winmod/rolekit         80"
  "server/internal/winmod/dns             85"
  "server/internal/winmod/dhcp            88"
  "server/internal/winmod/certauth        88"
  "server/internal/winmod/fileshares      85"
  "server/internal/winmod/printsrv        88"
  # Group Policy (ADR-0083): catalog and guards, the report parser, backups, approvals; measured with the integration tests.
  "server/internal/winmod/grouppolicy     80"
  # Snapshots of the Windows modules: reads, scheduled reads, retention (ADR-0073).
  "server/internal/modsnap                 75"
  # Windows hardening (ADR-0054): the ownership reader's package and the
  # related-controls tables, their generator and extraction.
  "internal/winpolicy                      95"
  "server/internal/jobs/hardening/controls 95"
  "server/internal/jobs/hardening/controls/extract 95"
  # Its command: run is tested, main only parses flags.
  "server/internal/jobs/hardening/controls/cmd/gencontrols 50"
  # The compliance engine (ADR-0078): licence classes and the edition rule, the
  # content check, the control library, the packs and their loader, the scan and the
  # roll-up. Measured with the integration tests.
  "server/internal/compliance              95"
  "server/internal/compliance/content      80"
  "server/internal/compliance/library      88"
  "server/internal/compliance/packs        78"
  "server/internal/compliance/rollup       95"
  "server/internal/compliance/scan         92"
  "server/internal/compliance/engine       70"
  "server/internal/compliance/fix          72"
  # The assessment workspace (ADR-0078, C5): the score range and its gate, the roll-up, the workflow
  # and the freeze, evidence, the plan of action, exports and the OSCAL writer.
  "server/internal/compliance/assess       75"
  "server/internal/compliance/assess/export 85"
  "server/internal/compliance/assess/oscal 90"
  "server/internal/compliance/content/templates 75"
  # Security posture (ADR-0082) and the two compliance alerts.
  "server/internal/posture                 75"
  "server/internal/compliance/alerts       65"
  "server/cmd/packlint                     85"
  "server/internal/inventory               85"
  "server/internal/monitoring              85"
  # The one notification sender and its address policy (ADR-0053).
  "server/internal/notify                  78"
  "server/internal/addrpolicy              88"
  "server/internal/httpapi/jobsapi         90"
  "server/internal/httpapi/inventoryapi    90"
  "server/internal/httpapi/alertsapi       90"
  # Disk health: what agents read, judged by the server's rules (ADR-0065).
  "server/internal/hardware                90"
  "server/internal/httpapi/hardwareapi     90"
  # Audit forwarding: every tenant's records leave the server through it.
  "server/internal/auditfwd                88"
  "server/internal/httpapi/auditfwdapi     90"
  # The mail server: it holds a password, and its limits keep invitations
  # and password resets going (ADR-0053).
  "server/internal/mailserver              88"
  "server/internal/httpapi/mailserverapi   90"
  # Microsoft 365's tokens: an application's secret or private key signs
  # them in to every mailbox it is given.
  "server/internal/m365                    90"
  # The customer record: customers' staff as contacts, personal data each
  # organization and site keeps to itself (ADR-0066).
  "server/internal/docs                    90"
  "server/internal/httpapi/docsapi         90"
  # Reports: their CSV exports take tenants' data out of EasyRMM.
  "server/internal/reports                 90"
  "server/internal/httpapi/reportsapi      90"
  # EasyPatch: it holds a token that installs software on every linked
  # endpoint, and decides which EasyRMM user may act on which endpoint.
  "server/internal/easypatch               90"
  # The hash list of everything installed (ADR-0070).
  "server/internal/agentfiles              85"
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
  # Repairing agents (ADR-0069): the server hands instructions to agents
  # that run as SYSTEM or root.
  "server/internal/recovery                85"
  "server/internal/httpapi/repairsapi      90"
  # Remote access: the MeshCentral client, and the service and gateway that
  # decide who reaches MeshCentral.
  "server/internal/meshcentral             85"
  "server/internal/remote                  88"
  "server/cmd/easyrmm-server               80"
  # Saved RDP credentials (ADR-0079): a sealed password per device, opened
  # only for the gateway, and the routes that save and delete it.
  # Quick Assist (ADR-0080): links, tickets, sessions, the runner.
  "server/internal/quickassist             75"
  "server/internal/httpapi/quickassistapi  80"
  "internal/qaticket                       80"
  "agent/quickassist                       45"
  "server/internal/rdpcreds                88"
  "server/internal/httpapi/rdpcredsapi     90"
  # The host updater (ADR-0052): it runs as root, verifies what it
  # installs, and replaces the whole deployment.
  "updater/internal/release                90"
  "updater/internal/fetch                  90"
  "updater/internal/host                   80"
  "updater/cmd/easyrmm-updater             75"
  # The endpoint agent. Its end-to-end run in a container is not
  # instrumented; these floors come from its unit tests.
  "agent/channel                           90"
  "agent/client                            90"
  "agent/runner                            90"
  "agent/host                              85"
  # Defender exclusions (ADR-0070); the Windows half runs in the windows-defender job.
  "agent/defender                          83"
  "agent/meshagent                         80"
  "agent/state                             75"
  "agent/cmd/easyrmm-agent                 75"
  "agent/jobs                              80"
  # The registry builtin's engine (ADR-0067); its Windows half runs on the Windows runners.
  "agent/registry                          80"
  # The event viewer builtin's engine (ADR-0068); its Windows half runs on the Windows runners.
  "agent/winevent                          75"
  "agent/update                            80"
  "agent/removal                           85"
  "agent/easypatch                         85"
  "agent/inventory                         90"
  "agent/metrics                           90"
  # Finding and choosing PowerShell 7 (ADR-0064): the platform-neutral part;
  # the Windows part is tested as LocalSystem on CI's Windows runners.
  "agent/powershell                        95"
  # Parses what disks answer (ADR-0065); the transports' system calls run
  # only in the machine tests.
  "agent/hardware                          97"
  # Agent logs (ADR-0069): the agent's buffer, shipper and tails, the
  # redaction both sides share, and the server's storage and console routes.
  "agent/logship                           85"
  "internal/logredact                      88"
  "server/internal/agentlogs               85"
  "server/internal/httpapi/agentlogsapi    80"
  # The keystore and recovery-key escrow (ADR-0081): the cryptography the agent
  # and the keystore share, the keystore process (its TPM, passphrase and file
  # modes, recovery bundles, wraps and checks), the server's side of the socket
  # and the escrow states, the agent's escrow code (its Windows WMI reader has no
  # test off Windows), and the console route.
  "internal/escrowcrypto                   90"
  "server/internal/keystored               75"
  "server/internal/keystore                78"
  "server/internal/httpapi/keystoreapi     85"
  "agent/escrow                            85"
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
