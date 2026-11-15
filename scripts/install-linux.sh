#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════
# EasyRMM Unified Agent Installer for Linux
# Usage: sudo bash install-linux.sh \
#          --server https://rmm.example.com \
#          --token <enrollment-token> \
#          --meshid <mesh-group-id>
# ═══════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/easyrm"
CONFIG_FILE="$INSTALL_DIR/agent.json"
SERVICE_NAME="easyrmmagent"
SKIP_EASYPATCH=false

usage() {
    echo "Usage: sudo $0 --server <url> --token <token> --meshid <id> [--skip-easypatch]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER_URL="$2"; shift 2 ;;
        --token) ENROLL_TOKEN="$2"; shift 2 ;;
        --meshid) MESH_ID="$2"; shift 2 ;;
        --skip-easypatch) SKIP_EASYPATCH=true; shift ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

[ -z "${SERVER_URL:-}" ] && echo "Error: --server required" && usage
[ -z "${ENROLL_TOKEN:-}" ] && echo "Error: --token required" && usage
[ -z "${MESH_ID:-}" ] && echo "Error: --meshid required" && usage

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

ARCH=$(uname -m)
case $ARCH in
    x86_64) AGENT_ARCH="amd64" ;;
    aarch64) AGENT_ARCH="arm64" ;;
    *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

echo -e "${CYAN}=====================================${NC}"
echo -e "${CYAN}  EasyRMM Unified Agent Installer${NC}"
echo -e "${CYAN}=====================================${NC}"
echo ""

mkdir -p "$INSTALL_DIR"

# ── Step 1: Install MeshCentral Agent ──────────────────────────
echo -e "${YELLOW}[1/3] Installing MeshCentral Agent...${NC}"

MESH_AGENT_URL="$SERVER_URL/meshagents?id=6&meshid=$MESH_ID&installflags=2"
MESH_INSTALLER=$(mktemp /tmp/meshagent.XXXXXX)

if curl -fsSL -o "$MESH_INSTALLER" "$MESH_AGENT_URL"; then
    chmod +x "$MESH_INSTALLER"
    "$MESH_INSTALLER" -install 2>/dev/null || true
    echo -e "  ${GREEN}MeshCentral Agent installed.${NC}"
else
    echo -e "  ${RED}WARNING: MeshCentral Agent installation failed.${NC}"
    echo -e "  ${YELLOW}Continuing with EasyRMM agent...${NC}"
fi
rm -f "$MESH_INSTALLER"

# ── Step 2: Install EasyRMM Agent ─────────────────────────────
echo -e "${YELLOW}[2/3] Installing EasyRMM Agent...${NC}"

AGENT_URL="$SERVER_URL/downloads/easyrmmagent-linux-$AGENT_ARCH"
AGENT_BIN="$INSTALL_DIR/easyrmmagent"

if ! curl -fsSL -o "$AGENT_BIN" "$AGENT_URL"; then
    echo -e "  ${RED}ERROR: Failed to download EasyRMM agent${NC}"
    exit 1
fi
chmod +x "$AGENT_BIN"

echo -e "  Enrolling agent with server..."
"$AGENT_BIN" --server "$SERVER_URL" --enroll "$ENROLL_TOKEN" --config "$CONFIG_FILE"

echo -e "  Installing systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=EasyRMM Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_BIN --server $SERVER_URL --config $CONFIG_FILE
Restart=always
RestartSec=10
User=root
WorkingDirectory=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"
echo -e "  ${GREEN}EasyRMM Agent installed and started.${NC}"

# ── Step 3: Install EasyPatch Agent (optional) ─────────────────
if [ "$SKIP_EASYPATCH" = false ]; then
    echo -e "${YELLOW}[3/3] Installing EasyPatch Agent...${NC}"
    # EasyPatch is Windows-only currently; skip on Linux
    echo -e "  ${YELLOW}EasyPatch is currently Windows-only. Skipping.${NC}"
else
    echo -e "[3/3] Skipping EasyPatch Agent (--skip-easypatch)"
fi

echo ""
echo -e "${CYAN}=====================================${NC}"
echo -e "${GREEN}  Installation Complete${NC}"
echo -e "${CYAN}=====================================${NC}"
echo "  Server:  $SERVER_URL"
echo "  Config:  $CONFIG_FILE"
echo "  Service: $SERVICE_NAME"
echo ""
echo "  Check status: systemctl status $SERVICE_NAME"
echo ""
