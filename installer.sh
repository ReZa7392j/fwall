#!/usr/bin/env bash
# installer.sh — fwall system installer
# Run as root: sudo bash installer.sh
# To uninstall: sudo bash installer.sh --uninstall

set -euo pipefail

# ─────────────────────────────────────────
# Paths
# ─────────────────────────────────────────

BIN_TARGET="/usr/local/bin/fwall"
LIB_DIR="/usr/local/lib/fwall"
CONF_DIR="/etc/fwall"
CONF_TARGET="$CONF_DIR/fwall.conf"
SERVICE_TARGET="/etc/systemd/system/fwall.service"
LOG_FILE="/var/log/fwall.log"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✔${NC}  $*"; }
warn() { echo -e "${YELLOW}  ⚠${NC}  $*"; }
err()  { echo -e "${RED}  ✘${NC}  $*"; exit 1; }
info() { echo -e "     $*"; }

require_root() {
    [[ $EUID -eq 0 ]] || err "installer.sh must be run as root. Use: sudo bash installer.sh"
}

check_deps() {
    info "Checking dependencies..."
    local missing=()
    for cmd in python3 iptables iptables-save iptables-restore systemctl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing required commands: ${missing[*]}"
    fi

    # Python 3.10+ required (for match/case)
    py_ver=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    py_minor=$(python3 -c "import sys; print(sys.version_info.minor)")
    if [[ $(python3 -c "import sys; print(sys.version_info.major)") -lt 3 || $py_minor -lt 10 ]]; then
        err "Python 3.10+ required (found $py_ver)"
    fi
    ok "Dependencies satisfied (Python $py_ver)"
}

# ─────────────────────────────────────────
# Install
# ─────────────────────────────────────────

do_install() {
    echo ""
    echo "  ┌──────────────────────────────┐"
    echo "  │   fwall installer            │"
    echo "  └──────────────────────────────┘"
    echo ""

    require_root
    check_deps

    # 1. Create directories
    info "Creating directories..."
    mkdir -p "$LIB_DIR" "$CONF_DIR"
    ok "Directories created: $LIB_DIR, $CONF_DIR"

    # 2. Install engine.sh
    info "Installing engine.sh..."
    cp "$SCRIPT_DIR/engine.sh" "$LIB_DIR/engine.sh"
    chmod 750 "$LIB_DIR/engine.sh"
    ok "engine.sh → $LIB_DIR/engine.sh"

    # 3. Install fwall.py as /usr/local/bin/fwall
    info "Installing fwall binary..."
    cp "$SCRIPT_DIR/fwall.py" "$BIN_TARGET"
    chmod 755 "$BIN_TARGET"
    ok "fwall.py → $BIN_TARGET"

    # 4. Install config (don't overwrite existing)
    info "Installing config..."
    if [[ -f "$CONF_TARGET" ]]; then
        warn "Config already exists at $CONF_TARGET — skipping (keeping your settings)"
    else
        cp "$SCRIPT_DIR/fwall.conf" "$CONF_TARGET"
        chmod 640 "$CONF_TARGET"
        ok "fwall.conf → $CONF_TARGET"
    fi

    # 5. Create log file
    info "Setting up log file..."
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    ok "Log file ready: $LOG_FILE"

    # 6. Install systemd service
    info "Installing systemd service..."
    cp "$SCRIPT_DIR/fwall.service" "$SERVICE_TARGET"
    chmod 644 "$SERVICE_TARGET"
    systemctl daemon-reload
    ok "fwall.service → $SERVICE_TARGET"

    # 7. Done
    echo ""
    echo "  ┌──────────────────────────────────────────────────┐"
    echo "  │   fwall installed successfully!                  │"
    echo "  │                                                  │"
    echo "  │   Quick start:                                   │"
    echo "  │     sudo fwall allow 22        # allow SSH       │"
    echo "  │     sudo fwall default deny    # block the rest  │"
    echo "  │     sudo fwall start           # activate        │"
    echo "  │     sudo fwall enable          # survive reboot  │"
    echo "  │                                                  │"
    echo "  │   Config:  /etc/fwall/fwall.conf                 │"
    echo "  │   Logs:    /var/log/fwall.log                    │"
    echo "  └──────────────────────────────────────────────────┘"
    echo ""
}

# ─────────────────────────────────────────
# Uninstall
# ─────────────────────────────────────────

do_uninstall() {
    echo ""
    info "Uninstalling fwall..."
    require_root

    # Stop and disable service
    if systemctl is-active --quiet fwall 2>/dev/null; then
        systemctl stop fwall
        ok "fwall service stopped"
    fi
    if systemctl is-enabled --quiet fwall 2>/dev/null; then
        systemctl disable fwall
        ok "fwall service disabled"
    fi

    # Remove files
    local removed=()
    for path in "$BIN_TARGET" "$SERVICE_TARGET"; do
        if [[ -f "$path" ]]; then
            rm -f "$path"
            removed+=("$path")
        fi
    done
    for path in "$LIB_DIR"; do
        if [[ -d "$path" ]]; then
            rm -rf "$path"
            removed+=("$path")
        fi
    done

    systemctl daemon-reload

    echo ""
    warn "The following were NOT removed (your data):"
    info "  $CONF_DIR   (config + rules)"
    info "  $LOG_FILE   (logs)"
    info "To fully remove: sudo rm -rf $CONF_DIR $LOG_FILE"
    echo ""

    for f in "${removed[@]}"; do ok "Removed: $f"; done
    ok "fwall uninstalled."
    echo ""
}

# ─────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────

case "${1:-install}" in
    --uninstall|-u) do_uninstall ;;
    --install|-i|install|"") do_install ;;
    *)
        echo "Usage: sudo bash installer.sh [--install|--uninstall]"
        exit 1
        ;;
esac
