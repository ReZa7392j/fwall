#!/usr/bin/env bash
# engine.sh — fwall iptables executor
# Called by fwall.py via subprocess. Never run rules logic here.
# Usage: engine.sh <action> [args...]
#
# Actions:
#   flush                          — clear all rules
#   policy <ACCEPT|DROP>           — set default INPUT policy
#   apply <action> <proto> <port> <direction> [from_ip] [to_ip]
#   delete <action> <proto> <port> <direction> [from_ip] [to_ip]
#   status                         — print current iptables state
#   save                           — save iptables rules to disk
#   restore                        — restore iptables rules from disk

set -euo pipefail

IPT="iptables"
SAVE_FILE="/etc/fwall/iptables.rules"

# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[engine] ERROR: must be run as root" >&2
        exit 1
    fi
}

log() {
    echo "[engine] $*"
}

# Build the iptables rule arguments from parameters
# Usage: build_rule_args <proto> <port> <direction> [from_ip] [to_ip]
build_rule_args() {
    local proto="$1"
    local port="$2"
    local direction="$3"
    local from_ip="${4:-}"
    local to_ip="${5:-}"

    local chain args=""

    # Direction → chain
    case "$direction" in
        in)  chain="INPUT"   ;;
        out) chain="OUTPUT"  ;;
        fwd) chain="FORWARD" ;;
        *)
            echo "[engine] ERROR: unknown direction '$direction'" >&2
            exit 1
            ;;
    esac

    # Protocol
    if [[ "$proto" != "any" ]]; then
        args="$args -p $proto"
    fi

    # Port (only if not "any")
    if [[ "$port" != "any" ]]; then
        if [[ "$proto" == "tcp" || "$proto" == "udp" ]]; then
            args="$args --dport $port"
        fi
    fi

    # Source IP / subnet
    if [[ -n "$from_ip" && "$from_ip" != "any" ]]; then
        args="$args -s $from_ip"
    fi

    # Destination IP / subnet
    if [[ -n "$to_ip" && "$to_ip" != "any" ]]; then
        args="$args -d $to_ip"
    fi

    echo "$chain $args"
}

# ─────────────────────────────────────────
# Actions
# ─────────────────────────────────────────

do_flush() {
    log "Flushing all rules..."
    $IPT -F
    $IPT -X
    $IPT -Z
    $IPT -t nat -F
    $IPT -t nat -X
    $IPT -t mangle -F
    $IPT -t mangle -X
    # Set all chains to ACCEPT so machine isn't locked out after flush
    $IPT -P INPUT   ACCEPT
    $IPT -P FORWARD ACCEPT
    $IPT -P OUTPUT  ACCEPT
    log "Flush complete."
}

do_policy() {
    local policy="${1:-ACCEPT}"
    if [[ "$policy" != "ACCEPT" && "$policy" != "DROP" ]]; then
        echo "[engine] ERROR: policy must be ACCEPT or DROP" >&2
        exit 1
    fi
    log "Setting default INPUT policy to $policy"
    $IPT -P INPUT "$policy"
}

do_apply() {
    local action="$1"   # ACCEPT or DROP
    local proto="$2"
    local port="$3"
    local direction="$4"
    local from_ip="${5:-any}"
    local to_ip="${6:-any}"

    read -r chain extra_args <<< "$(build_rule_args "$proto" "$port" "$direction" "$from_ip" "$to_ip")"

    log "Applying: $chain $extra_args -j $action"
    # shellcheck disable=SC2086
    $IPT -A "$chain" $extra_args -j "$action"
}

do_delete() {
    local action="$1"
    local proto="$2"
    local port="$3"
    local direction="$4"
    local from_ip="${5:-any}"
    local to_ip="${6:-any}"

    read -r chain extra_args <<< "$(build_rule_args "$proto" "$port" "$direction" "$from_ip" "$to_ip")"

    log "Deleting: $chain $extra_args -j $action"
    # shellcheck disable=SC2086
    if $IPT -D "$chain" $extra_args -j "$action" 2>/dev/null; then
        log "Rule deleted."
    else
        echo "[engine] WARNING: rule not found, nothing deleted." >&2
    fi
}

do_status() {
    echo "════════════════════════════════════════"
    echo "  fwall — iptables status"
    echo "════════════════════════════════════════"
    $IPT -L -n -v --line-numbers
}

do_save() {
    log "Saving iptables rules to $SAVE_FILE"
    mkdir -p "$(dirname "$SAVE_FILE")"
    iptables-save > "$SAVE_FILE"
    log "Saved."
}

do_restore() {
    if [[ ! -f "$SAVE_FILE" ]]; then
        echo "[engine] WARNING: no saved rules at $SAVE_FILE" >&2
        exit 0
    fi
    log "Restoring iptables rules from $SAVE_FILE"
    iptables-restore < "$SAVE_FILE"
    log "Restored."
}

# ─────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────

require_root

ACTION="${1:-}"
shift || true

case "$ACTION" in
    flush)   do_flush                          ;;
    policy)  do_policy   "$@"                  ;;
    apply)   do_apply    "$@"                  ;;
    delete)  do_delete   "$@"                  ;;
    status)  do_status                         ;;
    save)    do_save                           ;;
    restore) do_restore                        ;;
    *)
        echo "[engine] ERROR: unknown action '$ACTION'" >&2
        echo "Usage: engine.sh {flush|policy|apply|delete|status|save|restore}" >&2
        exit 1
        ;;
esac
