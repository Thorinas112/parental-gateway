#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Parental Gateway - container entrypoint
#
#   1. Enables IPv4 forwarding (gateway mode)
#   2. Applies the default NAT / forwarding policy
#   3. Optionally configures the LAN interface address
#   4. Hands over to the Python web application
# ---------------------------------------------------------------------------
set -euo pipefail

log()  { echo "[entrypoint] $*"; }
warn() { echo "[entrypoint] WARN: $*" >&2; }

LAN_IFACE="${LAN_IFACE:-eth0}"
WAN_IFACE="${WAN_IFACE:-${LAN_IFACE}}"
LAN_SUBNET="${LAN_SUBNET:-}"
LAN_IP_CIDR="${LAN_IP_CIDR:-}"
GATEWAY_MODE="${GATEWAY_MODE:-1}"
FIREWALL_MODE="${FIREWALL_MODE:-auto}"

# ---------------------------------------------------------------------------
# 1. IP forwarding
# ---------------------------------------------------------------------------
enable_ip_forwarding() {
    if [ -w /proc/sys/net/ipv4/ip_forward ]; then
        if echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then
            log "net.ipv4.ip_forward = 1 (via /proc)"
        else
            warn "could not write /proc/sys/net/ipv4/ip_forward"
        fi
    elif sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
        log "net.ipv4.ip_forward = 1 (via sysctl)"
    else
        warn "could not enable net.ipv4.ip_forward - run with --cap-add NET_ADMIN"
    fi

    # Keep connection tracking happy across long-lived NAT sessions.
    if [ -w /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established ]; then
        echo 86400 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# 2. Auto-detect the LAN subnet when it was not supplied
# ---------------------------------------------------------------------------
detect_lan_subnet() {
    if [ -n "$LAN_SUBNET" ]; then
        return 0
    fi
    if ! command -v ip >/dev/null 2>&1; then
        return 0
    fi

    # Prefer the kernel's own connected route - it gives the *network* address
    # (192.168.1.0/24) rather than the interface address (192.168.1.156/24).
    local network
    network="$(ip -o -4 route show dev "$LAN_IFACE" proto kernel 2>/dev/null | awk '{print $1}' | head -n1 || true)"

    # Fallback: normalise the interface address to its network.
    if [ -z "$network" ]; then
        local cidr
        cidr="$(ip -o -4 addr show dev "$LAN_IFACE" 2>/dev/null | awk '{print $4}' | head -n1 || true)"
        if [ -n "$cidr" ]; then
            network="$(python3 -c 'import ipaddress,sys;print(ipaddress.ip_network(sys.argv[1],strict=False))' "$cidr" 2>/dev/null || echo "$cidr")"
        fi
    fi

    if [ -n "$network" ]; then
        LAN_SUBNET="$network"
        log "auto-detected LAN_SUBNET=$LAN_SUBNET on $LAN_IFACE"
    else
        warn "could not auto-detect LAN_SUBNET for $LAN_IFACE - NAT rules skipped"
    fi
}

# ---------------------------------------------------------------------------
# 3. Optional static address on the LAN interface
# ---------------------------------------------------------------------------
configure_lan_interface() {
    if [ -z "$LAN_IP_CIDR" ]; then
        return 0
    fi
    if ! command -v ip >/dev/null 2>&1; then
        warn "iproute2 not available - skipping LAN_IP_CIDR"
        return 0
    fi
    ip link set "$LAN_IFACE" up || warn "could not bring $LAN_IFACE up"
    ip addr replace "$LAN_IP_CIDR" dev "$LAN_IFACE" || warn "could not assign $LAN_IP_CIDR to $LAN_IFACE"
    log "LAN interface $LAN_IFACE configured with $LAN_IP_CIDR"
}

# ---------------------------------------------------------------------------
# 4. Default NAT + forwarding policy
# ---------------------------------------------------------------------------
setup_nat() {
    if [ -z "$LAN_SUBNET" ]; then
        warn "LAN_SUBNET empty - skipping NAT bootstrap (the app will retry later)"
        return 0
    fi
    if ! command -v iptables >/dev/null 2>&1; then
        warn "iptables not found in the image - skipping NAT bootstrap"
        return 0
    fi

    # Masquerade LAN traffic leaving via the WAN interface.
    if ! iptables -t nat -C POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IFACE" -j MASQUERADE \
            || warn "could not add MASQUERADE rule"
        log "NAT: MASQUERADE $LAN_SUBNET -> $WAN_IFACE"
    fi

    # Established / related traffic back into the LAN.
    if ! iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
        iptables -I FORWARD 1 -m state --state ESTABLISHED,RELATED -j ACCEPT \
            || warn "could not add ESTABLISHED/RELATED rule"
    fi

    # Allow LAN -> WAN by default; the PCTRL chain (managed by the app)
    # is inserted at the top of FORWARD and applies the MAC-based blocks.
    if ! iptables -C FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT \
            || warn "could not add LAN->WAN forward rule"
    fi
    if ! iptables -C FORWARD -i "$LAN_IFACE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$LAN_IFACE" -j ACCEPT \
            || warn "could not add LAN forward rule"
    fi

    log "forwarding policy initialised (LAN=$LAN_IFACE WAN=$WAN_IFACE SUBNET=$LAN_SUBNET)"
}

# ---------------------------------------------------------------------------
# 5. Firewall chain bootstrap is performed by the application itself
#    (see app/firewall.py) so that rule ownership lives in one place.
# ---------------------------------------------------------------------------

if [ "$GATEWAY_MODE" = "1" ] || [ "$GATEWAY_MODE" = "true" ]; then
    enable_ip_forwarding
    configure_lan_interface
    detect_lan_subnet
    setup_nat
else
    log "GATEWAY_MODE=0 - skipping forwarding/NAT bootstrap"
fi

if [ "$FIREWALL_MODE" = "off" ]; then
    log "FIREWALL_MODE=off - application runs in dry-run mode"
fi

# Make the detected values visible to the Python process.
export LAN_IFACE WAN_IFACE LAN_SUBNET LAN_IP_CIDR GATEWAY_MODE FIREWALL_MODE

log "starting web application on port ${WEB_PORT:-8080}"
exec python -m app
