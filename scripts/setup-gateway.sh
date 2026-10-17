#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Parental Gateway - host-side network helper
#
# Prepares a Linux host to route LAN traffic through the gateway container.
# This script only touches kernel sysctls and prints the iptables lines you
# need - it never writes to the application's managed PCTRL chain.
#
#   sudo ./scripts/setup-gateway.sh --lan eth1 --wan eth0 --subnet 192.168.1.0/24
#   sudo ./scripts/setup-gateway.sh --lan eth1 --wan eth0 --subnet 192.168.1.0/24 --apply
# ---------------------------------------------------------------------------
set -euo pipefail

LAN_IFACE="eth0"
WAN_IFACE="eth0"
LAN_SUBNET=""
LAN_IP_CIDR=""
APPLY=0
PORT=8080

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options
  --lan  <iface>    interface facing LAN clients   (default: eth0)
  --wan  <iface>    interface facing the internet  (default: same as --lan)
  --subnet <cidr>   client subnet, e.g. 192.168.1.0/24
  --ip   <cidr>     assign a static address to the LAN interface
  --port <port>     web UI port to open in the firewall hints (default 8080)
  --apply           also execute the printed iptables rules
  -h, --help        show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --lan)    LAN_IFACE="$2"; shift 2 ;;
        --wan)    WAN_IFACE="$2"; shift 2 ;;
        --subnet) LAN_SUBNET="$2"; shift 2 ;;
        --ip)     LAN_IP_CIDR="$2"; shift 2 ;;
        --port)   PORT="$2"; shift 2 ;;
        --apply)  APPLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "please run as root (sudo)" >&2; exit 1; }

echo "==> Parental Gateway host setup"
echo "    LAN interface : $LAN_IFACE"
echo "    WAN interface : $WAN_IFACE"
echo "    LAN subnet    : ${LAN_SUBNET:-<auto>}"

# ---------------------------------------------------------------------------
# 1. IP forwarding
# ---------------------------------------------------------------------------
echo
echo "==> Enabling IPv4 forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1
if ! grep -qs '^net.ipv4.ip_forward=1' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null; then
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-parental-gateway.conf
    echo "    wrote /etc/sysctl.d/99-parental-gateway.conf"
fi

# ---------------------------------------------------------------------------
# 2. Optional LAN address
# ---------------------------------------------------------------------------
if [ -n "$LAN_IP_CIDR" ]; then
    echo
    echo "==> Configuring $LAN_IFACE with $LAN_IP_CIDR"
    ip link set "$LAN_IFACE" up
    ip addr replace "$LAN_IP_CIDR" dev "$LAN_IFACE"
    ip -o -4 addr show dev "$LAN_IFACE"
fi

# ---------------------------------------------------------------------------
# 3. Auto-detect the subnet if not supplied
# ---------------------------------------------------------------------------
if [ -z "$LAN_SUBNET" ]; then
    LAN_SUBNET="$(ip -o -4 addr show dev "$LAN_IFACE" 2>/dev/null | awk '{print $4}' | head -n1 || true)"
    echo
    echo "==> Auto-detected LAN subnet: ${LAN_SUBNET:-<none found>}"
fi

# ---------------------------------------------------------------------------
# 4. iptables baseline
# ---------------------------------------------------------------------------
echo
echo "==> iptables baseline (LAN=$LAN_IFACE WAN=$WAN_IFACE SUBNET=${LAN_SUBNET:-n/a})"

RULES=(
    "iptables -t nat -A POSTROUTING -s ${LAN_SUBNET:-0.0.0.0/0} -o $WAN_IFACE -j MASQUERADE"
    "iptables -I FORWARD 1 -m state --state ESTABLISHED,RELATED -j ACCEPT"
    "iptables -A FORWARD -i $LAN_IFACE -o $WAN_IFACE -j ACCEPT"
    "iptables -A FORWARD -i $LAN_IFACE -j ACCEPT"
)

for rule in "${RULES[@]}"; do
    echo "    $rule"
done

if [ "$APPLY" -eq 1 ]; then
    echo
    echo "==> Applying rules"
    for rule in "${RULES[@]}"; do
        # skip if the identical rule already exists
        check="${rule/ -A / -C }"
        check="${check/ -I FORWARD 1 / -C FORWARD }"
        if ! eval "$check" >/dev/null 2>&1; then
            eval "$rule"
            echo "    added: $rule"
        else
            echo "    exists: $rule"
        fi
    done
else
    echo
    echo "    (dry run - re-run with --apply to execute)"
fi

# ---------------------------------------------------------------------------
# 5. Firewall hints
# ---------------------------------------------------------------------------
cat <<EOF

==> Firewall hints
    Allow the web UI from your LAN only:

        iptables -A INPUT -p tcp -s ${LAN_SUBNET:-<your-subnet>} --dport $PORT -j ACCEPT
        iptables -A INPUT -p tcp --dport $PORT -j DROP

    If you use ufw:

        ufw route allow in on $LAN_IFACE out on $WAN_IFACE
        ufw allow from ${LAN_SUBNET:-<your-subnet>} to any port $PORT proto tcp

==> Next steps
    1. Start the container:   docker compose up -d --build
    2. Point your DHCP 'router' option at this host (${LAN_IP_CIDR:-<LAN IP>})
    3. Open http://<lan-ip>:$PORT and press "Scan"

EOF
