#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Parental Gateway - "why isn't my block working?"
#
# Walks every layer between the dashboard button and the wire, and tells you
# which one is broken. Safe to run at any time; it only reads state.
#
#   bash scripts/diagnose.sh
#   curl -fsSL https://raw.githubusercontent.com/Thorinas112/parental-gateway/main/scripts/diagnose.sh | bash
#
# Optionally pass a device IP to check that specific client:
#
#   bash scripts/diagnose.sh 192.168.1.152
# ---------------------------------------------------------------------------
set -uo pipefail

TARGET_IP="${1:-}"
PROJECT_DIR="${PROJECT_DIR:-$HOME/deploy/parental-gateway}"
CONTAINER="${CONTAINER:-parental-gateway}"

PASS=0
FAIL=0
say()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
info() { printf '       %s\n' "$*"; }
hint() { printf '  \033[1;33m->\033[0m  %s\n' "$*"; }

SUDO=""
if ! docker info >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
fi
D() { $SUDO docker "$@"; }

echo "============================================================"
echo " Parental Gateway diagnostics"
echo "============================================================"

# ---------------------------------------------------------------- 1. container
say "1. Container"
if D ps --filter name="^${CONTAINER}$" --format '{{.Status}}' | grep -q Up; then
    ok "running: $(D ps --filter name="^${CONTAINER}$" --format '{{.Status}}')"
else
    bad "container '${CONTAINER}' is not running"
    hint "start it: cd $PROJECT_DIR && docker compose -f docker-compose.yml -f docker-compose.build.yml up -d"
    echo; echo "Nothing below can work without the container. Fix this first."; exit 1
fi

# ---------------------------------------------------------------- 2. forwarding
say "2. IP forwarding (without this, FORWARD sees no packets)"
FWD=$(D exec "$CONTAINER" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "?")
if [ "$FWD" = "1" ]; then
    ok "net.ipv4.ip_forward = 1"
else
    bad "net.ipv4.ip_forward = $FWD  <- packets are NOT being routed"
    hint "sudo sysctl -w net.ipv4.ip_forward=1"
    hint "echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-forwarding.conf"
    hint "if refused: this host is an LXC -> set lxc.sysctl.net.ipv4.ip_forward: 1 on the hypervisor"
fi

# ---------------------------------------------------------------- 3. firewall
say "3. Firewall mode"
CHAINS=$(D exec "$CONTAINER" iptables -S 2>/dev/null || true)
if echo "$CHAINS" | grep -q '^-N PCTRL'; then
    ok "PCTRL chain exists (enforcement is live, not dry-run)"
else
    bad "PCTRL chain missing - the app is in dry-run mode"
    hint "check FIREWALL_MODE in .env (should be 'auto'), and that the container has cap_add: NET_ADMIN"
fi

# ---------------------------------------------------------------- 4. rules
say "4. Installed block rules"
RULES=$(D exec "$CONTAINER" iptables -S PCTRL 2>/dev/null || true)
BLOCKED=$(echo "$RULES" | grep -c 'j DROP' || true)
if [ "$BLOCKED" -gt 0 ]; then
    ok "$BLOCKED device(s) currently blocked in the kernel"
    echo "$RULES" | grep 'j DROP' | sed 's/^/       /'
else
    info "no DROP rules installed right now (nothing is blocked in the UI, or it has not reconciled)"
    hint "the app reconciles every 20s - press 'Apply' in the dashboard to force it"
fi

# ---------------------------------------------------------------- 5. transit
say "5. Is client traffic actually transiting this box?"
echo "       (byte counters on the per-device accounting chain)"
STATS=$(D exec "$CONTAINER" iptables -L PCTRL-STAT -vnx 2>/dev/null | tail -n +3 || true)
TRANSIT=$(echo "$STATS" | awk '$2 > 0 {count++} END {print count+0}')
TOTAL=$(echo "$STATS" | grep -c . || true)
if [ "$TRANSIT" -gt 0 ]; then
    ok "$TRANSIT of $TOTAL tracked address(es) have moved traffic through the box"
else
    bad "ZERO bytes have transited this box"
    hint "clients are not routing through it. Their default gateway is probably still the router."
    hint "check a client: 'ip route | grep default' must show this box's IP"
    hint "then set your DHCP 'router' option to this box - see docs/DEPLOYMENT.md section 5"
fi
echo "       top counters:"
echo "$STATS" | awk '$2 > 0 {printf "         %12s B  ->  %s\n", $2, $NF}' | head -5
[ "$TRANSIT" -eq 0 ] && echo "         (all zero)"

# ---------------------------------------------------------------- 6. dns
say "6. DNS interception"
if D exec "$CONTAINER" iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'dport 53'; then
    ok "port-53 redirect installed (web filtering cannot be bypassed)"
    D exec "$CONTAINER" iptables -t nat -S PREROUTING 2>/dev/null | grep 'dport 53' | sed 's/^/       /'
else
    bad "no DNS redirect - clients can point at any resolver and bypass filtering"
    hint "enable DNS filtering in the dashboard Settings panel"
fi

# ---------------------------------------------------------------- 7. client
if [ -n "$TARGET_IP" ]; then
    say "7. Device $TARGET_IP"
    DEV=$(D exec "$CONTAINER" python -c "
import sqlite3, sys
c = sqlite3.connect('/app/data/app.db')
row = c.execute('SELECT mac, custom_name, hostname, approved, blocked, last_seen FROM devices WHERE ip=? OR last_ip=?', ('$TARGET_IP', '$TARGET_IP')).fetchone()
print('|'.join(str(x) for x in row) if row else 'none')
" 2>/dev/null || echo "none")

    if [ "$DEV" = "none" ]; then
        bad "no device recorded for $TARGET_IP"
        hint "press Scan in the dashboard, then try again"
    else
        IFS='|' read -r MAC NAME HOST APPROVED BLOCKED LAST <<< "$DEV"
        ok "known device  mac=$MAC  name=${NAME:-$HOST}  approved=$APPROVED  blocked=$BLOCKED"
        if D exec "$CONTAINER" iptables -S PCTRL 2>/dev/null | grep -qi "$MAC"; then
            ok "a DROP rule for $MAC is installed in the kernel"
        else
            bad "no DROP rule for $MAC in the kernel"
            hint "toggle the device's access switch in the dashboard, then wait 20s"
        fi
    fi

    say "    MAC randomisation"
    info "iPhones (iOS 14+) and Androids (10+) use a randomised MAC per network."
    info "If the phone joined with a different MAC than the one recorded, the rule"
    info "cannot match. Check the phone's actual MAC:"
    info "  iOS:     Settings -> Wi-Fi -> (i) next to the network -> Wi-Fi Address"
    info "  Android: Settings -> Network -> Wi-Fi -> gear -> Advanced -> MAC address"
    info "and compare with the MAC shown in the dashboard."
fi

# ---------------------------------------------------------------- verdict
echo
echo "============================================================"
if [ "$FAIL" -eq 0 ]; then
    echo " All checks passed."
    echo
    echo " If a device is still online after being blocked:"
    echo "   1. confirm its default route really points at this box"
    echo "   2. watch the rule appear:  docker exec $CONTAINER watch -n1 iptables -S PCTRL"
    echo "   3. make sure you blocked the MAC the device is actually using now"
else
    echo " $FAIL check(s) failed - see the hints above, top to bottom."
    echo " Layers are ordered: fix an earlier one before worrying about a later one."
fi
echo "============================================================"
exit $FAIL
