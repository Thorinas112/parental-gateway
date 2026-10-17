"""iptables backend.

All enforcement lives in one dedicated chain (``PCTRL`` by default) that is
jumped to from the top of ``FORWARD``. The chain is declaratively rebuilt on
every reconcile: the app computes *which MACs should be dropped* and this
module makes the kernel ruleset match that list exactly.

Three operating modes (``FIREWALL_MODE``):

``auto``  use iptables when the binary is present, otherwise dry-run
``force`` require iptables and raise when it is unavailable
``off``   never touch the kernel; the UI still shows the computed ruleset
"""

from __future__ import annotations

import logging
import re
import shutil
import threading
from typing import Any, Iterable

from .config import Config
from .utils import norm_mac, run_command

log = logging.getLogger("pg.firewall")

IPT = "iptables"
IPT_SAVE = "iptables-save"
CHAIN = Config.FIREWALL_CHAIN
STAT_CHAIN = Config.FIREWALL_STAT_CHAIN

_lock = threading.RLock()
_state: dict[str, Any] = {
    "last_applied": [],
    "last_error": None,
    "last_ok": None,
    "dry_run": None,
}


class FirewallUnavailable(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Low level helpers
# --------------------------------------------------------------------------
def _run(args: list[str], timeout: int = 20):
    return run_command([IPT, *args], timeout=timeout)


_available: dict[str, Any] = {"value": None}


def iptables_available() -> bool:
    if _available["value"] is not None:
        return bool(_available["value"])
    if Config.FIREWALL_MODE == "off":
        _available["value"] = False
        return False
    if shutil.which(IPT) is None:
        _available["value"] = False
        return False
    probe = _run(["-w", "-L", "-n"])
    _available["value"] = probe.returncode == 0
    if not _available["value"]:
        log.warning("iptables probe failed: %s", (probe.stderr or "").strip())
    return bool(_available["value"])


def dry_run() -> bool:
    """True when rules are computed but not applied to the kernel."""
    if Config.FIREWALL_MODE == "off":
        return True
    return not iptables_available()


def _require() -> None:
    if Config.FIREWALL_MODE == "force" and not iptables_available():
        raise FirewallUnavailable("iptables is required (FIREWALL_MODE=force) but not usable")


def _ensure_rule(check_args: list[str], insert_args: list[str]) -> bool:
    """Add ``insert_args`` when ``check_args`` reports the rule is absent."""
    if _run(["-w", *check_args]).returncode == 0:
        return False
    result = _run(["-w", *insert_args])
    return result.returncode == 0


# --------------------------------------------------------------------------
# Chain management
# --------------------------------------------------------------------------
def ensure_chain() -> None:
    with _lock:
        _run(["-w", "-N", CHAIN])  # already-exists -> non-zero, harmless
        _ensure_rule(
            ["-C", "FORWARD", "-j", CHAIN],
            ["-I", "FORWARD", "1", "-j", CHAIN],
        )


def apply_rules(blocked_macs: Iterable[str]) -> dict[str, Any]:
    """Make the ``PCTRL`` chain drop exactly ``blocked_macs``."""
    macs = sorted({m for m in (norm_mac(x) for x in blocked_macs) if m})
    _require()

    if dry_run():
        _state.update({"last_applied": macs, "last_ok": True, "last_error": None, "dry_run": True})
        return {"applied": macs, "dry_run": True, "count": len(macs)}

    with _lock:
        try:
            ensure_chain()
            flushed = _run(["-w", "-F", CHAIN])
            if flushed.returncode != 0:
                raise RuntimeError((flushed.stderr or "iptables flush failed").strip())

            for mac in macs:
                result = _run(["-w", "-A", CHAIN, "-m", "mac", "--mac-source", mac, "-j", "DROP"])
                if result.returncode != 0:
                    raise RuntimeError(
                        (result.stderr or f"failed to add rule for {mac}").strip()
                    )

            # Explicit terminator keeps the chain readable in `iptables -S`.
            _run(["-w", "-A", CHAIN, "-j", "RETURN"])

            _state.update(
                {
                    "last_applied": macs,
                    "last_ok": True,
                    "last_error": None,
                    "dry_run": False,
                }
            )
            return {"applied": macs, "dry_run": False, "count": len(macs)}
        except Exception as exc:  # noqa: BLE001
            _state.update({"last_ok": False, "last_error": str(exc), "dry_run": False})
            log.error("failed to apply firewall rules: %s", exc)
            raise


def flush_chain() -> None:
    if dry_run():
        _state["last_applied"] = []
        return
    with _lock:
        _run(["-w", "-F", CHAIN])
        _state["last_applied"] = []


# --------------------------------------------------------------------------
# NAT / forwarding policy
# --------------------------------------------------------------------------
def setup_nat(lan_subnet: str, wan_iface: str, lan_iface: str | None = None) -> dict[str, Any]:
    """Install the baseline MASQUERADE + forwarding rules."""
    if not lan_subnet:
        return {"applied": False, "reason": "no LAN subnet configured"}
    if dry_run():
        return {"applied": False, "dry_run": True, "reason": "firewall in dry-run mode"}

    actions: list[str] = []
    with _lock:
        if _ensure_rule(
            ["-t", "nat", "-C", "POSTROUTING", "-s", lan_subnet, "-o", wan_iface, "-j", "MASQUERADE"],
            ["-t", "nat", "-I", "POSTROUTING", "1", "-s", lan_subnet, "-o", wan_iface, "-j", "MASQUERADE"],
        ):
            actions.append("masquerade")

        if _ensure_rule(
            ["-C", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["-I", "FORWARD", "1", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ):
            actions.append("established")

        if lan_iface:
            if _ensure_rule(
                ["-C", "FORWARD", "-i", lan_iface, "-o", wan_iface, "-j", "ACCEPT"],
                ["-A", "FORWARD", "-i", lan_iface, "-o", wan_iface, "-j", "ACCEPT"],
            ):
                actions.append("lan-wan")

        ensure_chain()

    return {"applied": True, "actions": actions, "lan_subnet": lan_subnet, "wan_iface": wan_iface}


# --------------------------------------------------------------------------
# Introspection
# --------------------------------------------------------------------------
def dump_rules() -> dict[str, str]:
    """Return the current filter + nat rulesets for the UI."""
    if dry_run():
        computed = [f"-A {CHAIN} -m mac --mac-source {m} -j DROP" for m in _state.get("last_applied", [])]
        computed.append(f"-A {CHAIN} -j RETURN")
        return {
            "filter": "\n".join(computed) or f"# {CHAIN} chain is empty (dry-run)",
            "nat": "# dry-run - no kernel ruleset",
        }

    filter_out = _run(["-w", "-S"]).stdout or ""
    nat_out = _run(["-w", "-t", "nat", "-S"]).stdout or ""
    return {"filter": filter_out.strip(), "nat": nat_out.strip()}


def status() -> dict[str, Any]:
    return {
        "binary": IPT,
        "chain": CHAIN,
        "stat_chain": STAT_CHAIN,
        "available": iptables_available(),
        "dry_run": dry_run(),
        "mode": Config.FIREWALL_MODE,
        "blocked_count": len(_state.get("last_applied", [])),
        "last_ok": _state.get("last_ok"),
        "last_error": _state.get("last_error"),
        "last_applied": _state.get("last_applied", []),
    }


# ==========================================================================
# Accounting chain (traffic byte counters)
#
# A separate chain from PCTRL so that enforcement can be rebuilt freely while
# the counters keep accumulating. It is NEVER flushed - rules are only added
# or removed individually as devices come and go.
#
#   -A PCTRL-STAT -m mac --mac-source AA:BB:CC:DD:EE:01 -j RETURN   (upload)
#   -A PCTRL-STAT -d 192.168.1.10/32 -j RETURN                       (download)
#
# Upload is matched on the device's MAC; download arrives addressed to the
# *gateway*, so it has to be matched on the device's IP instead.
# ==========================================================================

_STAT_RULE_RE = re.compile(r"^\[(\d+):(\d+)\]\s+-A\s+(\S+)\s+(.*)$")
_MAC_SRC_RE = re.compile(r"--mac-source\s+([0-9A-Fa-f:]{17})", re.IGNORECASE)
_DST_IP_RE = re.compile(r"(?:^|\s)-d\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?")


def ensure_stat_chain() -> bool:
    """Create the accounting chain and jump to it from FORWARD."""
    if dry_run():
        return False
    with _lock:
        _run(["-w", "-N", STAT_CHAIN])
        # Position 2: after PCTRL, so enforcement is still evaluated first.
        _ensure_rule(
            ["-C", "FORWARD", "-j", STAT_CHAIN],
            ["-I", "FORWARD", "2", "-j", STAT_CHAIN],
        )
    return True


def list_stat_rules() -> list[dict[str, Any]]:
    """Return every rule in the accounting chain, with its byte counters.

    Each entry: ``{n, packets, bytes, mac, dst_ip}`` where ``n`` is the
    1-based rule number suitable for ``iptables -D <chain> <n>``.
    """
    if dry_run():
        return []

    proc = run_command([IPT_SAVE, "-c", "-t", "filter"])
    if proc.returncode != 0:
        log.debug("iptables-save failed: %s", (proc.stderr or "").strip())
        return []

    rules: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        match = _STAT_RULE_RE.match(line)
        if not match or match.group(3) != STAT_CHAIN:
            continue

        spec = match.group(4)
        mac_match = _MAC_SRC_RE.search(spec)
        dst_match = _DST_IP_RE.search(spec)
        rules.append(
            {
                "n": len(rules) + 1,
                "packets": int(match.group(1)),
                "bytes": int(match.group(2)),
                "mac": (mac_match.group(1).upper() if mac_match else None),
                "dst_ip": (dst_match.group(1) if dst_match else None),
                "spec": spec,
            }
        )
    return rules


def add_stat_upload_rule(mac: str) -> bool:
    if dry_run():
        return False
    normalised = norm_mac(mac)
    if not normalised:
        return False
    with _lock:
        return (
            _run(
                ["-w", "-A", STAT_CHAIN, "-m", "mac", "--mac-source", normalised, "-j", "RETURN"]
            ).returncode
            == 0
        )


def add_stat_download_rule(ip: str) -> bool:
    if dry_run() or not ip:
        return False
    with _lock:
        return _run(["-w", "-A", STAT_CHAIN, "-d", ip, "-j", "RETURN"]).returncode == 0


def delete_stat_rule(rule_number: int) -> bool:
    """Remove a rule by its 1-based number within the accounting chain."""
    if dry_run():
        return False
    with _lock:
        return _run(["-w", "-D", STAT_CHAIN, str(int(rule_number))]).returncode == 0


def flush_stat_chain() -> bool:
    """Discard all counters. Only used by tests and explicit resets."""
    if dry_run():
        return False
    with _lock:
        return _run(["-w", "-F", STAT_CHAIN]).returncode == 0


# ==========================================================================
# DNS interception
#
# Clients can bypass a DNS filter simply by talking to 8.8.8.8 directly. These
# PREROUTING rules redirect every DNS packet arriving from the LAN to the
# gateway's own resolver, whatever destination address the client used.
# ==========================================================================

_DNS_PROTOCOLS = ("udp", "tcp")


def _dns_rule(lan_iface: str, protocol: str, target_port: int, action: str = "A") -> list[str]:
    """Redirect LAN DNS traffic to the gateway's own resolver.

    The destination port stays 53 (that is what clients query), while
    ``--to-ports`` is whatever port the proxy actually listens on.
    """
    return [
        "-t", "nat", action, "PREROUTING",
        "-i", lan_iface, "-p", protocol, "--dport", "53",
        "-j", "REDIRECT", "--to-ports", str(int(target_port)),
    ]


def _purge_dns_redirects(lan_iface: str) -> int:
    """Remove every DNS redirect for this interface, whatever its target port.

    Necessary because the proxy may bind a different port after a restart, and
    a leftover rule would keep sending client queries at a dead port.
    """
    proc = _run(["-w", "-t", "nat", "-S", "PREROUTING"])
    if proc.returncode != 0:
        return 0

    doomed: list[list[str]] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("-A PREROUTING") or "-j REDIRECT" not in line:
            continue
        if f"-i {lan_iface}" not in line or "--dport 53" not in line:
            continue
        parts = line.split()
        doomed.append(["-t", "nat", "-D", "PREROUTING"] + parts[2:])

    removed = 0
    for spec in doomed:
        if _run(["-w", *spec]).returncode == 0:
            removed += 1
    return removed


def setup_dns_redirect(lan_iface: str, enabled: bool = True, target_port: int = 53) -> dict[str, Any]:
    """Enable or disable forced DNS interception for the LAN interface."""
    if dry_run():
        return {"applied": False, "dry_run": True, "enabled": enabled}
    if not lan_iface:
        return {"applied": False, "reason": "no LAN interface configured"}

    changed: list[str] = []
    with _lock:
        # Always start from a clean slate so port changes cannot leave orphans.
        removed = _purge_dns_redirects(lan_iface)
        if removed:
            changed.append(f"purge {removed}")

        if enabled:
            for protocol in _DNS_PROTOCOLS:
                if _run(["-w", *_dns_rule(lan_iface, protocol, target_port, "-A")]).returncode == 0:
                    changed.append(f"add {protocol}/{target_port}")

    return {"applied": True, "enabled": enabled, "target_port": target_port, "changed": changed}


def dns_redirect_active(lan_iface: str, target_port: int = 53) -> bool:
    if dry_run():
        return False
    for protocol in _DNS_PROTOCOLS:
        if _run(["-w", *_dns_rule(lan_iface, protocol, target_port, "-C")]).returncode != 0:
            return False
    return True
