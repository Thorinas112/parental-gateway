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
import shutil
import threading
from typing import Any, Iterable

from .config import Config
from .utils import norm_mac, run_command

log = logging.getLogger("pg.firewall")

IPT = "iptables"
CHAIN = Config.FIREWALL_CHAIN

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
        "available": iptables_available(),
        "dry_run": dry_run(),
        "mode": Config.FIREWALL_MODE,
        "blocked_count": len(_state.get("last_applied", [])),
        "last_ok": _state.get("last_ok"),
        "last_error": _state.get("last_error"),
        "last_applied": _state.get("last_applied", []),
    }
