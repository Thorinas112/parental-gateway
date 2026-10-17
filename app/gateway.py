"""Gateway helpers: IP forwarding, NAT bootstrapping and interface state."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from .config import Config
from .db import log_event
from . import firewall
from .utils import run_command

log = logging.getLogger("pg.gateway")

_PROC_FORWARD = "/proc/sys/net/ipv4/ip_forward"


# --------------------------------------------------------------------------
# IP forwarding
# --------------------------------------------------------------------------
def ip_forwarding_enabled() -> bool | None:
    try:
        with open(_PROC_FORWARD, "r", encoding="utf-8") as handle:
            return handle.read().strip() == "1"
    except OSError:
        return None


def enable_ip_forwarding() -> bool:
    try:
        with open(_PROC_FORWARD, "w", encoding="utf-8") as handle:
            handle.write("1")
        log.info("net.ipv4.ip_forward = 1")
        return True
    except OSError:
        proc = run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        if proc.returncode == 0:
            log.info("net.ipv4.ip_forward = 1 (sysctl)")
            return True
        log.warning("unable to enable net.ipv4.ip_forward: %s", (proc.stderr or "").strip())
        return False


# --------------------------------------------------------------------------
# Interface / subnet introspection
# --------------------------------------------------------------------------
def interface_info(iface: str) -> dict[str, Any]:
    proc = run_command(["ip", "-o", "-4", "addr", "show", "dev", iface])
    out = proc.stdout or ""
    addr_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", out)
    link = run_command(["ip", "-o", "link", "show", "dev", iface])
    state = "UP" if re.search(r"state\s+UP", link.stdout or "") else "DOWN"
    return {
        "name": iface,
        "address": addr_match.group(1) if addr_match else None,
        "state": state if proc.returncode == 0 else "missing",
    }


def list_interfaces() -> list[dict[str, Any]]:
    """Every usable interface, for the setup wizard's dropdowns."""
    proc = run_command(["ip", "-o", "-4", "addr", "show"])
    seen: dict[str, dict[str, Any]] = {}
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1].split("@", 1)[0]
        if name == "lo" or name in seen:
            continue
        seen[name] = {"name": name, "address": parts[3]}

    if not seen:
        link = run_command(["ip", "-o", "link", "show"])
        for line in (link.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[1].rstrip(":").split("@", 1)[0]
            if name != "lo":
                seen[name] = {"name": name, "address": None}

    result = []
    for entry in seen.values():
        info = interface_info(entry["name"])
        entry["state"] = info["state"]
        entry["address"] = entry["address"] or info["address"]
        result.append(entry)
    result.sort(key=lambda e: (e.get("address") is None, e["name"]))
    return result


def default_route_iface() -> str | None:
    """Interface carrying the default route (usually the WAN side)."""
    proc = run_command(["ip", "route", "show", "default"])
    match = re.search(r"\bdev\s+(\S+)", proc.stdout or "")
    return match.group(1) if match else None


# Virtual/container interfaces that are never the real LAN.
_VIRTUAL_PREFIXES = ("docker", "br-", "veth", "virbr", "lxdbr", "cni", "flannel", "tun", "tap", "wg")


def suggest_network() -> dict[str, Any]:
    """Best guess at the wizard's network defaults for this host.

    Prefers the interface holding the default route, then the first real
    (non-virtual) interface with an address, so a fresh install is never
    pre-filled with a name that does not exist.
    """
    ifaces = list_interfaces()
    route_iface = default_route_iface()

    def is_virtual(name: str) -> bool:
        return name.startswith(_VIRTUAL_PREFIXES) or name == "lo"

    real = [i for i in ifaces if not is_virtual(i["name"])]
    with_address = [i for i in real if i.get("address")]

    lan = None
    if route_iface and any(i["name"] == route_iface for i in ifaces):
        lan = route_iface
    elif with_address:
        lan = with_address[0]["name"]
    elif real:
        lan = real[0]["name"]
    elif ifaces:
        lan = ifaces[0]["name"]
    else:
        lan = "eth0"

    subnet = None
    address = None
    for entry in ifaces:
        if entry["name"] == lan:
            address = entry.get("address")
            break
    if address:
        try:
            subnet = str(ipaddress.ip_network(address, strict=False))
        except ValueError:
            subnet = None

    return {
        "lan_iface": lan,
        "wan_iface": route_iface or lan,
        "lan_subnet": subnet,
        "default_route_iface": route_iface,
    }


def resolve_wizard_network(configured_lan: str, configured_wan: str, configured_subnet: str) -> dict[str, Any]:
    """Merge operator-configured values with detection.

    A configured interface that does not exist on this host is discarded in
    favour of the detected one - otherwise a container built for a different
    machine would pre-fill ``eth0`` and silently fail to find anything.
    """
    suggestion = suggest_network()
    known = {i["name"] for i in list_interfaces()}

    lan = configured_lan if configured_lan in known else suggestion["lan_iface"]
    wan = configured_wan if configured_wan in known else (suggestion["wan_iface"] or lan)

    subnet = configured_subnet
    if not subnet:
        try:
            subnet = str(ipaddress.ip_network(interface_info(lan)["address"] or "", strict=False))
        except ValueError:
            subnet = suggestion["lan_subnet"]

    return {
        "lan_iface": lan,
        "wan_iface": wan,
        "lan_subnet": subnet or "",
        "detected_subnet": suggestion["lan_subnet"],
        "default_route_iface": suggestion["default_route_iface"],
    }


def detect_subnet(iface: str | None = None) -> str | None:
    from . import settings as runtime_settings

    configured = runtime_settings.lan_subnet()
    if configured:
        try:
            return str(ipaddress.ip_network(configured, strict=False))
        except ValueError:
            log.warning("invalid LAN subnet %r", configured)

    info = interface_info(iface or runtime_settings.lan_iface())
    if info["address"]:
        try:
            return str(ipaddress.ip_network(info["address"], strict=False))
        except ValueError:
            return None
    return None


def configure_interface(iface: str, cidr: str) -> bool:
    if run_command(["ip", "link", "set", "dev", iface, "up"]).returncode != 0:
        return False
    return run_command(["ip", "addr", "replace", cidr, "dev", iface]).returncode == 0


# --------------------------------------------------------------------------
# Bootstrap
# --------------------------------------------------------------------------
def bootstrap() -> dict[str, Any]:
    """Called at start-up: forwarding + NAT when gateway mode is on."""
    from . import settings as runtime_settings

    lan = runtime_settings.lan_iface()
    wan = runtime_settings.wan_iface()

    result: dict[str, Any] = {"gateway_mode": Config.GATEWAY_MODE, "lan_iface": lan, "wan_iface": wan}
    if not Config.GATEWAY_MODE:
        result["skipped"] = "gateway mode disabled"
        return result

    result["forwarding"] = enable_ip_forwarding()

    if Config.LAN_IP_CIDR:
        result["interface_configured"] = configure_interface(lan, Config.LAN_IP_CIDR)

    subnet = detect_subnet()
    result["subnet"] = subnet
    if subnet:
        nat = firewall.setup_nat(subnet, wan, lan)
        result["nat"] = nat
        log_event(f"Gateway bootstrap: forwarding on, NAT {subnet} via {wan}", source="gateway")
    else:
        result["nat"] = {"applied": False, "reason": "LAN subnet could not be determined"}
        log_event("Gateway bootstrap: LAN subnet unknown, NAT not installed", level="warn", source="gateway")
    return result


# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------
def status() -> dict[str, Any]:
    from . import settings as runtime_settings

    subnet = detect_subnet()
    return {
        "gateway_mode": Config.GATEWAY_MODE,
        "ip_forward": ip_forwarding_enabled(),
        "lan_iface": interface_info(runtime_settings.lan_iface()),
        "wan_iface": interface_info(runtime_settings.wan_iface()),
        "subnet": subnet,
        "nat_configured": bool(subnet) and not firewall.dry_run(),
    }
