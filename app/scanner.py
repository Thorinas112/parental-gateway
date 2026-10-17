"""Layer-2 / layer-3 device discovery.

Primary path: scapy ARP probe (authoritative, works even for silent hosts).
Fallback path: the kernel neighbour table (`ip neigh`), which is populated
passively by normal gateway traffic - useful when raw sockets are unavailable.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any

from .config import Config
from .db import log_event
from .models import upsert_device
from .utils import norm_mac, run_command, to_ts

log = logging.getLogger("pg.scanner")

_NEIGH_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+(?P<mac>[0-9a-fA-F:]{17})",
    re.MULTILINE,
)


# --------------------------------------------------------------------------
# Subnet discovery
# --------------------------------------------------------------------------
def detect_subnet(iface: str | None = None) -> str | None:
    """Return the CIDR of ``iface``, or the configured LAN subnet."""
    from . import settings as runtime_settings

    configured = runtime_settings.lan_subnet()
    if configured:
        try:
            return str(ipaddress.ip_network(configured, strict=False))
        except ValueError:
            log.warning("invalid LAN subnet %r", configured)

    iface = iface or runtime_settings.lan_iface()
    proc = run_command(["ip", "-o", "-4", "addr", "show", "dev", iface])
    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", proc.stdout or "")
    if match:
        try:
            return str(ipaddress.ip_network(match.group(1), strict=False))
        except ValueError:
            pass

    # Last resort: the default route interface.
    proc = run_command(["ip", "-o", "-4", "addr", "show"])
    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", proc.stdout or "")
    if match:
        try:
            return str(ipaddress.ip_network(match.group(1), strict=False))
        except ValueError:
            pass
    return None


# --------------------------------------------------------------------------
# Hostname resolution
# --------------------------------------------------------------------------
def resolve_hostnames(ips: list[str], workers: int = 16, timeout: float = 2.0) -> dict[str, str]:
    results: dict[str, str] = {}
    if not ips:
        return results

    def _lookup(ip: str) -> tuple[str, str | None]:
        try:
            name = socket.gethostbyaddr(ip)[0]
            return ip, name.rstrip(".")
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ip, None

    pool = ThreadPoolExecutor(max_workers=min(workers, max(1, len(ips))))
    try:
        futures = {pool.submit(_lookup, ip): ip for ip in ips}
        for future in futures:
            try:
                ip, name = future.result(timeout=timeout)
            except FuturesTimeout:
                continue
            except Exception:  # noqa: BLE001 - resolution is best-effort
                continue
            if name:
                results[ip] = name
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results


def read_dhcp_leases() -> dict[str, str]:
    """Best-effort hostname source: dnsmasq / ISC DHCP lease files."""
    candidates = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhcpcd/dhcpcd.leases",
    ]
    leases: dict[str, str] = {}
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    parts = line.split()
                    if path.endswith("dnsmasq.leases") and len(parts) >= 4:
                        ip, host = parts[2], parts[3]
                        if host and host != "*":
                            leases[ip] = host
                    elif "lease" in line and "{" not in line:
                        pass
        except OSError:
            continue
    return leases


# --------------------------------------------------------------------------
# Scanning backends
# --------------------------------------------------------------------------
def _arp_scan_scapy(cidr: str, iface: str, timeout: float) -> list[dict[str, str]] | None:
    try:
        from scapy.all import ARP, Ether, conf, srp  # type: ignore
    except Exception as exc:  # noqa: BLE001
        log.debug("scapy unavailable: %s", exc)
        return None

    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    try:
        answered, _ = srp(packet, timeout=timeout, iface=iface, verbose=0, retry=1)
    except Exception as exc:  # noqa: BLE001 - fall back to the neighbour table
        log.warning("scapy ARP scan failed on %s: %s", iface, exc)
        return None

    found: list[dict[str, str]] = []
    for _sent, received in answered:
        mac = norm_mac(getattr(received, "hwsrc", None))
        ip = getattr(received, "psrc", None)
        if mac and ip:
            found.append({"ip": ip, "mac": mac})
    return found


def _neighbour_table(iface: str) -> list[dict[str, str]]:
    proc = run_command(["ip", "neigh", "show", "dev", iface])
    output = proc.stdout or ""
    if not output.strip():
        proc = run_command(["ip", "neigh", "show"])
        output = proc.stdout or ""

    found: list[dict[str, str]] = []
    for match in _NEIGH_RE.finditer(output):
        mac = norm_mac(match.group("mac"))
        if mac:
            found.append({"ip": match.group("ip"), "mac": mac})

    if not found:
        # Very old distributions: parse `arp -an`.
        proc = run_command(["arp", "-an"])
        for match in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", proc.stdout or ""):
            mac = norm_mac(match.group(2))
            if mac:
                found.append({"ip": match.group(1), "mac": mac})
    return found


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def scan_network(iface: str | None = None, timeout: float = 2.5) -> dict[str, Any]:
    """Discover devices on the LAN and persist them.

    Returns a summary dict suitable for the API response.
    """
    started = to_ts()
    from . import settings as runtime_settings

    iface = iface or runtime_settings.lan_iface()
    cidr = detect_subnet(iface)

    devices: list[dict[str, str]] = []
    method = "none"

    if cidr:
        scanned = _arp_scan_scapy(cidr, iface, timeout)
        if scanned is not None:
            devices = scanned
            method = "arp"
        else:
            devices = _neighbour_table(iface)
            method = "neighbour-table"
    else:
        devices = _neighbour_table(iface)
        method = "neighbour-table"

    # Deduplicate by MAC, keeping the most recent IP.
    by_mac: dict[str, dict[str, str]] = {}
    for entry in devices:
        mac = entry.get("mac")
        if mac:
            by_mac[mac] = entry

    ips = [e["ip"] for e in by_mac.values() if e.get("ip")]
    hostnames = resolve_hostnames(ips)
    leases = read_dhcp_leases()

    for mac, entry in by_mac.items():
        ip = entry.get("ip")
        hostname = hostnames.get(ip) or leases.get(ip)
        upsert_device(mac, ip=ip, hostname=hostname)

    summary = {
        "subnet": cidr,
        "interface": iface,
        "method": method,
        "found": len(by_mac),
        "devices": [
            {
                "mac": mac,
                "ip": entry.get("ip"),
                "hostname": hostnames.get(entry.get("ip", "")) or leases.get(entry.get("ip", "")),
            }
            for mac, entry in sorted(by_mac.items())
        ],
        "duration_ms": (to_ts() - started) * 1000,
    }
    log_event(
        f"Network scan ({method}) on {iface}{'/' + cidr if cidr else ''} found {len(by_mac)} device(s)",
        source="scanner",
    )
    log.info("scan complete: %s", summary["found"])
    return summary


def ping_host(ip: str, count: int = 2) -> bool:
    proc = run_command(["ping", "-c", str(count), "-W", "1", ip], timeout=count * 3 + 2)
    return proc.returncode == 0


def run_arping(ip: str, iface: str | None = None, count: int = 2) -> str | None:
    """Return the MAC answering for ``ip`` via a direct ARP probe."""
    args = ["arping", "-c", str(count), "-w", "3"]
    if iface:
        args += ["-I", iface]
    args.append(ip)
    proc = run_command(args, timeout=count * 4 + 3)
    match = re.search(r"\[([0-9A-Fa-f:]{17})\]", proc.stdout or "")
    return norm_mac(match.group(1)) if match else None
