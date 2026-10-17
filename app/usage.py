"""Traffic accounting: kernel byte counters -> SQLite -> aggregates.

Counting model
--------------
The kernel keeps byte/packet counters on every iptables rule. We install one
rule per device in a dedicated ``PCTRL-STAT`` chain and simply read those
counters periodically:

    -A PCTRL-STAT -m mac --mac-source AA:BB:CC:DD:EE:01 -j RETURN   <- upload
    -A PCTRL-STAT -d 192.168.1.10/32 -j RETURN                      <- download

Upload is matched on the device MAC. Download arrives addressed to the
*gateway*, so it has to be matched on the device IP instead.

The chain is never flushed: rules are added and removed individually as
devices come and go, so counters survive. Each sample records the *delta*
since the previous one.

Storage
-------
Raw samples are kept briefly for detailed graphs, then rolled up
incrementally into hourly and daily rows which are cheap to query forever.

    usage_samples   last 48h    (live graphs)
    usage_hourly    last 90d    (7d / 30d graphs)
    usage_daily     kept        (long-term history)
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any, Iterable

from . import firewall
from .config import Config
from .db import db, log_event, rows
from .models import list_devices
from .utils import to_ts

log = logging.getLogger("pg.usage")

_lock = threading.RLock()

# mac -> last seen cumulative counter (absolute, from the kernel)
_last_counters: dict[str, dict[str, int]] = {}
_samples_since_prune = 0

RANGES: dict[str, dict[str, Any]] = {
    "1h": {"seconds": 3600, "table": "usage_samples", "ts": "ts", "buckets": 60, "label": "Last hour"},
    "24h": {"seconds": 86400, "table": "usage_samples", "ts": "ts", "buckets": 96, "label": "Last 24 hours"},
    "7d": {"seconds": 7 * 86400, "table": "usage_hourly", "ts": "hour_ts", "buckets": 168, "label": "Last 7 days"},
    "30d": {"seconds": 30 * 86400, "table": "usage_hourly", "ts": "hour_ts", "buckets": 120, "label": "Last 30 days"},
    "90d": {"seconds": 90 * 86400, "table": "usage_daily", "ts": "day_ts", "buckets": 90, "label": "Last 90 days"},
}

DEFAULT_RANGE = "24h"


# --------------------------------------------------------------------------
# Chain synchronisation
# --------------------------------------------------------------------------
def sync_stat_rules() -> dict[str, int]:
    """Make the accounting chain match the current device list.

    Only adds/removes the rules that differ - flushing would reset every
    counter, which is the one thing we must avoid.
    """
    if firewall.dry_run():
        return {"added": 0, "removed": 0, "dry_run": True}

    firewall.ensure_stat_chain()

    devices = list_devices()
    desired_upload = {d["mac"] for d in devices if d.get("mac")}
    desired_download: dict[str, str] = {}
    for device in devices:
        ip = device.get("ip") or device.get("last_ip")
        if device.get("mac") and ip:
            desired_download[device["mac"]] = ip

    rules = firewall.list_stat_rules()
    existing_upload: dict[str, int] = {}
    existing_download: dict[str, int] = {}
    for rule in rules:
        if rule["mac"]:
            existing_upload[rule["mac"]] = rule["n"]
        elif rule["dst_ip"]:
            existing_download[rule["dst_ip"]] = rule["n"]

    wanted_ips = set(desired_download.values())

    # Remove stale rules, highest rule number first so numbering stays valid.
    doomed = [n for mac, n in existing_upload.items() if mac not in desired_upload]
    doomed += [n for ip, n in existing_download.items() if ip not in wanted_ips]
    removed = 0
    for number in sorted(doomed, reverse=True):
        if firewall.delete_stat_rule(number):
            removed += 1

    added = 0
    for mac in sorted(desired_upload - set(existing_upload)):
        if firewall.add_stat_upload_rule(mac):
            added += 1
    for ip in sorted(wanted_ips - set(existing_download)):
        if firewall.add_stat_download_rule(ip):
            added += 1

    if added or removed:
        log.debug("accounting rules: +%s / -%s", added, removed)
    return {"added": added, "removed": removed}


# --------------------------------------------------------------------------
# Counter reading
# --------------------------------------------------------------------------
def read_counters() -> dict[str, dict[str, int]]:
    """Return cumulative byte/packet counters keyed by MAC address."""
    ip_to_mac: dict[str, str] = {}
    for device in list_devices():
        ip = device.get("ip") or device.get("last_ip")
        if device.get("mac") and ip:
            ip_to_mac[ip] = device["mac"]

    totals: dict[str, dict[str, int]] = {}
    for rule in firewall.list_stat_rules():
        mac = rule["mac"] or ip_to_mac.get(rule["dst_ip"] or "")
        if not mac:
            continue
        slot = totals.setdefault(mac, {"up": 0, "down": 0, "packets_up": 0, "packets_down": 0})
        if rule["mac"]:
            slot["up"] += int(rule["bytes"])
            slot["packets_up"] += int(rule["packets"])
        else:
            slot["down"] += int(rule["bytes"])
            slot["packets_down"] += int(rule["packets"])
    return totals


# --------------------------------------------------------------------------
# Sampling
# --------------------------------------------------------------------------
def _day_start(ts: int) -> int:
    dt = datetime.fromtimestamp(ts)
    return int(datetime(dt.year, dt.month, dt.day).timestamp())


def _hour_start(ts: int) -> int:
    dt = datetime.fromtimestamp(ts)
    return int(datetime(dt.year, dt.month, dt.day, dt.hour).timestamp())


def _persist(samples: Iterable[tuple[int, str, int, int]]) -> None:
    batch = list(samples)
    if not batch:
        return
    with db() as conn:
        conn.executemany(
            "INSERT INTO usage_samples (ts, mac, up, down) VALUES (?, ?, ?, ?)", batch
        )
        for ts, mac, up, down in batch:
            conn.execute(
                "INSERT INTO usage_hourly (mac, hour_ts, up, down) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(mac, hour_ts) DO UPDATE SET up = up + excluded.up, down = down + excluded.down",
                (mac, _hour_start(ts), up, down),
            )
            conn.execute(
                "INSERT INTO usage_daily (mac, day_ts, up, down) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(mac, day_ts) DO UPDATE SET up = up + excluded.up, down = down + excluded.down",
                (mac, _day_start(ts), up, down),
            )


def prune() -> None:
    now = to_ts()
    with db() as conn:
        conn.execute(
            "DELETE FROM usage_samples WHERE ts < ?",
            (now - Config.USAGE_RETENTION_HOURS * 3600,),
        )
        conn.execute(
            "DELETE FROM usage_hourly WHERE hour_ts < ?",
            (now - Config.USAGE_HOURLY_RETENTION_DAYS * 86400,),
        )


def sample() -> dict[str, Any]:
    """Read the kernel counters and record the delta since the last sample."""
    global _samples_since_prune

    if not Config.USAGE_ENABLED:
        return {"enabled": False}

    with _lock:
        sync_stat_rules()
        counters = read_counters()
        now = to_ts()

        batch: list[tuple[int, str, int, int]] = []
        for mac, current in counters.items():
            previous = _last_counters.get(mac)
            # First sight of this device: take the baseline only. Otherwise we
            # would attribute all traffic since boot to a single sample.
            if previous is None:
                _last_counters[mac] = {"up": current["up"], "down": current["down"]}
                continue

            up = current["up"] - previous["up"]
            down = current["down"] - previous["down"]
            # A negative delta means the counter was reset (chain rebuilt).
            if up < 0:
                up = current["up"]
            if down < 0:
                down = current["down"]

            _last_counters[mac] = {"up": current["up"], "down": current["down"]}
            if up > 0 or down > 0:
                batch.append((now, mac, up, down))

        if batch:
            _persist(batch)

        _samples_since_prune += 1
        if _samples_since_prune >= 60:
            _samples_since_prune = 0
            try:
                prune()
            except Exception:  # noqa: BLE001
                log.debug("usage prune failed", exc_info=True)

        return {
            "enabled": True,
            "ts": now,
            "devices": len(counters),
            "recorded": len(batch),
            "bytes": sum(b[2] + b[3] for b in batch),
        }


def reset() -> None:
    """Forget all accounting state (keeps the rules, clears the numbers)."""
    global _samples_since_prune
    with _lock:
        _last_counters.clear()
        _samples_since_prune = 0
        with db() as conn:
            conn.execute("DELETE FROM usage_samples")
            conn.execute("DELETE FROM usage_hourly")
            conn.execute("DELETE FROM usage_daily")
        if not firewall.dry_run():
            firewall.flush_stat_chain()
            firewall.ensure_stat_chain()
    log_event("Traffic counters reset", source="usage")


# --------------------------------------------------------------------------
# Query
# --------------------------------------------------------------------------
def _bucketise(points: list[dict[str, Any]], buckets: int, span: int, now: int) -> list[dict[str, Any]]:
    """Collapse samples into ``buckets`` evenly spaced buckets ending at ``now``."""
    if buckets <= 0:
        return []
    width = max(1, span // buckets)
    out = [
        {"ts": now - (buckets - 1 - i) * width, "up": 0, "down": 0, "total": 0}
        for i in range(buckets)
    ]
    for point in points:
        age = now - int(point["ts"])
        index = buckets - 1 - (age // width)
        if 0 <= index < buckets:
            out[index]["up"] += point["up"]
            out[index]["down"] += point["down"]
            out[index]["total"] += point["up"] + point["down"]
    return out


def query(range_key: str | None = None) -> dict[str, Any]:
    """Aggregated usage for the dashboard."""
    key = (range_key or DEFAULT_RANGE).strip()
    spec = RANGES.get(key) or RANGES[DEFAULT_RANGE]
    now = to_ts()
    since = now - int(spec["seconds"])

    rows_ = rows(
        f"SELECT mac, {spec['ts']} AS ts, up, down FROM {spec['table']} WHERE {spec['ts']} >= ? ORDER BY ts",
        (since,),
    )

    devices = {d["mac"]: d for d in list_devices()}
    per_mac: dict[str, dict[str, int]] = {}
    for row in rows_:
        slot = per_mac.setdefault(row["mac"], {"up": 0, "down": 0})
        slot["up"] += int(row["up"])
        slot["down"] += int(row["down"])

    # Include devices with no traffic so the list is complete.
    for mac in devices:
        per_mac.setdefault(mac, {"up": 0, "down": 0})

    total_up = sum(v["up"] for v in per_mac.values())
    total_down = sum(v["down"] for v in per_mac.values())
    grand_total = total_up + total_down

    device_list = []
    for mac, totals in per_mac.items():
        device = devices.get(mac, {})
        combined = totals["up"] + totals["down"]
        device_list.append(
            {
                "mac": mac,
                "name": (device.get("custom_name") or device.get("hostname") or mac),
                "ip": device.get("ip") or device.get("last_ip"),
                "online": bool(device.get("last_seen")) and (now - int(device["last_seen"]))
                <= Config.ONLINE_WINDOW_MINUTES * 60,
                "group_id": device.get("group_id"),
                "group_name": device.get("group_name"),
                "group_color": device.get("group_color"),
                "up": totals["up"],
                "down": totals["down"],
                "total": combined,
                "percent": round(combined * 100 / grand_total, 1) if grand_total else 0.0,
            }
        )
    device_list.sort(key=lambda d: d["total"], reverse=True)

    # Aggregate up into groups; ungrouped devices form their own bucket.
    groups: dict[Any, dict[str, Any]] = {}
    for entry in device_list:
        key_id = entry["group_id"]
        if key_id not in groups:
            groups[key_id] = {
                "group_id": key_id,
                "name": entry["group_name"] or "Ungrouped",
                "color": entry["group_color"] or "#64748b",
                "up": 0,
                "down": 0,
                "total": 0,
                "device_count": 0,
            }
        bucket = groups[key_id]
        bucket["up"] += entry["up"]
        bucket["down"] += entry["down"]
        bucket["total"] += entry["total"]
        bucket["device_count"] += 1

    group_list = sorted(groups.values(), key=lambda g: g["total"], reverse=True)
    for group in group_list:
        group["percent"] = round(group["total"] * 100 / grand_total, 1) if grand_total else 0.0

    timeline = _bucketise(
        [{"ts": r["ts"], "up": r["up"], "down": r["down"]} for r in rows_],
        int(spec["buckets"]),
        int(spec["seconds"]),
        now,
    )

    return {
        "range": key,
        "label": spec["label"],
        "granularity": "raw" if spec["table"] == "usage_samples" else spec["table"].replace("usage_", ""),
        "since": since,
        "now": now,
        "timeline": timeline,
        "devices": device_list,
        "groups": group_list,
        "totals": {"up": total_up, "down": total_down, "total": grand_total},
        "row_count": len(rows_),
        "sampling_interval": Config.USAGE_INTERVAL_SECONDS,
        "retention_hours": Config.USAGE_RETENTION_HOURS,
    }


def status() -> dict[str, Any]:
    return {
        "enabled": Config.USAGE_ENABLED,
        "dry_run": firewall.dry_run(),
        "stat_chain": firewall.STAT_CHAIN,
        "interval": Config.USAGE_INTERVAL_SECONDS,
        "tracked": len(_last_counters),
        "rules": len(firewall.list_stat_rules()),
        "ranges": [
            {"key": k, "label": v["label"], "granularity": v["table"].replace("usage_", "")}
            for k, v in RANGES.items()
        ],
    }
