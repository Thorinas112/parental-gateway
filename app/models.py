"""Data access helpers for devices, groups, pauses and schedules."""

from __future__ import annotations

from typing import Any

from .db import db, execute, one, rows
from .utils import days_to_json, format_hhmm, norm_mac, to_ts


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------
DEVICE_SELECT = (
    "SELECT d.*, g.name AS group_name, g.color AS group_color, g.blocked AS group_blocked "
    "FROM devices d LEFT JOIN groups g ON g.id = d.group_id "
)


def list_devices() -> list[dict[str, Any]]:
    return rows(DEVICE_SELECT + "ORDER BY d.last_seen DESC, d.mac ASC")


def get_device(mac: str) -> dict[str, Any] | None:
    mac = norm_mac(mac)
    if not mac:
        return None
    return one(DEVICE_SELECT + "WHERE d.mac = ?", (mac,))


def upsert_device(mac: str, ip: str | None = None, hostname: str | None = None) -> None:
    mac = norm_mac(mac)
    if not mac:
        return
    now = to_ts()
    # When "block unknown devices" is on, a never-before-seen MAC is held in
    # quarantine until it is approved.
    approved = 0 if get_setting("auto_block_unknown", "0") == "1" else 1
    with db() as conn:
        existing = conn.execute("SELECT mac, hostname FROM devices WHERE mac = ?", (mac,)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO devices (mac, ip, hostname, custom_name, group_id, blocked, approved, "
                "first_seen, last_seen, last_ip) VALUES (?, ?, ?, NULL, NULL, 0, ?, ?, ?, ?)",
                (mac, ip, hostname or None, approved, now, now, ip),
            )
        else:
            new_hostname = hostname or existing["hostname"]
            conn.execute(
                "UPDATE devices SET ip = COALESCE(?, ip), last_ip = COALESCE(?, last_ip), "
                "hostname = ?, last_seen = ? WHERE mac = ?",
                (ip, ip, new_hostname, now, mac),
            )


def approve_device(mac: str, approved: bool = True) -> bool:
    mac = norm_mac(mac)
    if not mac:
        return False
    with db() as conn:
        cur = conn.execute(
            "UPDATE devices SET approved = ? WHERE mac = ?", (1 if approved else 0, mac)
        )
        return cur.rowcount > 0


def approve_all_devices() -> int:
    with db() as conn:
        cur = conn.execute("UPDATE devices SET approved = 1 WHERE approved = 0")
        return int(cur.rowcount or 0)


def list_unapproved() -> list[dict[str, Any]]:
    return rows(DEVICE_SELECT + "WHERE d.approved = 0 ORDER BY d.last_seen DESC")


def touch_devices(macs: list[str]) -> None:
    if not macs:
        return
    now = to_ts()
    clean = [m for m in (norm_mac(x) for x in macs) if m]
    if not clean:
        return
    with db() as conn:
        conn.executemany("UPDATE devices SET last_seen = ? WHERE mac = ?", [(now, m) for m in clean])


def update_device(mac: str, **fields: Any) -> bool:
    mac = norm_mac(mac)
    if not mac:
        return False
    allowed = {"ip", "hostname", "custom_name", "group_id", "blocked"}
    assignments, values = [], []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "custom_name":
            value = (value or "").strip() or None
        if key == "group_id":
            value = int(value) if value not in (None, "", 0, "0") else None
        if key == "blocked":
            value = 1 if value else 0
        assignments.append(f"{key} = ?")
        values.append(value)
    if not assignments:
        return False
    values.append(mac)
    with db() as conn:
        cur = conn.execute(f"UPDATE devices SET {', '.join(assignments)} WHERE mac = ?", tuple(values))
        return cur.rowcount > 0


def delete_device(mac: str) -> bool:
    mac = norm_mac(mac)
    if not mac:
        return False
    with db() as conn:
        conn.execute("DELETE FROM pauses WHERE target_type = 'device' AND target_id = ?", (mac,))
        cur = conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))
        return cur.rowcount > 0


def macs_for_group(group_id: int) -> list[str]:
    return [r["mac"] for r in rows("SELECT mac FROM devices WHERE group_id = ?", (int(group_id),))]


# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------
def list_groups() -> list[dict[str, Any]]:
    return rows(
        "SELECT g.*, "
        "(SELECT COUNT(*) FROM devices d WHERE d.group_id = g.id) AS device_count "
        "FROM groups g ORDER BY g.name COLLATE NOCASE"
    )


def get_group(group_id: int) -> dict[str, Any] | None:
    return one("SELECT * FROM groups WHERE id = ?", (int(group_id),))


def create_group(name: str, color: str = "#6366f1") -> int:
    name = (name or "").strip()
    if not name:
        raise ValueError("group name is required")
    return execute(
        "INSERT INTO groups (name, color, blocked, created_at) VALUES (?, ?, 0, ?)",
        (name, color or "#6366f1", to_ts()),
    )


def update_group(group_id: int, **fields: Any) -> bool:
    allowed = {"name", "color", "blocked"}
    assignments, values = [], []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "name":
            value = (value or "").strip()
            if not value:
                raise ValueError("group name is required")
        if key == "blocked":
            value = 1 if value else 0
        assignments.append(f"{key} = ?")
        values.append(value)
    if not assignments:
        return False
    values.append(int(group_id))
    with db() as conn:
        cur = conn.execute(f"UPDATE groups SET {', '.join(assignments)} WHERE id = ?", tuple(values))
        return cur.rowcount > 0


def delete_group(group_id: int) -> bool:
    with db() as conn:
        conn.execute("DELETE FROM schedules WHERE group_id = ?", (int(group_id),))
        conn.execute("DELETE FROM pauses WHERE target_type = 'group' AND target_id = ?", (str(group_id),))
        cur = conn.execute("DELETE FROM groups WHERE id = ?", (int(group_id),))
        return cur.rowcount > 0


# --------------------------------------------------------------------------
# Pauses / temporary overrides
# --------------------------------------------------------------------------
def add_pause(
    target_type: str,
    target_id,
    kind: str,
    minutes: int | None = None,
    label: str | None = None,
) -> int:
    if target_type not in ("device", "group", "all"):
        raise ValueError("target_type must be 'device', 'group' or 'all'")
    if kind not in ("block", "allow"):
        raise ValueError("kind must be 'block' or 'allow'")
    now = to_ts()

    if minutes is None:
        # "until resumed" - a sentinel expiry far enough out that nothing
        # normalises it into a countdown, and close enough to stay a valid
        # 64-bit timestamp.
        expires_at = now + 100 * 365 * 86400
    else:
        minutes = int(minutes)
        if minutes <= 0 or minutes > 60 * 24 * 14:
            raise ValueError("minutes must be between 1 and 20160")
        expires_at = now + minutes * 60

    with db() as conn:
        conn.execute(
            "DELETE FROM pauses WHERE target_type = ? AND target_id = ? AND kind = ?",
            (target_type, str(target_id), kind),
        )
        cur = conn.execute(
            "INSERT INTO pauses (target_type, target_id, kind, label, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_type, str(target_id), kind, label, now, expires_at),
        )
        return int(cur.lastrowid or 0)


def list_pauses(active_only: bool = True) -> list[dict[str, Any]]:
    if active_only:
        return rows("SELECT * FROM pauses WHERE expires_at > ? ORDER BY expires_at ASC", (to_ts(),))
    return rows("SELECT * FROM pauses ORDER BY expires_at DESC")


def clear_pauses(target_type: str, target_id) -> int:
    with db() as conn:
        cur = conn.execute(
            "DELETE FROM pauses WHERE target_type = ? AND target_id = ?",
            (target_type, str(target_id)),
        )
        return int(cur.rowcount or 0)


def clear_pause(pause_id: int) -> bool:
    with db() as conn:
        cur = conn.execute("DELETE FROM pauses WHERE id = ?", (int(pause_id),))
        return cur.rowcount > 0


def purge_expired_pauses() -> int:
    with db() as conn:
        cur = conn.execute("DELETE FROM pauses WHERE expires_at <= ?", (to_ts(),))
        return int(cur.rowcount or 0)


# --------------------------------------------------------------------------
# Weekly schedules
# --------------------------------------------------------------------------
def list_schedules() -> list[dict[str, Any]]:
    result = rows(
        "SELECT s.*, g.name AS group_name, g.color AS group_color "
        "FROM schedules s LEFT JOIN groups g ON g.id = s.group_id "
        "ORDER BY s.start_time ASC, s.id ASC"
    )
    for item in result:
        item["days"] = _decode_days(item.get("days_json"))
    return result


def _decode_days(raw: Any) -> list[int]:
    from .utils import parse_days

    return parse_days(raw)


def get_schedule(schedule_id: int) -> dict[str, Any] | None:
    row = one("SELECT * FROM schedules WHERE id = ?", (int(schedule_id),))
    if row:
        row["days"] = _decode_days(row.get("days_json"))
    return row


def create_schedule(
    group_id: int,
    days,
    start_time: str,
    end_time: str,
    name: str = "",
    enabled: bool = True,
) -> int:
    return execute(
        "INSERT INTO schedules (group_id, name, days_json, start_time, end_time, enabled, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            int(group_id),
            (name or "").strip(),
            days_to_json(days),
            format_hhmm(start_time),
            format_hhmm(end_time),
            1 if enabled else 0,
            to_ts(),
        ),
    )


def update_schedule(schedule_id: int, **fields: Any) -> bool:
    assignments, values = [], []
    if "group_id" in fields and fields["group_id"] is not None:
        assignments.append("group_id = ?")
        values.append(int(fields["group_id"]))
    if "name" in fields:
        assignments.append("name = ?")
        values.append((fields["name"] or "").strip())
    if "days" in fields:
        assignments.append("days_json = ?")
        values.append(days_to_json(fields["days"]))
    if "start_time" in fields:
        assignments.append("start_time = ?")
        values.append(format_hhmm(fields["start_time"]))
    if "end_time" in fields:
        assignments.append("end_time = ?")
        values.append(format_hhmm(fields["end_time"]))
    if "enabled" in fields:
        assignments.append("enabled = ?")
        values.append(1 if fields["enabled"] else 0)
    if not assignments:
        return False
    values.append(int(schedule_id))
    with db() as conn:
        cur = conn.execute(f"UPDATE schedules SET {', '.join(assignments)} WHERE id = ?", tuple(values))
        return cur.rowcount > 0


def delete_schedule(schedule_id: int) -> bool:
    with db() as conn:
        cur = conn.execute("DELETE FROM schedules WHERE id = ?", (int(schedule_id),))
        return cur.rowcount > 0


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
def get_setting(key: str, default: Any = None) -> Any:
    row = one("SELECT value FROM settings WHERE key = ?", (key,))
    return row["value"] if row and row["value"] is not None else default


def set_setting(key: str, value: Any) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, "" if value is None else str(value)),
        )


# --------------------------------------------------------------------------
# Web filtering rules
# --------------------------------------------------------------------------
GLOBAL_GROUP_ID = 0


def device_for_ip(ip: str) -> dict[str, Any] | None:
    """Look a device up by IP (used by the DNS proxy to find its group)."""
    if not ip:
        return None
    return one("SELECT * FROM devices WHERE ip = ? OR last_ip = ? ORDER BY last_seen DESC LIMIT 1", (ip, ip))


def mac_for_ip(ip: str) -> str | None:
    device = device_for_ip(ip)
    return device.get("mac") if device else None


def list_web_rules(group_id: int | None = None, enabled_only: bool = False) -> list[dict[str, Any]]:
    sql = (
        "SELECT w.*, g.name AS group_name FROM web_rules w "
        "LEFT JOIN groups g ON g.id = w.group_id "
    )
    clauses, params = [], []
    if group_id is not None:
        clauses.append("w.group_id = ?")
        params.append(int(group_id))
    if enabled_only:
        clauses.append("w.enabled = 1")
    if clauses:
        sql += "WHERE " + " AND ".join(clauses) + " "
    sql += "ORDER BY w.group_id, w.pattern"
    return rows(sql, tuple(params))


def add_web_rule(group_id: int, pattern: str, action: str = "block", source: str = "custom") -> int:
    from .dnsfilter import normalise_pattern

    cleaned = normalise_pattern(pattern)
    if not cleaned:
        raise ValueError("a domain pattern is required")
    if action not in ("block", "allow"):
        raise ValueError("action must be 'block' or 'allow'")
    group_id = int(group_id or 0)
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM web_rules WHERE group_id = ? AND pattern = ? AND action = ?",
            (group_id, cleaned, action),
        ).fetchone()
        if existing:
            return int(existing["id"])
        cur = conn.execute(
            "INSERT INTO web_rules (group_id, pattern, action, enabled, source, created_at) "
            "VALUES (?, ?, ?, 1, ?, ?)",
            (group_id, cleaned, action, source, to_ts()),
        )
        return int(cur.lastrowid or 0)


def update_web_rule(rule_id: int, **fields: Any) -> bool:
    assignments, values = [], []
    if "enabled" in fields:
        assignments.append("enabled = ?")
        values.append(1 if fields["enabled"] else 0)
    if "action" in fields:
        if fields["action"] not in ("block", "allow"):
            raise ValueError("action must be 'block' or 'allow'")
        assignments.append("action = ?")
        values.append(fields["action"])
    if "pattern" in fields:
        from .dnsfilter import normalise_pattern

        cleaned = normalise_pattern(fields["pattern"])
        if not cleaned:
            raise ValueError("a domain pattern is required")
        assignments.append("pattern = ?")
        values.append(cleaned)
    if not assignments:
        return False
    values.append(int(rule_id))
    with db() as conn:
        cur = conn.execute(f"UPDATE web_rules SET {', '.join(assignments)} WHERE id = ?", tuple(values))
        return cur.rowcount > 0


def delete_web_rule(rule_id: int) -> bool:
    with db() as conn:
        cur = conn.execute("DELETE FROM web_rules WHERE id = ?", (int(rule_id),))
        return cur.rowcount > 0


def delete_web_rules_for_group(group_id: int) -> int:
    with db() as conn:
        cur = conn.execute("DELETE FROM web_rules WHERE group_id = ?", (int(group_id),))
        return int(cur.rowcount or 0)


def web_rules_as_objects():
    """Build ``dnsfilter.Rule`` objects for the proxy's rule cache."""
    from .dnsfilter import Rule

    return [
        Rule(pattern=r["pattern"], action=r["action"], group_id=int(r["group_id"]), source=r["source"])
        for r in list_web_rules(enabled_only=True)
    ]


# --------------------------------------------------------------------------
# DNS query log
# --------------------------------------------------------------------------
def list_dns_queries(
    limit: int = 100,
    action: str | None = None,
    search: str | None = None,
    mac: str | None = None,
) -> list[dict[str, Any]]:
    sql = (
        "SELECT q.*, COALESCE(d.custom_name, d.hostname, q.mac) AS device_name "
        "FROM dns_queries q LEFT JOIN devices d ON d.mac = q.mac "
    )
    clauses, params = [], []
    if action in ("allowed", "blocked"):
        clauses.append("q.action = ?")
        params.append(action)
    if mac:
        clauses.append("q.mac = ?")
        params.append(mac)
    if search:
        clauses.append("q.domain LIKE ?")
        params.append(f"%{search}%")
    if clauses:
        sql += "WHERE " + " AND ".join(clauses) + " "
    sql += "ORDER BY q.ts DESC, q.id DESC LIMIT ?"
    params.append(max(1, min(500, int(limit))))
    return rows(sql, tuple(params))


def dns_query_stats() -> dict[str, Any]:
    totals = one(
        "SELECT COUNT(*) AS total, "
        "SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked, "
        "SUM(CASE WHEN action='allowed' THEN 1 ELSE 0 END) AS allowed "
        "FROM dns_queries"
    ) or {}
    top_domains = rows(
        "SELECT domain, COUNT(*) AS n FROM dns_queries WHERE action='blocked' "
        "GROUP BY domain ORDER BY n DESC LIMIT 10"
    )
    return {
        "total": int(totals.get("total") or 0),
        "blocked": int(totals.get("blocked") or 0),
        "allowed": int(totals.get("allowed") or 0),
        "top_blocked": top_domains,
    }


def prune_dns_queries(days: int = 7) -> int:
    cutoff = to_ts() - max(1, int(days)) * 86400
    with db() as conn:
        cur = conn.execute("DELETE FROM dns_queries WHERE ts < ?", (cutoff,))
        return int(cur.rowcount or 0)
