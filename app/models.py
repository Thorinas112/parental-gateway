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
    with db() as conn:
        existing = conn.execute("SELECT mac, hostname FROM devices WHERE mac = ?", (mac,)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO devices (mac, ip, hostname, custom_name, group_id, blocked, "
                "first_seen, last_seen, last_ip) VALUES (?, ?, ?, NULL, NULL, 0, ?, ?, ?)",
                (mac, ip, hostname or None, now, now, ip),
            )
        else:
            new_hostname = hostname or existing["hostname"]
            conn.execute(
                "UPDATE devices SET ip = COALESCE(?, ip), last_ip = COALESCE(?, last_ip), "
                "hostname = ?, last_seen = ? WHERE mac = ?",
                (ip, ip, new_hostname, now, mac),
            )


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
def add_pause(target_type: str, target_id, kind: str, minutes: int, label: str | None = None) -> int:
    if target_type not in ("device", "group"):
        raise ValueError("target_type must be 'device' or 'group'")
    if kind not in ("block", "allow"):
        raise ValueError("kind must be 'block' or 'allow'")
    minutes = int(minutes)
    if minutes <= 0 or minutes > 60 * 24 * 14:
        raise ValueError("minutes must be between 1 and 20160")
    now = to_ts()
    with db() as conn:
        conn.execute(
            "DELETE FROM pauses WHERE target_type = ? AND target_id = ? AND kind = ?",
            (target_type, str(target_id), kind),
        )
        cur = conn.execute(
            "INSERT INTO pauses (target_type, target_id, kind, label, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_type, str(target_id), kind, label, now, now + minutes * 60),
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
