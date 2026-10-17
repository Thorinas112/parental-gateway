"""Policy engine.

Turns the database state (manual toggles, pause timers, weekly schedules)
into a single, deterministic list of MAC addresses that must be dropped, then
pushes that list to the firewall backend.

Precedence (highest wins) per device:

    100  manual block (device toggle, or its group's toggle)
     80  pause timer  ("block for 30 minutes")
     60  allow timer  ("allow for 1 hour" - overrides schedules)
     40  weekly schedule window
      0  default: allowed
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any

from . import firewall, gateway
from .config import Config
from .db import log_event
from .models import (
    get_setting,
    list_devices,
    list_groups,
    list_pauses,
    list_schedules,
    purge_expired_pauses,
    set_setting,
)
from .utils import humanise_duration, now_dt, schedule_active, to_ts

log = logging.getLogger("pg.engine")

PRIORITY_MANUAL = 100
PRIORITY_UNAPPROVED = 90
PRIORITY_PAUSE = 80
PRIORITY_ALLOW = 60
PRIORITY_SCHEDULE = 40

_lock = threading.RLock()
_last: dict[str, Any] = {
    "blocked": [],
    "reasons": {},
    "decisions": {},
    "applied_at": 0,
    "error": None,
    "changed": False,
}


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def evaluate(when: datetime | None = None) -> dict[str, Any]:
    when = when or now_dt()
    now_ts = to_ts(when)

    devices = list_devices()
    groups = {g["id"]: g for g in list_groups()}
    pauses = list_pauses(active_only=True)
    schedules = list_schedules()

    # mac -> (priority, blocked, reason)
    decisions: dict[str, tuple[int, bool, str]] = {}

    def decide(mac: str, priority: int, blocked: bool, reason: str) -> None:
        current = decisions.get(mac)
        if current is None or priority >= current[0]:
            decisions[mac] = (priority, blocked, reason)

    by_group: dict[int | None, list[str]] = {}
    for device in devices:
        by_group.setdefault(device.get("group_id"), []).append(device["mac"])

    def group_macs(raw: Any) -> list[str]:
        try:
            return by_group.get(int(raw), [])
        except (TypeError, ValueError):
            return []

    # --- 1. manual toggles ------------------------------------------------
    for device in devices:
        if device.get("blocked"):
            decide(device["mac"], PRIORITY_MANUAL, True, "Blocked manually")
        group = groups.get(device.get("group_id"))
        if group and group.get("blocked"):
            decide(
                device["mac"],
                PRIORITY_MANUAL,
                True,
                f"Group “{group['name']}” is blocked",
            )

    # --- 2. unapproved devices -------------------------------------------
    # When "block unknown devices" is on, a freshly discovered MAC stays
    # quarantined until somebody explicitly approves it.
    for device in devices:
        if not device.get("approved", True):
            decide(
                device["mac"],
                PRIORITY_UNAPPROVED,
                True,
                "New device - waiting for approval",
            )

    # --- 3. pause timers (temporary block) --------------------------------
    for pause in pauses:
        remaining = int(pause["expires_at"] - now_ts)
        if pause["kind"] != "block":
            continue
        label = pause.get("label") or "Paused"
        reason = f"{label} · {_countdown(remaining)}"
        if pause["target_type"] == "device":
            decide(pause["target_id"], PRIORITY_PAUSE, True, reason)
        elif pause["target_type"] == "all":
            for device in devices:
                decide(device["mac"], PRIORITY_PAUSE, True, reason)
        else:
            for mac in group_macs(pause["target_id"]):
                decide(mac, PRIORITY_PAUSE, True, reason)

    # --- 4. allow timers (temporary override) ------------------------------
    for pause in pauses:
        remaining = int(pause["expires_at"] - now_ts)
        if pause["kind"] != "allow":
            continue
        label = pause.get("label") or "Allowed"
        reason = f"{label} · {_countdown(remaining)}"
        if pause["target_type"] == "device":
            decide(pause["target_id"], PRIORITY_ALLOW, False, reason)
        elif pause["target_type"] == "all":
            for device in devices:
                decide(device["mac"], PRIORITY_ALLOW, False, reason)
        else:
            for mac in group_macs(pause["target_id"]):
                decide(mac, PRIORITY_ALLOW, False, reason)

    # --- 5. weekly schedules ----------------------------------------------
    for schedule in schedules:
        if not schedule.get("enabled"):
            continue
        if not schedule_active(schedule.get("days") or [], schedule["start_time"], schedule["end_time"], when):
            continue
        group = groups.get(schedule.get("group_id"))
        reason = (
            f"Schedule “{schedule.get('name') or 'Bedtime'}” "
            f"({schedule['start_time']}–{schedule['end_time']})"
        )
        targets = by_group.get(schedule.get("group_id"), [])
        if schedule.get("group_id") is None:
            targets = [d["mac"] for d in devices]
        for mac in targets:
            decide(mac, PRIORITY_SCHEDULE, True, reason)
        if group:
            log.debug("schedule %s active for group %s", schedule["id"], group["name"])

    blocked = sorted(mac for mac, (_p, is_blocked, _r) in decisions.items() if is_blocked)
    reasons = {mac: reason for mac, (_p, _b, reason) in decisions.items()}
    return {
        "when": when,
        "blocked": blocked,
        "reasons": reasons,
        "decisions": {
            mac: {"priority": prio, "blocked": blk, "reason": reason}
            for mac, (prio, blk, reason) in decisions.items()
        },
    }


# --------------------------------------------------------------------------
# Reconcile
# --------------------------------------------------------------------------
def reconcile(force: bool = False, when: datetime | None = None) -> dict[str, Any]:
    """Compute the desired ruleset and apply it when it changed."""
    with _lock:
        purged = purge_expired_pauses()
        if purged:
            log.debug("purged %s expired timer(s)", purged)

        result = evaluate(when)
        desired = result["blocked"]
        previous = list(_last.get("blocked") or [])

        changed = desired != previous
        if not changed and not force and _last.get("applied_at"):
            return {
                **_last,
                "changed": False,
                "device_count": len(desired),
                "evaluated_at": to_ts(),
            }

        error = None
        applied = False
        try:
            firewall.apply_rules(desired)
            applied = True
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            log.error("firewall reconcile failed: %s", exc)

        if changed and applied:
            newly = sorted(set(desired) - set(previous))
            released = sorted(set(previous) - set(desired))
            if newly:
                log_event(f"Blocked {len(newly)} device(s): {', '.join(newly)}", source="firewall")
            if released:
                log_event(f"Unblocked {len(released)} device(s): {', '.join(released)}", source="firewall")

        _last.update(
            {
                "blocked": desired,
                "reasons": result["reasons"],
                "decisions": result["decisions"],
                "applied_at": to_ts(),
                "error": error,
                "changed": changed,
                "device_count": len(desired),
            }
        )
        return dict(_last)


def last_result() -> dict[str, Any]:
    return dict(_last)


def _countdown(remaining: int) -> str:
    """Human label for how long a timer still has to run."""
    if remaining > 30 * 86400:  # the "until resumed" sentinel
        return "until resumed"
    return f"{humanise_duration(remaining)} left"


def enforce_settings() -> None:
    """Apply user-configurable gateway settings (currently: auto-NAT)."""
    if get_setting("nat_enabled", "1") != "1":
        return
    from . import settings as runtime_settings

    subnet = gateway.detect_subnet()
    if subnet and not firewall.dry_run():
        firewall.setup_nat(subnet, runtime_settings.wan_iface(), runtime_settings.lan_iface())


def set_nat_enabled(enabled: bool) -> None:
    set_setting("nat_enabled", "1" if enabled else "0")
