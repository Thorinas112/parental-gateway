"""JSON API used by the dashboard."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from flask import Blueprint, g, jsonify, request

from .. import engine, firewall, gateway, scheduler
from .. import dnsfilter
from .. import settings as runtime_settings
from .. import usage as traffic
from ..config import Config
from ..db import log_event, recent_events
from ..models import (
    add_pause,
    add_web_rule,
    approve_all_devices,
    approve_device,
    clear_pause,
    clear_pauses,
    create_group,
    create_schedule,
    delete_device,
    delete_group,
    delete_schedule,
    delete_web_rule,
    dns_client_ips,
    dns_query_stats,
    dns_source_stats,
    get_device,
    get_group,
    get_schedule,
    get_setting,
    list_devices,
    list_dns_queries,
    list_groups,
    list_pauses,
    list_schedules,
    list_unapproved,
    list_web_rules,
    set_setting,
    update_device,
    update_group,
    update_schedule,
    update_web_rule,
    web_rules_as_objects,
)
from ..security import (
    api_auth,
    authenticate,
    create_session,
    create_user,
    current_token,
    destroy_session,
    get_session,
    record_failure,
    record_success,
    setup_required,
    throttled,
)
from ..utils import humanise_duration, to_ts

bp = Blueprint("api", __name__, url_prefix="/api")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _json_error(message: str, status: int = 400):
    return jsonify({"error": message}), status


def _body() -> dict[str, Any]:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _session_payload(session: dict[str, Any] | None) -> dict[str, Any]:
    if not session:
        return {"authenticated": False, "user": None, "csrf": None}
    return {
        "authenticated": True,
        "user": {"id": session["user_id"], "username": session["username"]},
        "csrf": session["csrf"],
        "expires_at": session["expires_at"],
    }


def _device_payload(
    device: dict[str, Any],
    decisions: dict[str, Any],
    now_ts: int,
    dns_ips: set[str] | None = None,
) -> dict[str, Any]:
    mac = device["mac"]
    decision = decisions.get(mac) or {}
    last_seen = device.get("last_seen") or 0
    online = (now_ts - int(last_seen)) <= Config.ONLINE_WINDOW_MINUTES * 60
    custom = (device.get("custom_name") or "").strip()
    ip = device.get("ip") or device.get("last_ip")
    return {
        "mac": mac,
        "ip": ip,
        "hostname": device.get("hostname"),
        "custom_name": custom or None,
        "name": custom or device.get("hostname") or mac,
        "group_id": device.get("group_id"),
        "group_name": device.get("group_name"),
        "group_color": device.get("group_color"),
        "blocked": bool(device.get("blocked")),
        "group_blocked": bool(device.get("group_blocked")),
        "approved": bool(device.get("approved", True)),
        "effective_blocked": bool(decision.get("blocked", False)),
        "reason": decision.get("reason"),
        # True when this device queries the gateway directly - the only case
        # where per-device DNS enforcement can actually reach it.
        "dns_direct": bool(dns_ips is not None and ip in dns_ips),
        "online": online,
        "first_seen": device.get("first_seen"),
        "last_seen": device.get("last_seen"),
    }


def _pause_payload(pause: dict[str, Any], now_ts: int) -> dict[str, Any]:
    remaining = max(0, int(pause["expires_at"]) - now_ts)
    indefinite = remaining > 30 * 86400  # "until resumed" sentinel
    return {
        "id": pause["id"],
        "target_type": pause["target_type"],
        "target_id": pause["target_id"],
        "kind": pause["kind"],
        "label": pause.get("label"),
        "created_at": pause["created_at"],
        "expires_at": pause["expires_at"],
        "remaining_seconds": remaining,
        "remaining_human": "until resumed" if indefinite else humanise_duration(remaining),
        "indefinite": indefinite,
    }


def _groups_payload() -> list[dict[str, Any]]:
    return [
        {
            "id": g["id"],
            "name": g["name"],
            "color": g["color"],
            "blocked": bool(g["blocked"]),
            "device_count": g.get("device_count", 0),
            "created_at": g.get("created_at"),
        }
        for g in list_groups()
    ]


def _schedules_payload() -> list[dict[str, Any]]:
    return [
        {
            "id": s["id"],
            "group_id": s["group_id"],
            "group_name": s.get("group_name"),
            "group_color": s.get("group_color"),
            "name": s.get("name") or "",
            "days": s.get("days") or [],
            "start_time": s["start_time"],
            "end_time": s["end_time"],
            "enabled": bool(s["enabled"]),
        }
        for s in list_schedules()
    ]


def _status_payload() -> dict[str, Any]:
    result = engine.last_result()
    return {
        "gateway": gateway.status(),
        "firewall": firewall.status(),
        "policy": {
            "blocked_count": len(result.get("blocked") or []),
            "blocked_macs": result.get("blocked") or [],
            "applied_at": result.get("applied_at"),
            "error": result.get("error"),
            "changed": result.get("changed"),
        },
        "server_time": to_ts(),
    }


def _set_session_cookie(response, session: dict[str, Any]):
    response.set_cookie(
        Config.SESSION_COOKIE_NAME,
        session["token"],
        max_age=Config.SESSION_TTL_HOURS * 3600,
        httponly=True,
        samesite=Config.SESSION_COOKIE_SAMESITE,
        secure=Config.SESSION_COOKIE_SECURE,
        path="/",
    )
    return response


# --------------------------------------------------------------------------
# First-run setup wizard
# --------------------------------------------------------------------------
@bp.get("/setup/status")
def setup_status():
    """Everything the wizard needs, reachable without a session."""
    resolved = gateway.resolve_wizard_network(
        runtime_settings.lan_iface(),
        runtime_settings.wan_iface(),
        runtime_settings.lan_subnet(),
    )

    interfaces = gateway.list_interfaces()
    # Surface the recommended interfaces first so the dropdowns are obvious.
    preferred = [resolved["lan_iface"], resolved["wan_iface"]]
    interfaces.sort(
        key=lambda i: (preferred.index(i["name"]) if i["name"] in preferred else len(preferred), i["name"])
    )

    return jsonify(
        {
            "required": setup_required(),
            "min_password_length": Config.MIN_PASSWORD_LENGTH,
            "gateway_mode": Config.GATEWAY_MODE,
            "detected_subnet": resolved["detected_subnet"],
            "default_route_iface": resolved["default_route_iface"],
            "recommended": {"lan": resolved["lan_iface"], "wan": resolved["wan_iface"]},
            "network": {
                "lan_iface": resolved["lan_iface"],
                "wan_iface": resolved["wan_iface"],
                "lan_subnet": resolved["lan_subnet"],
            },
            "interfaces": interfaces,
            "firewall": firewall.status(),
        }
    )


@bp.post("/setup")
def setup():
    """Create the administrator account and apply the chosen network config."""
    if not setup_required():
        return _json_error("setup has already been completed", 409)

    if throttled():
        return _json_error("too many attempts - try again later", 429)

    body = _body()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    confirm = body.get("confirm") or ""

    if not 2 <= len(username) <= 32:
        record_failure()
        return _json_error("username must be 2-32 characters")
    if not re.fullmatch(r"[A-Za-z0-9._\-]+", username):
        record_failure()
        return _json_error("username may only use letters, numbers, dot, dash or underscore")
    if len(password) < Config.MIN_PASSWORD_LENGTH:
        record_failure()
        return _json_error(f"password must be at least {Config.MIN_PASSWORD_LENGTH} characters")
    if len(password) > 256:
        record_failure()
        return _json_error("password is too long")
    if password != confirm:
        record_failure()
        return _json_error("passwords do not match")

    lan = (body.get("lan_iface") or "").strip() or None
    wan = (body.get("wan_iface") or "").strip() or None
    subnet = (body.get("lan_subnet") or "").strip() or None
    if subnet:
        try:
            subnet = str(ipaddress.ip_network(subnet, strict=False))
        except ValueError:
            return _json_error("LAN subnet must be a valid CIDR block, e.g. 192.168.1.0/24")

    try:
        user_id = create_user(username, password)
    except ValueError as exc:
        record_failure()
        return _json_error(str(exc))

    if lan or wan or subnet:
        runtime_settings.set_network(lan, wan, subnet)

    record_success()
    session = create_session(user_id)
    log_event(f"Setup completed - administrator {username!r} created", source="setup")

    try:
        gateway.bootstrap()
    except Exception:  # noqa: BLE001 - never fail the wizard after the account exists
        log_event("Gateway bootstrap after setup failed", level="warn", source="setup")
    engine.reconcile(force=True)

    payload = _session_payload({**session, "user_id": user_id, "username": username})
    return _set_session_cookie(jsonify(payload), session)


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------
@bp.post("/login")
def login():
    if setup_required():
        return jsonify({"error": "setup required", "setup_required": True}), 428

    body = _body()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if throttled():
        log_event(f"Login throttled for {username!r}", level="warn", source="auth")
        return _json_error("too many attempts - try again later", 429)

    user = authenticate(username, password)
    if not user:
        record_failure()
        log_event(f"Failed login for {username!r}", level="warn", source="auth")
        return _json_error("invalid username or password", 401)

    record_success()
    session = create_session(user["id"])
    log_event(f"User {user['username']!r} signed in", source="auth")

    payload = _session_payload({**session, "user_id": user["id"], "username": user["username"]})
    return _set_session_cookie(jsonify(payload), session)


@bp.post("/logout")
@api_auth
def logout():
    destroy_session(current_token())
    log_event(f"User {request_user()} signed out", source="auth")
    response = jsonify({"ok": True})
    response.delete_cookie(Config.SESSION_COOKIE_NAME, path="/")
    return response


def request_user() -> str:
    return (getattr(g, "user", {}) or {}).get("username", "unknown")


@bp.get("/session")
def session_info():
    return jsonify(_session_payload(get_session(current_token())))


# --------------------------------------------------------------------------
# Overview (single bootstrap call for the dashboard)
# --------------------------------------------------------------------------
@bp.get("/overview")
@api_auth
def overview():
    now = to_ts()
    decisions = engine.last_result().get("decisions") or {}
    dns_ips = dns_client_ips()
    return jsonify(
        {
            "devices": [_device_payload(d, decisions, now, dns_ips) for d in list_devices()],
            "groups": _groups_payload(),
            "schedules": _schedules_payload(),
            "pauses": [_pause_payload(p, now) for p in list_pauses(active_only=True)],
            "status": _status_payload(),
            "events": recent_events(25),
            "settings": {
                "lan_iface": runtime_settings.lan_iface(),
                "wan_iface": runtime_settings.wan_iface(),
                "gateway_mode": Config.GATEWAY_MODE,
                "firewall_mode": Config.FIREWALL_MODE,
                "online_window_minutes": Config.ONLINE_WINDOW_MINUTES,
                "scan_interval_minutes": Config.SCAN_INTERVAL_MINUTES,
                "day_names": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            },
        }
    )


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------
@bp.get("/devices")
@api_auth
def devices():
    now = to_ts()
    decisions = engine.last_result().get("decisions") or {}
    dns_ips = dns_client_ips()
    return jsonify({"devices": [_device_payload(d, decisions, now, dns_ips) for d in list_devices()]})


@bp.post("/scan")
@api_auth
def scan():
    summary = scheduler.run_scan_now()
    engine.reconcile(force=True)
    return jsonify({"ok": True, "scan": summary})


@bp.patch("/devices/<mac>")
@api_auth
def patch_device(mac: str):
    body = _body()
    fields: dict[str, Any] = {}
    if "name" in body:
        fields["custom_name"] = body.get("name")
    if "group_id" in body:
        fields["group_id"] = body.get("group_id")
    if "blocked" in body:
        fields["blocked"] = bool(body.get("blocked"))

    device = get_device(mac)
    if not device:
        return _json_error("device not found", 404)

    try:
        update_device(mac, **fields)
    except ValueError as exc:
        return _json_error(str(exc))

    engine.reconcile(force=True)
    log_event(f"Updated device {mac}", source="devices")
    now = to_ts()
    decisions = engine.last_result().get("decisions") or {}
    return jsonify({"ok": True, "device": _device_payload(get_device(mac), decisions, now)})


@bp.post("/devices/<mac>/access")
@api_auth
def device_access(mac: str):
    device = get_device(mac)
    if not device:
        return _json_error("device not found", 404)
    blocked = bool(_body().get("blocked"))
    update_device(mac, blocked=1 if blocked else 0)
    clear_pauses("device", mac)
    engine.reconcile(force=True)
    log_event(f"{'Blocked' if blocked else 'Allowed'} device {mac}", source="devices")
    return jsonify({"ok": True})


@bp.post("/devices/<mac>/timer")
@api_auth
def device_timer(mac: str):
    device = get_device(mac)
    if not device:
        return _json_error("device not found", 404)
    body = _body()
    try:
        minutes = int(body.get("minutes") or 0)
    except (TypeError, ValueError):
        return _json_error("minutes must be a number")
    kind = body.get("kind") or "block"
    label = (body.get("label") or "").strip() or None

    try:
        add_pause("device", mac, kind, minutes, label)
    except ValueError as exc:
        return _json_error(str(exc))

    engine.reconcile(force=True)
    verb = "Paused" if kind == "block" else "Allowed"
    log_event(f"{verb} device {mac} for {humanise_duration(minutes * 60)}", source="devices")
    return jsonify({"ok": True, "pauses": [_pause_payload(p, to_ts()) for p in list_pauses(True)]})


@bp.delete("/devices/<mac>")
@api_auth
def remove_device(mac: str):
    if not delete_device(mac):
        return _json_error("device not found", 404)
    engine.reconcile(force=True)
    log_event(f"Removed device {mac}", source="devices")
    return jsonify({"ok": True})


# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------
@bp.get("/groups")
@api_auth
def groups():
    return jsonify({"groups": _groups_payload()})


@bp.post("/groups")
@api_auth
def new_group():
    body = _body()
    name = (body.get("name") or "").strip()
    if not name:
        return _json_error("group name is required")
    if any(g["name"].lower() == name.lower() for g in list_groups()):
        return _json_error("a group with that name already exists", 409)
    try:
        group_id = create_group(name, body.get("color") or "#6366f1")
    except Exception as exc:  # noqa: BLE001
        return _json_error(str(exc))
    log_event(f"Created group {name!r}", source="groups")
    return jsonify({"ok": True, "group": get_group(group_id)})


@bp.patch("/groups/<int:group_id>")
@api_auth
def patch_group(group_id: int):
    if not get_group(group_id):
        return _json_error("group not found", 404)
    body = _body()
    fields = {k: body[k] for k in ("name", "color", "blocked") if k in body}
    try:
        update_group(group_id, **fields)
    except ValueError as exc:
        return _json_error(str(exc))
    engine.reconcile(force=True)
    return jsonify({"ok": True, "group": get_group(group_id)})


@bp.delete("/groups/<int:group_id>")
@api_auth
def remove_group(group_id: int):
    if not delete_group(group_id):
        return _json_error("group not found", 404)
    engine.reconcile(force=True)
    log_event(f"Deleted group #{group_id}", source="groups")
    return jsonify({"ok": True})


@bp.post("/groups/<int:group_id>/access")
@api_auth
def group_access(group_id: int):
    group = get_group(group_id)
    if not group:
        return _json_error("group not found", 404)
    blocked = bool(_body().get("blocked"))
    update_group(group_id, blocked=1 if blocked else 0)
    clear_pauses("group", str(group_id))
    engine.reconcile(force=True)
    log_event(
        f"{'Blocked' if blocked else 'Allowed'} all devices in group {group['name']!r}",
        source="groups",
    )
    return jsonify({"ok": True})


@bp.post("/groups/<int:group_id>/timer")
@api_auth
def group_timer(group_id: int):
    group = get_group(group_id)
    if not group:
        return _json_error("group not found", 404)
    body = _body()
    try:
        minutes = int(body.get("minutes") or 0)
    except (TypeError, ValueError):
        return _json_error("minutes must be a number")
    kind = body.get("kind") or "block"
    label = (body.get("label") or "").strip() or None

    try:
        add_pause("group", group_id, kind, minutes, label)
    except ValueError as exc:
        return _json_error(str(exc))

    engine.reconcile(force=True)
    verb = "Paused" if kind == "block" else "Allowed"
    log_event(
        f"{verb} group {group['name']!r} for {humanise_duration(minutes * 60)}",
        source="groups",
    )
    return jsonify({"ok": True, "pauses": [_pause_payload(p, to_ts()) for p in list_pauses(True)]})


# --------------------------------------------------------------------------
# Timers
# --------------------------------------------------------------------------
@bp.get("/pauses")
@api_auth
def pauses():
    now = to_ts()
    return jsonify({"pauses": [_pause_payload(p, now) for p in list_pauses(active_only=True)]})


@bp.delete("/pauses/<int:pause_id>")
@api_auth
def remove_pause(pause_id: int):
    if not clear_pause(pause_id):
        return _json_error("timer not found", 404)
    engine.reconcile(force=True)
    return jsonify({"ok": True})


# --------------------------------------------------------------------------
# Schedules
# --------------------------------------------------------------------------
@bp.get("/schedules")
@api_auth
def schedules():
    return jsonify({"schedules": _schedules_payload()})


@bp.post("/schedules")
@api_auth
def new_schedule():
    body = _body()
    group_id = body.get("group_id")
    if group_id in (None, "", 0, "0"):
        return _json_error("a group is required for a schedule")
    if not get_group(int(group_id)):
        return _json_error("group not found", 404)
    days = body.get("days") or []
    if not days:
        return _json_error("select at least one day")

    try:
        schedule_id = create_schedule(
            int(group_id),
            days,
            body.get("start_time") or "21:00",
            body.get("end_time") or "07:00",
            body.get("name") or "",
            bool(body.get("enabled", True)),
        )
    except ValueError as exc:
        return _json_error(str(exc))

    engine.reconcile(force=True)
    log_event(f"Created schedule #{schedule_id}", source="schedules")
    return jsonify({"ok": True, "schedule": get_schedule(schedule_id)})


@bp.patch("/schedules/<int:schedule_id>")
@api_auth
def patch_schedule(schedule_id: int):
    if not get_schedule(schedule_id):
        return _json_error("schedule not found", 404)
    body = _body()
    fields = {k: body[k] for k in ("group_id", "name", "days", "start_time", "end_time", "enabled") if k in body}
    try:
        update_schedule(schedule_id, **fields)
    except ValueError as exc:
        return _json_error(str(exc))
    engine.reconcile(force=True)
    return jsonify({"ok": True, "schedule": get_schedule(schedule_id)})


@bp.delete("/schedules/<int:schedule_id>")
@api_auth
def remove_schedule(schedule_id: int):
    if not delete_schedule(schedule_id):
        return _json_error("schedule not found", 404)
    engine.reconcile(force=True)
    log_event(f"Deleted schedule #{schedule_id}", source="schedules")
    return jsonify({"ok": True})


# --------------------------------------------------------------------------
# System
# --------------------------------------------------------------------------
@bp.get("/status")
@api_auth
def status():
    return jsonify(_status_payload())


@bp.get("/rules")
@api_auth
def rules():
    engine.reconcile()
    return jsonify({**firewall.dump_rules(), "status": firewall.status()})


@bp.post("/system/reconcile")
@api_auth
def system_reconcile():
    result = scheduler.kick()
    return jsonify({"ok": True, "result": result, "status": _status_payload()})


@bp.post("/system/nat")
@api_auth
def system_nat():
    enabled = bool(_body().get("enabled"))
    engine.set_nat_enabled(enabled)
    if enabled:
        subnet = gateway.detect_subnet()
        if subnet and not firewall.dry_run():
            firewall.setup_nat(subnet, runtime_settings.wan_iface(), runtime_settings.lan_iface())
    engine.reconcile(force=True)
    return jsonify({"ok": True, "nat_enabled": enabled})


@bp.get("/events")
@api_auth
def events():
    limit = min(200, max(5, int(request.args.get("limit", 40))))
    return jsonify({"events": recent_events(limit)})


# --------------------------------------------------------------------------
# Traffic usage
# --------------------------------------------------------------------------
@bp.get("/usage")
@api_auth
def usage():
    """Aggregated traffic for the dashboard's usage graphs.

    Query params:
      range   one of 1h, 24h, 7d, 30d, 90d (default 24h)
      refresh force a counter sample before answering
    """
    range_key = request.args.get("range") or traffic.DEFAULT_RANGE
    if request.args.get("refresh"):
        try:
            traffic.sample()
        except Exception:  # noqa: BLE001
            log_event("Usage sample failed", level="warn", source="usage")
    return jsonify(traffic.query(range_key))


@bp.get("/usage/status")
@api_auth
def usage_status():
    return jsonify(traffic.status())


@bp.post("/usage/sample")
@api_auth
def usage_sample():
    """Take a counter sample immediately (used by the UI's refresh button)."""
    try:
        result = traffic.sample()
    except Exception as exc:  # noqa: BLE001
        return _json_error(f"sampling failed: {exc}")
    return jsonify({"ok": True, "sample": result})


@bp.post("/usage/reset")
@api_auth
def usage_reset():
    traffic.reset()
    log_event("Traffic usage counters reset", source="usage")
    return jsonify({"ok": True})


# --------------------------------------------------------------------------
# Master pause ("dinner time")
# --------------------------------------------------------------------------
@bp.post("/pause-all")
@api_auth
def pause_all():
    """Pause internet for every device at once, optionally on a timer."""
    body = _body()
    raw = body.get("minutes")
    label = (body.get("label") or "").strip() or None

    clear_pauses("all", "*")

    if raw in (None, "", 0, "0"):
        add_pause("all", "*", "block", None, label or "Paused (all devices)")
        engine.reconcile(force=True)
        log_event("Internet paused for all devices until resumed", source="controls")
        return jsonify({"ok": True, "paused": True, "minutes": None, "indefinite": True})

    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        return _json_error("minutes must be a number")

    try:
        add_pause("all", "*", "block", minutes, label or "Paused (all devices)")
    except ValueError as exc:
        return _json_error(str(exc))

    engine.reconcile(force=True)
    log_event(f"Paused internet for all devices for {humanise_duration(minutes * 60)}", source="controls")
    return jsonify({"ok": True, "paused": True, "minutes": minutes, "indefinite": False})


@bp.post("/resume-all")
@api_auth
def resume_all():
    clear_pauses("all", "*")
    engine.reconcile(force=True)
    log_event("Internet resumed for all devices", source="controls")
    return jsonify({"ok": True, "paused": False})


# --------------------------------------------------------------------------
# Device approval (unknown-device quarantine)
# --------------------------------------------------------------------------
@bp.post("/devices/<mac>/approve")
@api_auth
def device_approve(mac: str):
    if not get_device(mac):
        return _json_error("device not found", 404)
    approved = bool(_body().get("approved", True))
    approve_device(mac, approved)
    engine.reconcile(force=True)
    log_event(f"{'Approved' if approved else 'Unapproved'} device {mac}", source="devices")
    return jsonify({"ok": True})


@bp.post("/devices/approve-all")
@api_auth
def device_approve_all():
    count = approve_all_devices()
    engine.reconcile(force=True)
    log_event(f"Approved {count} pending device(s)", source="devices")
    return jsonify({"ok": True, "approved": count})


@bp.get("/devices/unapproved")
@api_auth
def devices_unapproved():
    decisions = engine.last_result().get("decisions") or {}
    now = to_ts()
    dns_ips = dns_client_ips()
    return jsonify(
        {"devices": [_device_payload(d, decisions, now, dns_ips) for d in list_unapproved()]}
    )


# --------------------------------------------------------------------------
# Web filtering rules
# --------------------------------------------------------------------------
def _rule_payload(rule: dict[str, Any]) -> dict[str, Any]:
    group_id = int(rule.get("group_id") or 0)
    return {
        "id": rule["id"],
        "group_id": group_id,
        "group_name": rule.get("group_name") or ("Everyone" if group_id == 0 else None),
        "pattern": rule["pattern"],
        "action": rule["action"],
        "enabled": bool(rule["enabled"]),
        "source": rule.get("source") or "custom",
    }


@bp.get("/web-rules")
@api_auth
def web_rules():
    group_id = request.args.get("group_id")
    gid = int(group_id) if group_id not in (None, "") else None
    return jsonify({"rules": [_rule_payload(r) for r in list_web_rules(gid)]})


@bp.post("/web-rules")
@api_auth
def web_rules_create():
    body = _body()
    pattern = (body.get("pattern") or "").strip()
    action = body.get("action") or "block"
    group_id = body.get("group_id") or 0
    if group_id not in (0, "0", None) and not get_group(int(group_id)):
        return _json_error("group not found", 404)

    try:
        rule_id = add_web_rule(int(group_id), pattern, action)
    except ValueError as exc:
        return _json_error(str(exc))

    _reload_dns_rules()
    log_event(f"Web filter: {action} {pattern}", source="filter")
    return jsonify({"ok": True, "rule": _rule_payload(next(r for r in list_web_rules() if r["id"] == rule_id))})


@bp.patch("/web-rules/<int:rule_id>")
@api_auth
def web_rules_update(rule_id: int):
    body = _body()
    fields = {k: body[k] for k in ("pattern", "action", "enabled") if k in body}
    try:
        if not update_web_rule(rule_id, **fields):
            return _json_error("rule not found", 404)
    except ValueError as exc:
        return _json_error(str(exc))
    _reload_dns_rules()
    return jsonify({"ok": True})


@bp.delete("/web-rules/<int:rule_id>")
@api_auth
def web_rules_delete(rule_id: int):
    if not delete_web_rule(rule_id):
        return _json_error("rule not found", 404)
    _reload_dns_rules()
    log_event(f"Web filter: removed rule #{rule_id}", source="filter")
    return jsonify({"ok": True})


def _reload_dns_rules() -> None:
    try:
        dnsfilter.get_proxy().set_rules(web_rules_as_objects())
    except Exception:  # noqa: BLE001
        log_event("Could not reload DNS filter rules", level="warn", source="filter")


# --------------------------------------------------------------------------
# DNS proxy
# --------------------------------------------------------------------------
@bp.get("/dns/status")
@api_auth
def dns_status():
    proxy = dnsfilter.get_proxy()
    lan = runtime_settings.lan_iface()
    rules = list_web_rules()
    return jsonify(
        {
            "running": proxy.is_running(),
            "port": proxy.port,
            "listen_port": proxy.listen_port,
            "interceptable": proxy.interceptable,
            "bound_to": list(proxy.bound_to) if proxy.bound_to else None,
            "upstreams": list(proxy.upstreams),
            "stats": dict(proxy.stats),
            "interception": (
                firewall.dns_redirect_active(lan, target_port=proxy.listen_port) if not firewall.dry_run() else False
            ),
            "lan_iface": lan,
            "rule_count": len(rules),
            "block_rules": sum(1 for r in rules if r["action"] == "block" and r["enabled"]),
            "allow_rules": sum(1 for r in rules if r["action"] == "allow" and r["enabled"]),
            "sources": dns_source_stats(),
            "direct_clients": sorted(dns_client_ips()),
            "device_blocking_available": not dns_source_stats().get("suspected_relay", False),
            "dry_run": firewall.dry_run(),
        }
    )


@bp.post("/dns/start")
@api_auth
def dns_start():
    proxy = dnsfilter.get_proxy()
    proxy.set_rules(web_rules_as_objects())
    started = proxy.start()
    interception = firewall.setup_dns_redirect(
        runtime_settings.lan_iface(), enabled=started, target_port=proxy.listen_port
    )
    log_event("DNS filtering started" if started else "DNS filtering failed to start",
              level="info" if started else "error", source="filter")
    return jsonify({"ok": started, "running": proxy.is_running(), "interception": interception})


@bp.post("/dns/stop")
@api_auth
def dns_stop():
    proxy = dnsfilter.get_proxy()
    firewall.setup_dns_redirect(runtime_settings.lan_iface(), enabled=False, target_port=proxy.listen_port)
    proxy.stop()
    log_event("DNS filtering stopped", source="filter")
    return jsonify({"ok": True, "running": proxy.is_running()})


@bp.get("/dns/queries")
@api_auth
def dns_queries():
    limit = request.args.get("limit", 100)
    return jsonify(
        {
            "queries": list_dns_queries(
                limit=int(limit),
                action=request.args.get("action"),
                search=request.args.get("q"),
                mac=request.args.get("mac"),
            ),
            "stats": dns_query_stats(),
        }
    )


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
@bp.get("/settings")
@api_auth
def settings_get():
    return jsonify(_settings_payload())


def _settings_payload() -> dict[str, Any]:
    return {
        "auto_block_unknown": get_setting("auto_block_unknown", "0") == "1",
        "dns_filtering": get_setting("dns_filtering", "1") == "1",
        "dns_enforces_blocks": get_setting("dns_enforces_blocks", "1") == "1",
        "min_password_length": Config.MIN_PASSWORD_LENGTH,
        "usage_enabled": Config.USAGE_ENABLED,
    }


@bp.patch("/settings")
@api_auth
def settings_patch():
    body = _body()
    if "auto_block_unknown" in body:
        set_setting("auto_block_unknown", "1" if body["auto_block_unknown"] else "0")
    if "dns_enforces_blocks" in body:
        set_setting("dns_enforces_blocks", "1" if body["dns_enforces_blocks"] else "0")
    if "dns_filtering" in body:
        enabled = bool(body["dns_filtering"])
        set_setting("dns_filtering", "1" if enabled else "0")
        proxy = dnsfilter.get_proxy()
        if enabled:
            proxy.set_rules(web_rules_as_objects())
            if not proxy.is_running():
                proxy.start()
            firewall.setup_dns_redirect(runtime_settings.lan_iface(), enabled=True, target_port=proxy.listen_port)
        else:
            firewall.setup_dns_redirect(runtime_settings.lan_iface(), enabled=False, target_port=proxy.listen_port)
            proxy.stop()

    engine.reconcile(force=True)
    return jsonify({"ok": True, "settings": _settings_payload()})


@bp.errorhandler(404)
def not_found(_exc):
    return _json_error("not found", 404)


@bp.errorhandler(405)
def method_not_allowed(_exc):
    return _json_error("method not allowed", 405)


@bp.errorhandler(500)
def server_error(_exc):
    return _json_error("internal server error", 500)
