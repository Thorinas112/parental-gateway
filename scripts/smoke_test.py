"""Smoke test for the Parental Gateway (runs anywhere, no iptables needed).

Covers the first-run setup wizard, authentication, the policy engine, timers,
schedules and the system endpoints.

    python scripts/smoke_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DATA_DIR", Path(tempfile.mkdtemp(prefix="pg-smoke-")).as_posix())
os.environ.setdefault("DB_PATH", os.path.join(os.environ["DATA_DIR"], "smoke.db"))
# NOTE: ADMIN_PASSWORD is deliberately NOT set - the wizard must be the only
# way an account comes into existence on a fresh install.
os.environ.pop("ADMIN_PASSWORD", None)
os.environ.pop("ADMIN_USERNAME", None)
os.environ.setdefault("FIREWALL_MODE", "off")
os.environ.setdefault("GATEWAY_MODE", "0")
os.environ.setdefault("SCAN_INTERVAL_MINUTES", "0")
os.environ.setdefault("RECONCILE_INTERVAL_SECONDS", "3600")

from app import create_app  # noqa: E402
from app import engine  # noqa: E402
from app import settings as runtime_settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.models import upsert_device  # noqa: E402

PASS, FAIL = 0, 0
CREDS = {"username": "admin", "password": "test-password-123"}


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ok   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label} {detail}")


def main() -> int:
    global csrf
    print("== Parental Gateway smoke test ==")
    app = create_app()
    client = app.test_client()

    # ==================================================================
    print("\n-- first-run setup wizard --")
    init_db()
    check("healthz works with no account", client.get("/healthz").status_code == 200)
    check("setup page renders", b"setup-card" in client.get("/setup").data)

    root = client.get("/")
    check("root redirects to setup", root.status_code == 302 and "/setup" in (root.headers.get("Location") or ""),
          str(root.headers.get("Location")))
    login_page = client.get("/login")
    check("login redirects to setup", login_page.status_code == 302 and "/setup" in (login_page.headers.get("Location") or ""))

    check("protected API refused (428)", client.get("/api/overview").status_code == 428)
    check("login refused while unconfigured",
          client.post("/api/login", json={"username": "admin", "password": "x"}).status_code == 428)

    status = client.get("/api/setup/status").get_json()
    check("setup status reports required", status.get("required") is True)
    check("wizard gets interface list", isinstance(status.get("interfaces"), list))
    check("wizard gets min password length", status.get("min_password_length", 0) >= 8)
    check("wizard gets network defaults", set(status.get("network", {})) >= {"lan_iface", "wan_iface", "lan_subnet"})

    def setup(payload):
        return client.post("/api/setup", json=payload)

    check("rejects short password",
          setup({"username": "admin", "password": "short", "confirm": "short"}).status_code == 400)
    check("rejects mismatched passwords",
          setup({"username": "admin", "password": "test-password-123", "confirm": "different-one"}).status_code == 400)
    check("rejects bad username",
          setup({"username": "bad name!", "password": "test-password-123", "confirm": "test-password-123"}).status_code == 400)
    check("rejects empty username",
          setup({"username": "", "password": "test-password-123", "confirm": "test-password-123"}).status_code == 400)
    check("rejects malformed subnet",
          setup({"username": "admin", "password": "test-password-123", "confirm": "test-password-123",
                 "lan_subnet": "not-a-cidr"}).status_code == 400)
    check("account still absent after failures", client.get("/api/setup/status").get_json()["required"] is True)

    created = setup({
        "username": CREDS["username"],
        "password": CREDS["password"],
        "confirm": CREDS["password"],
        "lan_iface": "eth1",
        "wan_iface": "eth0",
        "lan_subnet": "192.168.1.0/24",
    })
    check("setup completes", created.status_code == 200, f"{created.status_code} {created.get_json()}")
    csrf = created.get_json().get("csrf")
    check("session + csrf issued", bool(csrf))
    check("wizard network settings persisted",
          (runtime_settings.lan_iface(), runtime_settings.wan_iface(), runtime_settings.lan_subnet())
          == ("eth1", "eth0", "192.168.1.0/24"),
          str(runtime_settings.network_summary()))
    check("subsequent setup refused (409)",
          setup({"username": "attacker", "password": "test-password-123", "confirm": "test-password-123"}).status_code == 409)
    check("second account not created",
          client.get("/api/session").get_json()["user"]["username"] == CREDS["username"])

    headers = {"X-CSRF-Token": csrf}
    check("root serves dashboard after setup", client.get("/").status_code == 200)
    check("setup page now redirects away", client.get("/setup").status_code == 302)

    dashboard_html = client.get("/").data.decode()
    check("static assets are cache-busted", "app.css?v=" in dashboard_html,
          dashboard_html[dashboard_html.find("app.css") - 20:dashboard_html.find("app.css") + 40] if "app.css" in dashboard_html else "app.css not referenced")
    check("js is cache-busted", "app.js?v=" in dashboard_html)

    # ==================================================================
    print("\n-- authentication --")
    client.post("/api/logout", json={}, headers=headers)
    check("session revoked on logout", client.get("/api/overview").status_code == 401)

    bad = client.post("/api/login", json={"username": "admin", "password": "wrong"})
    check("bad password rejected", bad.status_code == 401, str(bad.status_code))
    ok = client.post("/api/login", json=CREDS)
    check("login succeeds", ok.status_code == 200, str(ok.status_code))
    csrf = ok.get_json().get("csrf")
    headers = {"X-CSRF-Token": csrf}
    check("csrf issued", bool(csrf))
    check("session cookie set", "pg_session" in (ok.headers.get("Set-Cookie") or ""))
    check("overview loads", client.get("/api/overview").status_code == 200)
    check("csrf required on POST", client.post("/api/groups", json={"name": "x"}).status_code == 403)

    # ==================================================================
    print("\n-- devices & groups --")
    upsert_device("AA:BB:CC:DD:EE:01", ip="192.168.1.10", hostname="tablet")
    upsert_device("aa-bb-cc-dd-ee-02", ip="192.168.1.11", hostname="tv")

    devices = client.get("/api/devices").get_json()["devices"]
    check("two devices discovered", len(devices) == 2, str(len(devices)))
    check("mac normalised", any(d["mac"] == "AA:BB:CC:DD:EE:02" for d in devices))

    grp = client.post("/api/groups", json={"name": "Kids", "color": "#f87171"}, headers=headers)
    check("group created", grp.status_code == 200, str(grp.status_code))
    gid = grp.get_json()["group"]["id"]

    patch = client.patch("/api/devices/AA%3ABB%3ACC%3ADD%3AEE%3A01", json={"group_id": gid, "name": "Sam's Tablet"}, headers=headers)
    check("device assigned to group", patch.status_code == 200, str(patch.status_code))
    check("url-encoded MAC accepted", patch.get_json()["device"]["mac"] == "AA:BB:CC:DD:EE:01")
    check("custom name saved", patch.get_json()["device"]["name"] == "Sam's Tablet")

    # ==================================================================
    print("\n-- firewall policy engine --")
    client.post(f"/api/groups/{gid}/access", json={"blocked": True}, headers=headers)
    result = engine.last_result()
    check("group block marks member", "AA:BB:CC:DD:EE:01" in result["blocked"])
    check("non-member stays open", "AA:BB:CC:DD:EE:02" not in result["blocked"])
    check("reason recorded", "Kids" in (result["reasons"].get("AA:BB:CC:DD:EE:01") or ""))

    client.post(f"/api/groups/{gid}/access", json={"blocked": False}, headers=headers)
    client.post("/api/devices/AA:BB:CC:DD:EE:02/timer", json={"minutes": 15, "kind": "block"}, headers=headers)
    result = engine.last_result()
    check("pause timer blocks device", "AA:BB:CC:DD:EE:02" in result["blocked"])

    pauses = client.get("/api/pauses").get_json()["pauses"]
    check("timer listed", len(pauses) == 1)
    client.delete(f"/api/pauses/{pauses[0]['id']}", headers=headers)
    check("timer cleared", "AA:BB:CC:DD:EE:02" not in engine.last_result()["blocked"])

    # ==================================================================
    print("\n-- schedules --")
    sched = client.post(
        "/api/schedules",
        json={"group_id": gid, "days": [0, 1, 2, 3, 4], "start_time": "21:00", "end_time": "07:00", "name": "Bedtime"},
        headers=headers,
    )
    check("schedule created", sched.status_code == 200, str(sched.status_code))
    check("days decoded", sched.get_json()["schedule"]["days"] == [0, 1, 2, 3, 4])

    from app.utils import schedule_active
    from datetime import datetime

    late = datetime(2026, 10, 13, 22, 30)   # Monday 22:30
    morning = datetime(2026, 10, 14, 6, 0)  # Tuesday 06:00
    midday = datetime(2026, 10, 14, 12, 0)  # Tuesday 12:00
    check("window active late evening", schedule_active([0, 1, 2, 3, 4], "21:00", "07:00", late))
    check("window active after midnight", schedule_active([0, 1, 2, 3, 4], "21:00", "07:00", morning))
    check("window inactive at midday", not schedule_active([0, 1, 2, 3, 4], "21:00", "07:00", midday))

    evaluated = engine.evaluate(late)
    check("schedule blocks member at 22:30", "AA:BB:CC:DD:EE:01" in evaluated["blocked"])
    check("schedule leaves others open", "AA:BB:CC:DD:EE:02" not in evaluated["blocked"])
    check("schedule reason shown", "Bedtime" in (evaluated["reasons"].get("AA:BB:CC:DD:EE:01") or ""))

    evaluated = engine.evaluate(midday)
    check("schedule releases at midday", "AA:BB:CC:DD:EE:01" not in evaluated["blocked"])

    print("\n-- allow timer overrides schedule --")
    client.post(f"/api/groups/{gid}/timer", json={"minutes": 60, "kind": "allow", "label": "Movie night"}, headers=headers)
    evaluated = engine.evaluate(late)
    check("allow timer wins over schedule", "AA:BB:CC:DD:EE:01" not in evaluated["blocked"])

    # ==================================================================
    print("\n-- documentation --")
    anon = app.test_client()  # deliberately no session
    check("docs index redirects", anon.get("/docs").status_code == 302)

    for slug, needle in (
        ("how-it-works", b"policy engine"),
        ("deployment", b"DHCP"),
        ("readme", b"iptables"),
    ):
        page = anon.get(f"/docs/{slug}")
        body = page.data
        check(f"doc '{slug}' renders", page.status_code == 200 and b"docs-content" in body)
        check(f"doc '{slug}' has content", needle.lower() in body.lower(), needle.decode())
        check(f"doc '{slug}' has a toc", b"docs-toc" in body and b"On this page" in body)
        check(f"doc '{slug}' is self-contained", b"docs-body" in body and b"<style>" in body)

    check("unknown doc returns 404", anon.get("/docs/nope-not-real").status_code == 404)
    check("docs readable without a session", anon.get("/docs/how-it-works").status_code == 200)
    check("path traversal blocked", anon.get("/docs/..%2f..%2fetc%2fpasswd").status_code == 404)

    rendered = anon.get("/docs/how-it-works").data.decode()
    check("headings get anchors", 'id="' in rendered and "#1-the-one-paragraph-version" in rendered,
          "toc anchor missing")
    check("doc tabs present", all(s in rendered for s in ("How it works", "Deployment", "Reference")))

    # ==================================================================
    print("\n-- system endpoints --")
    check("status", client.get("/api/status").status_code == 200)
    check("rules dump", client.get("/api/rules").status_code == 200)
    check("events", client.get("/api/events").status_code == 200)
    check("reconcile", client.post("/api/system/reconcile", json={}, headers=headers).status_code == 200)

    print("\n-- cleanup / logout --")
    check("logout", client.post("/api/logout", json={}, headers=headers).status_code == 200)
    check("overview requires auth", client.get("/api/overview").status_code == 401)

    print(f"\n== {PASS} passed, {FAIL} failed ==")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
