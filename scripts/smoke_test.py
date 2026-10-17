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
os.environ.setdefault("DNS_PORT", "53999")
os.environ.setdefault("USAGE_INTERVAL_SECONDS", "3600")

from app import create_app  # noqa: E402
from app import engine  # noqa: E402
from app import settings as runtime_settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.models import upsert_device, web_rules_as_objects  # noqa: E402

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
    print("\n-- traffic usage accounting --")
    from app import usage as traffic

    empty = client.get("/api/usage").get_json()
    check("usage endpoint responds", "timeline" in empty and "devices" in empty and "groups" in empty)
    check("usage has totals block", set(empty["totals"]) >= {"up", "down", "total"})
    check("usage lists every device", len(empty["devices"]) == 2, str(len(empty["devices"])))
    check("unknown range falls back", client.get("/api/usage?range=nonsense").status_code == 200)

    # feed known samples through the same path the sampler uses
    now_ts = traffic.to_ts()
    traffic._persist([
        (now_ts, "AA:BB:CC:DD:EE:01", 1000, 9000),
        (now_ts, "AA:BB:CC:DD:EE:02", 500, 500),
        (now_ts, "AA:BB:CC:DD:EE:01", 2000, 0),
    ])

    got = traffic.query("24h")
    check("totals aggregated", got["totals"] == {"up": 3500, "down": 9500, "total": 13000}, str(got["totals"]))
    check("devices sorted by usage", got["devices"][0]["mac"] == "AA:BB:CC:DD:EE:01", str(got["devices"][0]))
    check("device up/down split",
          got["devices"][0]["up"] == 3000 and got["devices"][0]["down"] == 9000, str(got["devices"][0]))
    check("custom name used", got["devices"][0]["name"] == "Sam's Tablet", got["devices"][0]["name"])
    check("percentages computed", abs(got["devices"][0]["percent"] - 92.3) < 0.2, str(got["devices"][0]["percent"]))

    names = {g["name"]: g for g in got["groups"]}
    check("group rollup correct", names.get("Kids", {}).get("total") == 12000, str(names.get("Kids")))
    check("ungrouped bucket created", names.get("Ungrouped", {}).get("total") == 1000, str(names.get("Ungrouped")))
    check("group device counts", names["Kids"]["device_count"] == 1 and names["Ungrouped"]["device_count"] == 1)
    check("timeline bucketed", len(got["timeline"]) > 0 and all("ts" in p and "total" in p for p in got["timeline"]))
    check("timeline sums to totals",
          sum(p["total"] for p in got["timeline"]) == 13000,
          str(sum(p["total"] for p in got["timeline"])))

    # rollups must accumulate independently of the raw table
    hourly = traffic.rows("SELECT SUM(up) AS u, SUM(down) AS d FROM usage_hourly")[0]
    check("hourly rollup matches", (hourly["u"], hourly["d"]) == (3500, 9500), str(hourly))
    daily = traffic.rows("SELECT SUM(up) AS u, SUM(down) AS d FROM usage_daily")[0]
    check("daily rollup matches", (daily["u"], daily["d"]) == (3500, 9500), str(daily))

    check("range filtering excludes nothing for 24h", traffic.query("24h")["totals"]["total"] == 13000)
    check("1h range uses raw samples", traffic.query("1h")["granularity"] == "raw")
    check("7d range uses hourly rollups", traffic.query("7d")["granularity"] == "hourly")
    check("90d range uses daily rollups", traffic.query("90d")["granularity"] == "daily")

    check("usage status", client.get("/api/usage/status").status_code == 200)
    check("manual sample", client.post("/api/usage/sample", json={}, headers=headers).status_code == 200)
    check("reset clears everything",
          client.post("/api/usage/reset", json={}, headers=headers).status_code == 200
          and traffic.query("24h")["totals"]["total"] == 0)

    # ==================================================================
    print("\n-- web filtering: pattern matching --")
    from app import dnsfilter

    check("apex matches itself", dnsfilter.pattern_matches("example.com", "example.com"))
    check("apex matches subdomain", dnsfilter.pattern_matches("example.com", "www.example.com"))
    check("apex matches deep subdomain", dnsfilter.pattern_matches("example.com", "a.b.c.example.com"))
    check("does not match lookalike", not dnsfilter.pattern_matches("example.com", "notexample.com"))
    check("does not match suffix collision", not dnsfilter.pattern_matches("ample.com", "example.com"))
    check("wildcard excludes apex", not dnsfilter.pattern_matches("*.example.com", "example.com"))
    check("wildcard matches subdomain", dnsfilter.pattern_matches("*.example.com", "mail.example.com"))
    check("leading dot stripped", dnsfilter.pattern_matches(".example.com", "www.example.com"))
    check("url form normalised", dnsfilter.normalise_pattern("https://Sub.Example.com/path") == "sub.example.com")
    check("port stripped", dnsfilter.normalise_pattern("example.com:8443") == "example.com")

    rs = dnsfilter.RuleSet([
        dnsfilter.Rule("example.com", "block"),
        dnsfilter.Rule("kids.example.com", "allow"),
    ])
    check("block matches apex", rs.decide("example.com")["action"] == "blocked", str(rs.decide("example.com")))
    check("allow wins on more specific", rs.decide("kids.example.com")["action"] == "allowed",
          str(rs.decide("kids.example.com")))
    check("specific allow covers subdomains", rs.decide("cdn.kids.example.com")["action"] == "allowed")
    check("block still applies elsewhere", rs.decide("video.example.com")["action"] == "blocked")
    check("unmatched domain allowed", rs.decide("bbc.co.uk")["action"] == "allowed")

    tie = dnsfilter.RuleSet([
        dnsfilter.Rule("example.com", "block"),
        dnsfilter.Rule("example.com", "allow"),
    ])
    check("tie on specificity -> allow wins", tie.decide("example.com")["action"] == "allowed")

    print("\n-- web filtering: DNS packets --")
    query = dnsfilter.build_query("ads.tracker.net")
    check("question parsed", dnsfilter.parse_question_name(query) == "ads.tracker.net",
          str(dnsfilter.parse_question_name(query)))
    check("question end located", dnsfilter.question_end(query) == len(query))
    check("truncated packet rejected", dnsfilter.parse_question_name(b"\x00\x01") is None)

    import struct as _struct

    nx = dnsfilter.make_error_response(query, dnsfilter.RCODE_NXDOMAIN)
    check("nxdomain response built", len(nx) > 12)
    check("response sets QR bit", (_struct.unpack("!H", nx[2:4])[0] & 0x8000) != 0)
    check("response rcode is NXDOMAIN", (_struct.unpack("!H", nx[2:4])[0] & 0xF) == 3)
    check("response echoes the question", dnsfilter.parse_question_name(nx) == "ads.tracker.net")
    check("response keeps the query id", nx[0:2] == query[0:2])
    check("response has no answers", _struct.unpack("!H", nx[6:8])[0] == 0)

    print("\n-- web filtering: rules API --")
    w1 = client.post("/api/web-rules", json={"pattern": "BlockedSite.com", "action": "block", "group_id": 0}, headers=headers)
    check("global block rule created", w1.status_code == 200, str(w1.get_json()))
    check("pattern normalised", w1.get_json()["rule"]["pattern"] == "blockedsite.com")
    w2 = client.post("/api/web-rules", json={"pattern": "safe.blockedsite.com", "action": "allow", "group_id": 0}, headers=headers)
    check("global allow rule created", w2.status_code == 200)
    check("rule count reported", len(client.get("/api/web-rules").get_json()["rules"]) >= 2)
    check("rejects empty pattern", client.post("/api/web-rules", json={"pattern": "  "}, headers=headers).status_code == 400)
    check("rejects bad action", client.post("/api/web-rules", json={"pattern": "x.com", "action": "nuke"}, headers=headers).status_code == 400)

    group_rule = client.post("/api/web-rules", json={"pattern": "games.example.com", "action": "block", "group_id": gid}, headers=headers)
    check("group-scoped rule created", group_rule.status_code == 200)

    proxy = dnsfilter.get_proxy()
    proxy.set_rules(web_rules_as_objects())

    # device 01 is in group `gid`, device 02 is ungrouped
    d1 = proxy.decide("games.example.com", "192.168.1.10")
    d2 = proxy.decide("games.example.com", "192.168.1.11")
    check("group rule blocks its member", d1.action == "blocked", str(d1))
    check("group rule spares non-members", d2.action == "allowed", str(d2))
    check("global block applies to everyone", proxy.decide("blockedsite.com", "192.168.1.11").action == "blocked")
    check("global allow overrides global block",
          proxy.decide("safe.blockedsite.com", "192.168.1.11").action == "allowed")

    print("\n-- web filtering: live proxy --")
    check("proxy started on test port", proxy.is_running() or proxy.start(), "could not bind")
    if proxy.is_running():
        import socket as _socket

        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(dnsfilter.build_query("blockedsite.com"), ("127.0.0.1", proxy.port))
            reply, _ = sock.recvfrom(2048)
        check("blocked query answered NXDOMAIN over the wire",
              (_struct.unpack("!H", reply[2:4])[0] & 0xF) == 3, reply[:12].hex())
        check("blocked query logged",
              any(q["domain"] == "blockedsite.com" and q["action"] == "blocked"
                  for q in client.get("/api/dns/queries?action=blocked").get_json()["queries"]))

    check("dns status endpoint", client.get("/api/dns/status").status_code == 200)
    check("dns query log endpoint", client.get("/api/dns/queries").status_code == 200)

    print("\n-- web filtering: rule removal --")
    rid = group_rule.get_json()["rule"]["id"]
    check("rule deleted", client.delete(f"/api/web-rules/{rid}", headers=headers).status_code == 200)
    proxy.set_rules(web_rules_as_objects())
    check("group rule gone after delete", proxy.decide("games.example.com", "192.168.1.10").action == "allowed")

    # ==================================================================
    print("\n-- master pause (all devices) --")
    check("pause-all accepted",
          client.post("/api/pause-all", json={"minutes": 30, "label": "Dinner"}, headers=headers).status_code == 200)
    result = engine.last_result()
    check("pause-all blocks every device",
          all(m in result["blocked"] for m in ("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")), str(result["blocked"]))
    check("pause-all reason shown", "Dinner" in (result["reasons"].get("AA:BB:CC:DD:EE:01") or ""),
          str(result["reasons"].get("AA:BB:CC:DD:EE:01")))
    check("pause-all listed as a timer",
          any(p["target_type"] == "all" for p in client.get("/api/pauses").get_json()["pauses"]))

    check("resume-all accepted", client.post("/api/resume-all", json={}, headers=headers).status_code == 200)
    check("resume-all clears the block",
          "AA:BB:CC:DD:EE:02" not in engine.last_result()["blocked"], str(engine.last_result()["blocked"]))

    check("pause-all without a timer stays until resumed",
          client.post("/api/pause-all", json={}, headers=headers).status_code == 200
          and "AA:BB:CC:DD:EE:02" in engine.last_result()["blocked"])
    client.post("/api/resume-all", json={}, headers=headers)

    # ==================================================================
    print("\n-- unknown device quarantine --")
    check("setting starts off", client.get("/api/settings").get_json()["auto_block_unknown"] is False)
    check("enable auto-block",
          client.patch("/api/settings", json={"auto_block_unknown": True}, headers=headers).status_code == 200
          and client.get("/api/settings").get_json()["auto_block_unknown"] is True)

    upsert_device("AA:BB:CC:DD:FF:99", ip="192.168.1.99", hostname="mystery")
    result = engine.evaluate()
    check("new device quarantined", "AA:BB:CC:DD:FF:99" in result["blocked"], str(result["blocked"]))
    check("quarantine reason shown",
          "waiting for approval" in (result["reasons"].get("AA:BB:CC:DD:FF:99") or ""),
          str(result["reasons"].get("AA:BB:CC:DD:FF:99")))
    check("unapproved listed",
          any(d["mac"] == "AA:BB:CC:DD:FF:99"
              for d in client.get("/api/devices/unapproved").get_json()["devices"]))

    check("approve device",
          client.post("/api/devices/AA:BB:CC:DD:FF:99/approve", json={"approved": True}, headers=headers).status_code == 200)
    check("approved device released",
          "AA:BB:CC:DD:FF:99" not in engine.evaluate()["blocked"])

    upsert_device("AA:BB:CC:DD:FF:98", ip="192.168.1.98")
    check("approve-all clears the queue",
          client.post("/api/devices/approve-all", json={}, headers=headers).status_code == 200
          and client.get("/api/devices/unapproved").get_json()["devices"] == [])

    check("existing devices never quarantined", "AA:BB:CC:DD:EE:02" in [d["mac"] for d in client.get("/api/devices").get_json()["devices"]])
    client.patch("/api/settings", json={"auto_block_unknown": False}, headers=headers)

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
