# How Parental Gateway Works

A plain-English tour of the moving parts: what each piece does, how they talk to
each other, and what actually happens when you press **Block**.

* [1. The one-paragraph version](#1-the-one-paragraph-version)
* [2. The three planes](#2-the-three-planes)
* [3. Startup: what happens when the container boots](#3-startup-what-happens-when-the-container-boots)
* [4. First run: the setup wizard](#4-first-run-the-setup-wizard)
* [5. The web interface](#5-the-web-interface)
* [6. Authentication](#6-authentication)
* [7. The database](#7-the-database)
* [8. Finding devices](#8-finding-devices)
* [9. The policy engine](#9-the-policy-engine)
* [10. The firewall](#10-the-firewall)
* [11. Gateway mode: forwarding and NAT](#11-gateway-mode-forwarding-and-nat)
* [12. The background loop](#12-the-background-loop)
* [13. End to end: pressing "Block"](#13-end-to-end-pressing-block)
* [14. Safety and failure design](#14-safety-and-failure-design)
* [15. Where everything lives](#15-where-everything-lives)
* [16. Glossary](#16-glossary)

---

## 1. The one-paragraph version

Parental Gateway is a small web application that sits on your network and
decides which devices are allowed to reach the internet. It **discovers**
devices by their hardware (MAC) address, lets you **name and group** them,
**decides** who is allowed online using your toggles, timers and weekly
schedules, and then **enforces** that decision by writing MAC-address filters
into the Linux kernel's firewall. Everything is stored in one SQLite file, and
the whole thing runs in a single Docker container that acts as your network's
gateway.

```
              ┌────────────────────────────────────────────────────────┐
              │                    Parental Gateway                    │
              │                                                        │
   browser ──▶│  Web UI ──▶ JSON API ──▶ Policy engine ──▶ iptables   │──▶ internet
              │     ▲            ▲              ▲              │       │
              │     │            │              │              ▼       │
              │  templates    sessions       SQLite        PCTRL chain │
              │  + app.js    + CSRF        (app.db)        (per-MAC    │
              │                                                  DROP) │
              └────────────────────────────────────────────────────────┘
                                    ▲
                                    │ ARP scan
                              your LAN devices
```

---

## 2. The three planes

It helps to think about the system in three layers, because they change at
different speeds and fail differently.

| Plane | What it is | Files | Changes |
|---|---|---|---|
| **Data plane** | The kernel firewall actually dropping packets | `firewall.py`, `gateway.py`, `entrypoint.sh` | Every time policy changes |
| **Control plane** | The decision logic — *who should be blocked and why* | `engine.py`, `models.py` | Every 20 s, or on every button press |
| **Management plane** | The UI and API you interact with | `routes/`, `templates/`, `static/` | On every page load |

The important design rule: **the control plane is declarative**. The engine
doesn't say "add a rule" or "remove a rule" — it computes the complete list of
MAC addresses that should be blocked, and the firewall backend makes the kernel
match that list exactly. Nothing can drift out of sync.

---

## 3. Startup: what happens when the container boots

`entrypoint.sh` runs first, as root inside the container:

```
1. enable IP forwarding            echo 1 > /proc/sys/net/ipv4/ip_forward
2. (optional) set a LAN address    ip addr replace 192.168.1.1/24 dev eth1
3. detect the client subnet        ip -o -4 addr show dev eth1
4. install baseline NAT            iptables -t nat -A POSTROUTING -s … -j MASQUERADE
5. exec python -m app              hand over to the web application
```

Then `app/__init__.py` builds the Flask application:

```
init_db()              create the schema if the file is new
ensure_admin_user()    provision an account, or leave the wizard enabled
gateway.bootstrap()    forwarding + NAT with the configured interfaces
scheduler.start()      launch the background reconcile/scan thread
waitress.serve()       start the HTTP server on :8080
```

The HTTP server is **waitress**, not Flask's development server — the dev
server has a reloader that would spawn a second copy of the background
scheduler.

---

## 4. First run: the setup wizard

A brand-new database contains **zero user accounts**. There is no default
password anywhere in the codebase.

```python
def setup_required() -> bool:
    return count_users() == 0
```

While that is true:

* `/` and `/login` redirect to `/setup`
* every protected API returns **428 Precondition Required**
* `POST /api/login` is refused
* `POST /api/setup` is the only thing that will create an account

The wizard has four steps — Welcome (with pre-flight checks), Account, Network,
Finish. The Network step is pre-filled from live detection: the interface
holding the **default route** is preferred, virtual interfaces (`docker*`,
`br-*`, `virbr*`, `lxdbr*`…) are skipped, and a configured interface that
doesn't exist on this host is discarded in favour of the detected one.

Once one account exists the wizard is permanently closed: `/setup` redirects
away and `POST /api/setup` returns **409**. This is deliberate — otherwise
anyone who reached the page could claim a configured install.

> For unattended installs, set `ADMIN_PASSWORD` in the environment and the
> account is created at boot instead, skipping the wizard.

---

## 5. The web interface

There is no front-end framework. Three HTML templates, one stylesheet, one
JavaScript file.

| Page | File | Purpose |
|---|---|---|
| `setup.html` | 4-step wizard | first-run only |
| `login.html` | sign-in form | inline JS |
| `dashboard.html` | the whole app | an empty shell; JS fills it |

`dashboard.html` is deliberately just `<div id="group-grid">`, `<tbody
id="device-body">` and so on. `static/js/app.js` fetches one JSON blob from
`GET /api/overview` and renders everything client-side, then re-fetches every
30 seconds so the dashboard stays current.

That single-call design is why the UI feels instant on first paint: one request
returns devices, groups, schedules, timers, status and the activity log
together.

**`/docs`** is a fourth surface: `app/docs.py` renders the project's own
Markdown documentation to styled HTML at request time, with a section sidebar
generated from the heading structure. It shares one code path with
`scripts/build_docs.py`, which writes self-contained `docs/*.html` files for
offline reading. The routes are deliberately unauthenticated — they are static
documentation with no user data, and they need to be readable during setup,
before any account exists. Only three whitelisted files can ever be served.

**Asset caching.** Static files are served with `Cache-Control: public,
max-age=31536000, immutable`, and every reference is content-hashed:

```html
<link rel="stylesheet" href="/static/css/app.css?v=9a5e3dafbf">
```

Change the file, the hash changes, the URL changes, browsers fetch it
immediately. Without this, a fixed stylesheet never reaches a browser that has
already cached the old one.

### The `hidden` attribute gotcha

CSS like `.modal-backdrop { display: grid }` **out-ranks** the browser's default
`[hidden] { display: none }`, which leaves the element permanently visible. A
global guard exists for exactly this reason:

```css
[hidden] { display: none !important; }
```

---

## 6. Authentication

**Users** are stored as a salted password hash (Werkzeug's default — currently
`scrypt`, with the cost parameters recorded in the hash so they can be raised
later without invalidating existing accounts). Plaintext passwords are never
stored or logged.

**Sessions** are random 32-byte tokens in an `HttpOnly`, `SameSite=Lax` cookie.
The token is a database row — not a signed JWT — so logging out really deletes
it, and a restart can invalidate everything instantly. Sessions expire after
`SESSION_TTL_HOURS` (12 by default).

**CSRF.** Every session also carries a random CSRF token, returned by
`POST /api/login` and `GET /api/session`. Mutating requests must send it in the
`X-CSRF-Token` header. Because the session cookie is `HttpOnly`, JavaScript
can't read it — but it also can't be replayed cross-site thanks to `SameSite`
plus the header requirement.

**Throttling.** Failures are counted per client IP (8 attempts per 5 minutes by
default). The wizard is throttled by the same counter.

The `api_auth` decorator wraps every protected endpoint and does three things
in order: refuse if setup is incomplete (428), verify the session (401), verify
the CSRF token on mutations (403).

---

## 7. The database

One SQLite file at `data/app.db`, in WAL mode, with a process-wide lock so the
web handlers and the background thread don't collide. Eight tables:

| Table | Stores | Key column |
|---|---|---|
| `users` | administrator accounts | `password_hash` |
| `sessions` | login tokens + CSRF secrets | `token`, `expires_at` |
| `devices` | discovered hardware | **`mac` (primary key)** |
| `groups` | "Kids", "Smart TVs", … | `blocked` (block-all flag) |
| `pauses` | temporary timers | `kind` = `block` or `allow`, `expires_at` |
| `schedules` | weekly rules | `days_json`, `start_time`, `end_time` |
| `settings` | runtime config (network, etc.) | `key`/`value` |
| `events` | activity log | `message`, `level` |

Why MAC addresses and not IP addresses? Because **IPs change**. A phone gets a
new DHCP lease tomorrow; its MAC stays the same. Identifying devices by MAC is
what makes the rules survive reboots and renewals.

The whole file is the entire application state. Backing up is `cp app.db`;
restoring is copying it back.

---

## 8. Finding devices

`scanner.py` discovers what's on your network in two ways.

**Primary: ARP probe (scapy).** The scanner broadcasts
*"who has 192.168.1.x?"* for every address in the subnet and records who
answers. This is authoritative — it works even for devices that are silent,
and it's the only way to learn a MAC address from across a network.

**Fallback: the kernel neighbour table (`ip neigh`).** If raw sockets are
unavailable, it reads the addresses the gateway has already learned from normal
traffic. Less complete, but needs no privileges.

Hostnames come from reverse DNS, falling back to DHCP lease files
(`dnsmasq.leases`) if those are present.

Discovery runs every `SCAN_INTERVAL_MINUTES` (10 by default) and on demand when
you press **Scan**. Each result is upserted into `devices`, updating `last_seen`
— so "online" simply means "seen in the last `ONLINE_WINDOW_MINUTES`".

---

## 9. The policy engine

This is the brain. `engine.py` looks at everything in the database and answers
one question per device: **should this MAC be dropped right now, and why?**

Every source of truth has a priority. The highest priority wins.

| Priority | Source | Effect |
|---:|---|---|
| **100** | Manual **Block** — device toggle *or* its group's toggle | 🔴 blocked |
| **80** | **Pause** timer — "pause internet for 30 min" | 🔴 blocked |
| **60** | **Allow** timer — "allow for 1 hour" | 🟢 allowed |
| **40** | Weekly **schedule** window | 🔴 blocked |
| **0** | *(nothing applies)* | 🟢 allowed |

Two consequences worth understanding:

* **A manual block can never be overridden.** Priority 100 beats the Allow
  timer at 60, so a punishment block can't be undone by a leftover allow rule.
* **An Allow timer beats a schedule.** That's the "extend bedtime tonight"
  case: a 60-minute allow window punches through the 21:00–07:00 schedule.

Each decision also records a human-readable **reason**, which is what you see
in the dashboard's "Reason" column — *"Schedule ‘Bedtime’ (21:00–07:00)"* or
*"Paused · 24m left"*.

### Schedules that cross midnight

A window like `21:00 → 07:00` needs care. It is active if **either**:

* today is a selected day and the time is at or after 21:00, **or**
* yesterday was a selected day and the time is before 07:00.

So Friday night's block correctly ends on Saturday morning.

---

## 10. The firewall

`firewall.py` never rewrites your whole ruleset. It owns exactly **one** chain
and jumps to it from the top of `FORWARD`:

```
*filter
-A FORWARD -j PCTRL          # inserted once, at position 1
-A PCTRL -m mac --mac-source AA:BB:CC:DD:EE:01 -j DROP
-A PCTRL -m mac --mac-source AA:BB:CC:DD:EE:04 -j DROP
-A PCTRL -j RETURN
```

Because `PCTRL` is at position 1, it always sees the packet first. Because it
ends in `RETURN`, anything not explicitly dropped falls through to your normal
forwarding rules.

**Reconciliation is declarative.** On every cycle the engine hands over the
desired MAC list; the backend flushes `PCTRL` and rebuilds it to match exactly.
Rules can never duplicate or drift.

### Dry-run mode

`FIREWALL_MODE=off` (or `auto` when `iptables` is missing) puts the app in
**dry-run**: the policy engine computes everything and the UI shows exactly
which rules *would* be installed, but the kernel is never touched. That is how
the test suite runs, and how you can evaluate the UI on a laptop.

### Why MAC filtering and not IP filtering?

An IP filter is trivial to evade — set a static address. A MAC filter binds the
rule to the physical device. It's not unforgeable (a determined user can clone
a MAC), but for family use it's the right trade-off, and it keeps rules
survivable across DHCP renewals.

---

## 11. Gateway mode: forwarding and NAT

Filtering alone isn't enough — the traffic has to actually flow *through* the
container.

```
        [Internet]
             │  WAN (eth0)
   ┌─────────┴──────────────────────────┐
   │  1. net.ipv4.ip_forward = 1        │
   │  2. MASQUERADE 192.168.1.0/24      │   ← NAT: clients share the
   │  3. FORWARD ──▶ PCTRL ──▶ accept   │      gateway's public address
   └─────────┬──────────────────────────┘
             │  LAN (eth1)
       phones, laptops, TVs
```

1. **IP forwarding** tells the kernel to route packets between interfaces
   rather than ignoring them.
2. **MASQUERADE** rewrites the source address of outgoing traffic so replies
   come back to the gateway and can be handed back to the right client. Without
   it, your router has no idea where the traffic came from.
3. The **`PCTRL`** chain sits in the forwarding path and applies the MAC rules.

For enforcement to bite, your **DHCP server must hand out this gateway's IP as
the default route** (option 3 / "router"). If clients route via your normal
router, their traffic never reaches the container and nothing gets filtered.
That's the single most common reason "the blocks don't work".

---

## 12. The background loop

A single daemon thread (`scheduler.py`) drives two jobs:

| Job | Default interval | What it does |
|---|---|---|
| **reconcile** | every 20 s | recompute the policy, apply it if it changed |
| **scan** | every 10 min | rediscover devices, update `last_seen` |

The reconcile step is cheap when nothing changed — it compares the new desired
list against the last applied one and skips the kernel calls entirely.

The loop also purges expired timers as it goes, so a "pause for 30 minutes"
simply stops being true at the right moment and the next reconcile unblocks the
device. No sleeping timers, no callback bookkeeping — expiry is just another
input to the decision.

---

## 13. End to end: pressing "Block"

What actually happens when you flip the switch on *Sam's Tablet*.

```
 1. browser   POST /api/devices/AA:BB:…:01/access   {blocked: true}
              headers: X-CSRF-Token: 3f2a…

 2. api_auth  session valid?  CSRF matches?          → 401 / 403 otherwise

 3. models    UPDATE devices SET blocked = 1 WHERE mac = 'AA:BB:…:01'
              DELETE FROM pauses WHERE target_type='device' AND target_id=…

 4. engine    reconcile(force=True)
              ├─ evaluate()     → decisions: AA:BB:…:01 = (100, blocked, "Blocked manually")
              ├─ desired = ['AA:BB:…:01', …]
              └─ changed? yes

 5. firewall  iptables -w -F PCTRL
              iptables -w -A PCTRL -m mac --mac-source AA:BB:…:01 -j DROP
              iptables -w -A PCTRL -j RETURN

 6. kernel    next packet from that MAC hits FORWARD → PCTRL → DROP

 7. api       {ok: true}  →  JS refreshes /api/overview
              UI shows the row highlighted with reason "Blocked manually"
```

Total elapsed time: a few milliseconds, plus up to 20 s if you'd relied on the
background loop instead of the button press.

---

## 14. Safety and failure design

| Concern | How it's handled |
|---|---|
| **Default password** | None exists. Zero accounts until the wizard runs. |
| **Wizard hijack** | `POST /api/setup` returns 409 once any account exists. |
| **Rules drift** | The chain is rebuilt to match the desired list exactly, every cycle. |
| **Firewall missing** | Dry-run mode: everything computed and displayed, nothing applied. |
| **Bad MAC in a rule** | MACs are normalised and validated (`app/utils.norm_mac`) before they can reach `iptables`. |
| **Scheduler crash** | The loop catches everything; the web UI keeps working and logs the error. |
| **DB corruption** | SQLite WAL; the whole state is one file you can back up or restore. |
| **Restart wipes settings** | Nothing is in memory — all state is in the database, and the session key is persisted to `data/secret.key`. |
| **Locking yourself out** | Blocks only apply to `PCTRL` in `FORWARD`; the web UI is served from the gateway itself and is never blocked by its own rules. |

**One honest limitation.** MAC filtering binds to hardware, not to people. It's
the right tool for a family network, but it is not a security boundary against
someone determined to get around it, and the system is only effective for
devices that route through it. Deploy it on hardware you own or administer, and
tell your family it exists.

---

## 15. Where everything lives

```
parental-gateway/
├── entrypoint.sh            boot: forwarding, NAT, then exec the app
├── Dockerfile               python:3.12-slim + iptables/iproute2/scapy
├── docker-compose.yml       host networking + NET_ADMIN/NET_RAW
├── .env.example             every tunable, documented
│
├── app/
│   ├── __init__.py          Flask factory, bootstrap, cache-busting helper
│   ├── config.py            environment → settings
│   ├── db.py                schema + query helpers
│   ├── settings.py          runtime settings (DB over env)
│   ├── security.py          users, sessions, CSRF, throttling
│   ├── models.py            devices / groups / pauses / schedules
│   ├── scanner.py           ARP discovery            ─┐
│   ├── engine.py            policy evaluation         │ control plane
│   ├── firewall.py          PCTRL chain management    │
│   ├── gateway.py           forwarding + NAT         ─┘
│   ├── scheduler.py         background reconcile + scan
│   ├── routes/
│   │   ├── web.py           HTML pages
│   │   └── api.py           JSON API
│   ├── templates/           setup, login, dashboard
│   └── static/              css/app.css, js/app.js, img/
│
├── scripts/
│   ├── smoke_test.py        60-check backend + policy suite
│   ├── dom_test.mjs         72-check UI render + interaction suite
│   └── setup-gateway.sh     host-side networking helper
│
└── docs/
    ├── HOW_IT_WORKS.md      ← you are here
    └── DEPLOYMENT.md        step-by-step install guide
```

### Which file do I change for…?

| I want to… | Change |
|---|---|
| Add a new rule source (e.g. per-device time budgets) | `engine.py` (add a priority + a `decide()` call) |
| Support nftables instead of iptables | `firewall.py` (same interface, different backend) |
| Change how devices are discovered | `scanner.py` |
| Add a dashboard panel | `templates/dashboard.html` + `static/js/app.js` |
| Add an API endpoint | `routes/api.py`, wrap it in `@api_auth` |
| Change defaults or add a setting | `config.py` and `.env.example` |
| Edit or add documentation | the `.md` file in `docs/`, then `python scripts/build_docs.py` |
| Change how docs look | `app/static/css/docs.css` |
| Alter the schema | `db.py` (add the `CREATE TABLE` and bump nothing — `IF NOT EXISTS` handles fresh installs) |

---

## 16. Glossary

| Term | Meaning |
|---|---|
| **MAC address** | The hardware address of a network interface, e.g. `AA:BB:CC:DD:EE:FF`. Stable per device; used here as the device's identity. |
| **ARP** | Address Resolution Protocol — "who has this IP?" The answer reveals the device's MAC. |
| **iptables** | The Linux packet filter. Rules live in *chains*; `FORWARD` handles routed traffic. |
| **nftables** | The modern replacement for iptables. Most systems (including this container) run `iptables` on top of it. |
| **NAT / MASQUERADE** | Rewriting source addresses so many clients can share one public address. |
| **IP forwarding** | The kernel setting that lets a machine route packets between networks. |
| **DHCP option 3** | The router address handed to clients; must point at the gateway for enforcement to work. |
| **Reconcile** | Recomputing desired state and making reality match it — as opposed to applying incremental changes. |
| **Dry-run** | Computing and displaying the rules without touching the kernel. |
| **CSRF token** | A per-session secret proving a request came from your own page, not a third party. |
| **Password hash** | A salted, deliberately slow one-way transform of a password (here: scrypt). Verifying is cheap given the salt; guessing is expensive without it. |
| **WAL** | Write-Ahead Logging — SQLite's mode for safe concurrent reads and writes. |
