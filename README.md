# Parental Gateway

[![CI](https://github.com/Thorinas112/parental-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Thorinas112/parental-gateway/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Thorinas112/parental-gateway)](https://github.com/Thorinas112/parental-gateway/releases)
[![Licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-265%20passing-brightgreen.svg)](#development)

A self-hosted **parental control & network management** appliance that runs in a
Linux container (Docker or LXC) and acts as your network **gateway**.

It discovers every device on your LAN, lets you name and group them, and
enforces internet access rules **by MAC address** — with one-click group
blocking, pause timers and weekly bedtime schedules.

```
                    ┌──────────────────────────────────────────┐
   Internet ◄───────┤  WAN (eth0)   Parental Gateway container │
                    │   · NAT / IP forwarding                  │
                    │   · iptables chain PCTRL (MAC filters)   │
                    │   · Flask web UI  :8080                  │
                    │   · SQLite persistence                   │
                    └───────────────┬──────────────────────────┘
                                    │ LAN (br0 / eth1)
        ┌───────────────┬───────────┼────────────┬──────────────┐
     Sam's Tablet     Kids PC    Smart TV     Console      Parent laptop
     AA:BB:…:01       AA:BB:…:02 AA:BB:…:03   AA:BB:…:04   AA:BB:…:05
        │                 │                        │
        └── assigned to group "Kids" ── schedule 21:00 → 07:00 ── blocked
```

---

## Features

| Area | What you get |
|---|---|
| **Authentication** | Username/password login, signed session cookies, CSRF protection, login throttling |
| **Discovery** | scapy ARP sweep of the subnet with `ip neigh` fallback, reverse-DNS + DHCP-lease hostnames |
| **Device naming** | Friendly names ("Sam's Tablet") stored against the MAC address |
| **Groups / profiles** | Colour-coded groups ("Kids", "Smart TVs", "Dad's Devices") with device assignment |
| **Firewall** | Dynamic `iptables` rules keyed on MAC, all inside one managed `PCTRL` chain |
| **Group controls** | Single-click **Block all / Allow all** for a whole group, or per device |
| **Master pause** | One button to cut off **every** device — 15 min / 30 min / 1 h / 2 h, or until resumed |
| **Timers** | **Pause internet** for 15 min / 30 min / 1 h / 2 h / 4 h / overnight, plus an *Allow* override |
| **Schedules** | Recurring weekly windows (e.g. block *Kids* Mon–Fri 21:00 → 07:00) including midnight-crossing ranges |
| **Website filtering** | Per-group domain block/allow rules, a DNS proxy that answers NXDOMAIN, and a bypass-proof port-53 intercept |
| **Traffic usage** | Per-device and per-group bandwidth graphs with hourly/daily rollups kept long term |
| **Unknown device quarantine** | Any new MAC can be held offline until you approve it |
| **Gateway mode** | IP forwarding + NAT (MASQUERADE) so the container actually routes client traffic |
| **Observability** | Live ruleset viewer, DNS query log, activity log, gateway/firewall status pills |
| **Documentation** | Rendered in-app at `/docs`, plus standalone offline HTML |
| **Persistence** | Everything in a single SQLite file in a bind-mounted volume |

---

## Quick start

> **Note on cloning.** This repository is currently **private**, so `curl` on
> `raw.githubusercontent.com` returns 404 and `git clone`/`docker pull` need
> credentials. Authenticate once first (see [Access and authentication](#access-and-authentication)),
> or make the repository and package public.

### Option A — run the published image (recommended)

Multi-arch (`linux/amd64`, `linux/arm64`) images are published to GHCR on every
release, so a Raspberry Pi deploys exactly the same way as a server. There is
no build step.

**One-liner** — installs the Docker Compose/buildx plugins if they are missing,
adds you to the `docker` group, clones, configures and starts:

```bash
curl -fsSL https://raw.githubusercontent.com/Thorinas112/parental-gateway/main/scripts/setup-host.sh | bash -s -- --deploy
```

**Or by hand:**

```bash
gh repo clone Thorinas112/parental-gateway        # or: git clone <repo-url>
cd parental-gateway

cp .env.example .env
nano .env                                          # set LAN_IFACE / WAN_IFACE

docker compose up -d
xdg-open http://<host-ip>:8080
```

`docker-compose.yml` points at `ghcr.io/thorinas112/parental-gateway:latest` —
it pulls, it does not build.

### Option B — build from source

Same clone and `.env`, then use the build override:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

### Access and authentication

Because the repository is private, you need credentials on the deploying host.

**For the source** — a GitHub token with the `repo` scope:

```bash
gh auth login                              # easiest
# or
git clone https://<TOKEN>@github.com/Thorinas112/parental-gateway.git
```

**For the container image** — a Personal Access Token with `read:packages`:

```bash
# create one at https://github.com/settings/tokens/new  (scope: read:packages)
docker login ghcr.io -u Thorinas112 --password-stdin
```

**Or skip authentication entirely** — make the repo and package public:

```bash
gh repo edit Thorinas112/parental-gateway --visibility public
gh api -X POST user/packages/container/parental-gateway/visibility -f visibility=public
```

**On first run there is no account at all.** The gateway detects an empty
install and serves a **setup wizard** that creates your administrator login and
confirms the network settings. No default password is ever shipped — see
[First-run setup wizard](#first-run-setup-wizard).

> The default profile uses `network_mode: host` with `cap_add: [NET_ADMIN, NET_RAW]`.
> That is required: the container must see the real LAN interface to ARP-scan it
> and to forward client traffic. See `docker-compose.yml` for a bridge-networked
> variant if you only want to try the UI.

Full walkthrough (including Proxmox LXC and making the container the default
gateway for your clients): **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**

How it works internally — the policy engine, the firewall chain, discovery and
the request lifecycle: **[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md)**

---

## Reading the documentation

Three ways in, whichever suits:

| Where | What |
|---|---|
| **In the app** → `/docs` | Rendered, styled, with a section sidebar. Reachable from the **Docs** button in the dashboard. |
| **Offline files** → `docs/*.html` | Self-contained HTML (CSS inlined) — double-click to open in a browser, or send to someone. |
| **Source** → `*.md` | Plain Markdown, readable on GitHub or in any editor. |

```
http://<host-ip>:8080/docs                # live, from any device
docs/HOW_IT_WORKS.html                    # standalone, works offline
docs/DEPLOYMENT.html
docs/README.html
```

The `/docs` routes are intentionally **unauthenticated**: they are the
project's own static documentation with no user data, and being able to read
the deployment guide *during* the setup wizard — before any account exists — is
the point. Only three whitelisted files are ever served; nothing else reaches
the filesystem.

Regenerate the standalone HTML after editing a `.md` file:

```bash
python scripts/build_docs.py     # needs `pip install Markdown`
```

---

## Configuration

All settings are environment variables (see `.env.example` for the full list).

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_USERNAME` | `admin` | Username pre-filled by the setup wizard |
| `ADMIN_PASSWORD` | *(empty)* | **Empty = launch the setup wizard.** Set it to auto-provision an account for unattended installs |
| `REQUIRE_SETUP_WIZARD` | `0` | Force the wizard even when `ADMIN_PASSWORD` is set |
| `MIN_PASSWORD_LENGTH` | `8` | Minimum password length enforced by the wizard |
| `SECRET_KEY` | auto-generated in `data/secret.key` | Cookie/session signing key |
| `SESSION_TTL_HOURS` | `12` | Login session lifetime |
| `WEB_PORT` | `8080` | Web UI port |
| `GATEWAY_MODE` | `1` | Enable IP forwarding + NAT at boot |
| `LAN_IFACE` | `eth0` | Interface facing your clients (overridden by the wizard) |
| `WAN_IFACE` | `eth0` | Interface facing the internet (overridden by the wizard) |
| `LAN_SUBNET` | auto-detect | Client subnet in CIDR form (overridden by the wizard) |
| `LAN_IP_CIDR` | *(empty)* | Optional static address for `LAN_IFACE` |
| `SCAN_INTERVAL_MINUTES` | `10` | Background discovery interval (`0` = off) |
| `RECONCILE_INTERVAL_SECONDS` | `20` | How often rules are recomputed |
| `ONLINE_WINDOW_MINUTES` | `5` | "Online" threshold in the UI |
| `FIREWALL_MODE` | `auto` | `auto` / `force` / `off` (dry-run) |
| `FIREWALL_CHAIN` | `PCTRL` | Name of the managed iptables chain |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## First-run setup wizard

A brand-new install has **no user and no password**. Until the wizard is
finished, every protected API returns `428` and all page requests redirect to
`/setup`.

The wizard has four steps:

1. **Welcome** — pre-flight checks (gateway mode, detected subnet, firewall
   backend, interface count) and a warning that the account is unclaimed.
2. **Account** — username + password with confirmation and a strength meter.
   Minimum length is `MIN_PASSWORD_LENGTH` (8 by default).
3. **Network** — LAN interface, WAN interface and client subnet, pre-filled
   from live detection. These are stored in the database and take precedence
   over the environment variables.
4. **Finish** — summary, then straight into the dashboard signed in.

```
GET  /api/setup/status   # unauthenticated: wizard config + detection results
POST /api/setup          # unauthenticated ONLY while zero users exist
```

`POST /api/setup` returns `409` once an account exists, so the wizard can never
be used to hijack a configured install. Failed attempts are throttled with the
same per-IP counter as the login form.

For automated deployments set `ADMIN_PASSWORD` and the wizard is skipped
entirely (the account is created at boot). Set `REQUIRE_SETUP_WIZARD=1` to
override that and force the interactive flow.

---

## How enforcement works

The application never rewrites your whole ruleset. It owns exactly **one**
chain and jumps to it from the top of `FORWARD`:

```
*filter
-A FORWARD -j PCTRL            # inserted once, at position 1
-A PCTRL -m mac --mac-source AA:BB:CC:DD:EE:01 -j DROP
-A PCTRL -m mac --mac-source AA:BB:CC:DD:EE:04 -j DROP
-A PCTRL -j RETURN
```

On every reconcile the app computes the desired MAC list and rebuilds that
chain to match it exactly — so rules can never drift or duplicate.

### Rule precedence (per device)

| Priority | Source | Effect |
|---|---|---|
| 100 | Manual **Block** (device toggle or its group's toggle) | blocked |
| 80 | **Pause** timer ("pause for 30 min") | blocked |
| 60 | **Allow** timer ("allow for 1 hour") | allowed |
| 40 | Weekly **schedule** window | blocked |
| 0 | Default | allowed |

A manual block always wins, so a child can't undo a parental block with an
allow timer. The UI always shows *why* a device is blocked.

---

## Using the dashboard

1. **Scan** — sweep the subnet; devices appear with IP, MAC and hostname.
2. **Rename** — give each device a friendly name (stored against the MAC).
3. **Group** — create "Kids", "Smart TVs", … and drop devices into them.
4. **Block / Allow** — the switch on every device row, or **Block all** on a group card.
5. **Pause…** — pick a duration; a countdown chip appears at the top of the page.
6. **Schedules** — e.g. group *Kids*, Mon–Fri, `21:00 → 07:00`.
7. **Gateway & firewall** — inspect the live `filter` / `nat` rulesets and the activity log.

---

## API

All endpoints are JSON and live under `/api`. Authentication uses the
`pg_session` cookie; mutations additionally require the `X-CSRF-Token` header
(issued by `POST /api/login` and `GET /api/session`).

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/setup/status` | Unauthenticated wizard config + network detection |
| `POST` | `/api/setup` | Create the admin account (only while no user exists) |
| `POST` | `/api/login` | `{username, password}` → sets cookie, returns `{csrf}` |
| `POST` | `/api/logout` | Invalidate the current session |
| `GET` | `/api/session` | Session bootstrap for the UI |
| `GET` | `/api/overview` | Everything the dashboard needs in one call |
| `POST` | `/api/scan` | Trigger a subnet scan |
| `GET` | `/api/devices` | List discovered devices |
| `PATCH` | `/api/devices/{mac}` | `{name, group_id, blocked}` |
| `POST` | `/api/devices/{mac}/access` | `{blocked}` |
| `POST` | `/api/devices/{mac}/timer` | `{minutes, kind: block\|allow, label}` |
| `DELETE` | `/api/devices/{mac}` | Forget a device |
| `GET` `POST` | `/api/groups` | List / create groups |
| `PATCH` `DELETE` | `/api/groups/{id}` | Edit / delete a group |
| `POST` | `/api/groups/{id}/access` | `{blocked}` — block/allow the whole group |
| `POST` | `/api/groups/{id}/timer` | `{minutes, kind}` |
| `GET` `POST` | `/api/schedules` | List / create weekly schedules |
| `PATCH` `DELETE` | `/api/schedules/{id}` | Edit / delete a schedule |
| `GET` | `/api/pauses` | Active timers |
| `DELETE` | `/api/pauses/{id}` | Cancel a timer |
| `POST` | `/api/pause-all` | Pause **every** device — `{minutes}` or omit for "until resumed" |
| `POST` | `/api/resume-all` | Undo the master pause |
| `POST` | `/api/devices/{mac}/approve` | Approve/unapprove a quarantined device |
| `GET` | `/api/devices/unapproved` | Devices waiting for approval |
| `GET` `POST` | `/api/web-rules` | List / create domain filter rules |
| `PATCH` `DELETE` | `/api/web-rules/{id}` | Enable / disable / delete a rule |
| `GET` | `/api/dns/status` | Proxy state, rule counts, interception status |
| `POST` | `/api/dns/start` `/api/dns/stop` | Control the DNS proxy |
| `GET` | `/api/dns/queries` | Blocked/allowed query log (`?action=`, `?q=`, `?mac=`) |
| `GET` | `/api/usage` | Traffic graphs (`?range=1h\|24h\|7d\|30d\|90d`) |
| `POST` | `/api/usage/sample` `/api/usage/reset` | Sample now / clear history |
| `GET` `PATCH` | `/api/settings` | `auto_block_unknown`, `dns_filtering` |
| `GET` | `/api/status` | Gateway + firewall + policy status |
| `GET` | `/api/rules` | Live `iptables -S` output |
| `POST` | `/api/system/reconcile` | Force a rules re-apply |
| `POST` | `/api/system/nat` | `{enabled}` |
| `GET` | `/api/events` | Activity log |
| `GET` | `/healthz` | Unauthenticated liveness probe |

---

## Project layout

```
parental-gateway/
├── .github/workflows/         # CI + release/publish pipelines
├── Dockerfile                 # slim Python image + iptables/iproute2/scapy tooling
├── docker-compose.yml         # runs the published image (host networking + caps)
├── docker-compose.build.yml   # override: build the image from source
├── entrypoint.sh              # ip_forward, NAT bootstrap, interface config
├── requirements.txt
├── .env.example
├── LICENSE                    # MIT
├── CHANGELOG.md               # Keep a Changelog
├── SECURITY.md                # policy, hardening checklist, limitations
├── app/
│   ├── __init__.py            # Flask factory, bootstrap, waitress entry point
│   ├── config.py              # env-driven configuration
│   ├── db.py                  # SQLite schema + migrations
│   ├── security.py            # users, session tokens, CSRF, throttling
│   ├── models.py              # devices / groups / pauses / schedules / rules
│   ├── settings.py            # runtime settings (DB over env)
│   ├── docs.py                # Markdown -> HTML documentation renderer
│   ├── dnsfilter.py           # domain matching + DNS proxy
│   ├── scanner.py             # scapy ARP + `ip neigh` discovery
│   ├── usage.py               # byte counters -> SQLite -> aggregates
│   ├── firewall.py            # iptables PCTRL chain management
│   ├── gateway.py             # IP forwarding, NAT, interface state
│   ├── engine.py              # policy evaluation & reconciliation
│   ├── scheduler.py           # background reconcile + scan + sample loop
│   ├── routes/                # web + JSON API blueprints
│   ├── templates/             # setup.html, login.html, dashboard.html
│   └── static/                # css/app.css, css/docs.css, js/app.js
├── scripts/
│   ├── smoke_test.py          # backend API + policy-engine test suite
│   ├── dom_test.mjs           # dashboard render + interaction test suite
│   ├── build_docs.py          # render standalone docs/*.html files
│   └── setup-gateway.sh       # host-side helper (forwarding, routing, dnsmasq)
└── docs/
    ├── HOW_IT_WORKS.md        architecture & design explainer
    ├── DEPLOYMENT.md          step-by-step deployment guide
    └── *.html                 standalone renders for offline reading
```

---

## Development

```bash
# backend: API + policy-engine suite (no root, no iptables needed)
python scripts/smoke_test.py

# frontend: jsdom render + interaction suite
npm install          # installs jsdom (dev only)
node scripts/dom_test.mjs

# or both
npm test

# run locally against a dummy firewall
FIREWALL_MODE=off GATEWAY_MODE=0 DATA_DIR=./data python -m app
```

`FIREWALL_MODE=off` puts the app in **dry-run**: the policy engine still
computes everything and the UI shows exactly which rules *would* be installed,
but the kernel is never touched. Useful for testing on a laptop.

---

## Security notes

See **[SECURITY.md](SECURITY.md)** for the full policy, supported versions and
the system's known limitations.

**Before the UI is reachable by anyone else:**

- [ ] Complete the **setup wizard** — while it is pending, whoever reaches
      `/setup` first claims the administrator account. No default password exists.
- [ ] Use a long random `SECRET_KEY` so sessions survive container rebuilds;
      otherwise one is generated and persisted in `data/secret.key`.
- [ ] Set `SESSION_COOKIE_SECURE=1` if you front the UI with TLS.
- [ ] Restrict port 8080 to your LAN subnet at the firewall.
- [ ] Keep `./data` backed up and not world-readable — it holds the database
      (device MACs, hostnames, schedules) and the session signing key.
- [ ] Keep the host patched and rebuild the image regularly.
- [ ] Tell your family the network is filtered.* Cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` when
  `SESSION_COOKIE_SECURE=1` (set this if you terminate TLS in front).
* Mutating API calls require a per-session CSRF token.
* Logins are throttled per client IP (8 attempts / 5 minutes by default).
* The container needs `NET_ADMIN` to manage `iptables`. Do **not** add
  `privileged: true` — it is not required.
* This tool controls *your own* network. Only deploy it on hardware you own or
  administer, and tell your family it exists.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Firewall pill shows **dry-run** | `iptables` is missing or the container lacks `NET_ADMIN`. Add `cap_add: [NET_ADMIN, NET_RAW]`. |
| `could not enable net.ipv4.ip_forward` / `forwarding: False` | The container cannot write the sysctl. With `network_mode: host` it shares the host's network namespace, so set it **on the host** instead: `sysctl -w net.ipv4.ip_forward=1`. If the host is itself an **LXC**, the container may refuse the write — add `lxc.sysctl.net.ipv4.ip_forward: 1` to `/etc/pve/lxc/<CTID>.conf` and restart. Without forwarding the `FORWARD` chain never sees a packet, so no blocking happens. |
| No devices found on Scan | Host networking is required. Bridge networking cannot see your LAN. |
| Rules computed but clients still online | Clients must route **through** this container — set their DHCP gateway to the container IP (see deployment guide). |
| "could not auto-detect LAN_SUBNET" | Set `LAN_SUBNET=192.168.1.0/24` explicitly in `.env`. |
| `docker: unknown command: docker compose` | The Compose V2 plugin is missing — Ubuntu's `docker.io` package does not ship it. `sudo apt-get install -y docker-compose-v2`, or run `scripts/setup-host.sh`. |
| `permission denied` on `/var/run/docker.sock` | Your user is not in the `docker` group: `sudo usermod -aG docker $USER && newgrp docker`. |
| `error from registry: unauthorized` when pulling | The GHCR package is private. Either make it public, `docker login ghcr.io` with a `read:packages` token, or build with the `docker-compose.build.yml` override. |
| Sessions lost on restart | Set `SECRET_KEY` in `.env`, or keep the `./data` volume. |
| Schedules not firing | Schedules use the container clock — set `TZ` correctly. |

---

## Licence

[MIT](LICENSE) — use it, modify it, ship it.

## Releases

Every tag matching `v*` runs the full test suite, builds a multi-arch image and
publishes it to GHCR, then opens a GitHub Release with notes pulled from
[CHANGELOG.md](CHANGELOG.md).

```bash
# cutting a release is one command
git tag v1.1.0 && git push origin v1.1.0
```

| | |
|---|---|
| **Images** | `ghcr.io/thorinas112/parental-gateway` (`linux/amd64`, `linux/arm64`) |
| **Tags** | `latest`, `1.1.0`, `1.1` |
| **Changelog** | [CHANGELOG.md](CHANGELOG.md) |
