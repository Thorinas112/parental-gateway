# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scripts/setup-host.sh` — prepares a host for deployment: installs the Docker
  Compose V2 and buildx plugins when the distribution's Docker package omitted
  them (as Ubuntu's `docker.io` does), adds the current user to the `docker`
  group, and optionally clones, configures and starts the gateway with
  `--deploy`. Addresses the exact failures seen deploying to a fresh Ubuntu
  box: `docker: unknown command: docker compose`, the legacy-builder
  deprecation, and `permission denied` on `/var/run/docker.sock`.

## [1.0.1] - 2026-10-17

### Fixed

- **The documented "pull the published image" path did not work.** It used
  `curl` against `raw.githubusercontent.com`, which returns 404 for a private
  repository, and a `sed` command that would have left `context:`/`dockerfile:`
  orphaned under a commented-out `build:` parent — producing invalid YAML.
- `docker-compose.yml` now targets `ghcr.io/thorinas112/parental-gateway:latest`
  so `docker compose up -d` pulls and runs with no editing. A new
  `docker-compose.build.yml` override builds from source instead:
  `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`.
- Documented the credentials a private repository and GHCR package require
  (`gh auth login`, `docker login ghcr.io` with `read:packages`), plus the
  commands to make them public if you would rather not manage tokens.
- CI: jsdom 30 needs Node 22+ (its `undici` dependency calls APIs absent in
  Node 20), so the matrix is Node 22/24 and `package.json` declares
  `engines.node >=22`.
- CI: `docker/build-push-action` with `push: false` leaves the image in buildx's
  isolated builder; added `load: true` so the smoke test can actually run it.
- CI: the smoke-test container now publishes its port so the health check can
  reach it.

## [1.0.0] - 2026-10-17

First release. A complete, containerised parental control and network
management gateway.

### Added

**Core**
- First-run setup wizard — a fresh install has no account at all, so there is
  no default password to change. Protected endpoints return `428` until it is
  completed, and the wizard closes permanently once an account exists.
- Session-cookie authentication with scrypt password hashing, per-session CSRF
  tokens and per-IP login throttling.
- Single-file SQLite persistence (WAL) with automatic, additive migrations.

**Network**
- ARP device discovery via scapy with an `ip neigh` fallback; reverse-DNS and
  DHCP-lease hostnames.
- Friendly device naming and colour-coded groups ("Kids", "Smart TVs", …).
- Gateway mode: IP forwarding and NAT (MASQUERADE) bootstrapped by
  `entrypoint.sh`.

**Controls**
- Dynamic `iptables` enforcement by MAC address, confined to a single managed
  `PCTRL` chain that is rebuilt declaratively so rules cannot drift.
- Per-device and per-group block/allow, with a documented rule-precedence model.
- Pause/allow timers (15 min → overnight) and weekly schedules including
  midnight-crossing windows.
- One-click **Pause all** for the whole network, timed or until resumed.
- Unknown-device quarantine — newly seen MACs are held offline until approved.

**Websites**
- Per-group and global domain block/allow rules with wildcard and
  most-specific-wins semantics.
- Built-in DNS proxy (UDP + TCP) answering `NXDOMAIN` for blocked domains.
- `iptables` `PREROUTING` redirect so clients cannot bypass the filter by
  pointing at a public resolver.
- DNS query log with per-device attribution.

**Observability**
- Per-device and per-group traffic graphs driven by kernel byte counters, with
  incremental hourly/daily rollups and 1h–90d ranges.
- Live ruleset viewer, activity log and gateway/firewall status.
- Documentation rendered in-app at `/docs`, plus standalone offline HTML.

**Tooling**
- Dockerfile + docker-compose with `NET_ADMIN`/`NET_RAW` and host networking.
- Backend test suite (160 checks) and jsdom frontend suite (105 checks).
- GitHub Actions CI across multiple Python and Node versions, plus multi-arch
  Docker publishing to GHCR.

[Unreleased]: https://github.com/Thorinas112/parental-gateway/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Thorinas112/parental-gateway/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Thorinas112/parental-gateway/releases/tag/v1.0.0
