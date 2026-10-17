# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/Thorinas112/parental-gateway/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Thorinas112/parental-gateway/releases/tag/v1.0.0
