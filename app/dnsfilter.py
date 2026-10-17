"""DNS-level website filtering.

Three parts:

1. :class:`RuleSet` - decides whether a domain is allowed, purely from
   pattern-matching rules. Fully unit-testable, no I/O.

2. DNS packet helpers - read the question out of a raw query and synthesise an
   NXDOMAIN response without needing a full DNS library.

3. :class:`DnsProxy` - a UDP/TCP server on port 53 that forwards queries
   upstream and answers ``NXDOMAIN`` for blocked domains. Paired with an
   iptables NAT redirect (see :mod:`app.firewall`) so client devices cannot
   bypass it by talking to a public resolver directly.

Pattern semantics
-----------------
==================  ==============================================
``example.com``     matches the domain and every subdomain
``.example.com``    same as above (leading dot is stripped)
``*.example.com``   matches subdomains only, not the apex
``www.example.com`` matches that host and its subdomains
==================  ==============================================

The **most specific** matching rule wins, and when two rules tie on
specificity the **allow** rule wins - so you can block ``youtube.com`` while
still permitting ``kids.youtube.com``.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable

log = logging.getLogger("pg.dns")

DNS_HEADER_SIZE = 12
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
RCODE_SERVFAIL = 2
RCODE_REFUSED = 5

# Cache rule lookups briefly; the proxy answers queries far more often than
# the database changes.
_RULES_TTL = 5.0
_MAC_TTL = 30.0
_LOG_PRUNE_EVERY = 200


# ==========================================================================
# 1. Pattern matching (pure logic)
# ==========================================================================
def normalise_pattern(pattern: str) -> str:
    """Canonicalise a user-supplied domain pattern."""
    value = (pattern or "").strip().lower()
    if not value:
        return ""
    if value.startswith("*."):
        value = value[2:]
    elif value.startswith("*"):
        value = value[1:]
    value = value.lstrip(".")
    if value.startswith("http://"):
        value = value[7:]
    elif value.startswith("https://"):
        value = value[8:]
    value = value.split("/", 1)[0]
    value = value.split(":", 1)[0]
    while value.startswith("."):
        value = value[1:]
    return value.rstrip(".")


def pattern_matches(pattern: str, domain: str) -> bool:
    """True when ``domain`` is covered by ``pattern`` (see module docstring)."""
    raw = (pattern or "").strip().lower()
    # `*.example.com` covers subdomains only; everything else also covers the
    # apex domain. The wildcard has to be detected before normalising, which
    # deliberately strips it.
    wildcard = raw.startswith("*.")
    base = normalise_pattern(pattern)
    domain = (domain or "").strip().lower().rstrip(".")
    if not base or not domain:
        return False
    if wildcard:
        return domain.endswith("." + base)
    return domain == base or domain.endswith("." + base)


@dataclass(frozen=True)
class Rule:
    pattern: str
    action: str  # 'block' | 'allow'
    group_id: int = 0
    source: str = "custom"

    @property
    def base(self) -> str:
        return normalise_pattern(self.pattern)

    @property
    def wildcard(self) -> bool:
        return (self.pattern or "").strip().lower().startswith("*.")

    @property
    def specificity(self) -> int:
        # Rank by the effective domain, not the raw text, so `*.example.com`
        # and `example.com` tie and the allow-wins rule can apply.
        return len(self.base)


class RuleSet:
    """An ordered evaluation of web-filtering rules."""

    def __init__(self, rules: Iterable[Rule] | None = None):
        self.rules: list[Rule] = [r for r in (rules or []) if normalise_pattern(r.pattern)]
        # Most specific first keeps the hot path short-circuit friendly.
        self.rules.sort(key=lambda r: r.specificity, reverse=True)

    def matches(self, domain: str) -> list[Rule]:
        return [r for r in self.rules if pattern_matches(r.pattern, domain)]

    def decide(self, domain: str) -> dict[str, Any]:
        """Return ``{action, reason, pattern}`` for a queried domain."""
        domain = (domain or "").strip().lower().rstrip(".")
        if not domain:
            return {"action": "allowed", "reason": "no domain", "pattern": None}

        hits = self.matches(domain)
        if not hits:
            return {"action": "allowed", "reason": "no matching rule", "pattern": None}

        best = max(r.specificity for r in hits)
        top = [r for r in hits if r.specificity == best]
        winner = next((r for r in top if r.action == "allow"), top[0])

        if winner.action == "allow":
            return {
                "action": "allowed",
                "reason": f"allowed by {winner.pattern}",
                "pattern": winner.pattern,
            }
        return {
            "action": "blocked",
            "reason": f"blocked by {winner.pattern}",
            "pattern": winner.pattern,
        }


# ==========================================================================
# 2. DNS packet helpers
# ==========================================================================
def parse_question_name(packet: bytes) -> str | None:
    """Extract the first question's name, or None if unparseable."""
    if len(packet) < DNS_HEADER_SIZE:
        return None
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount < 1:
        return None

    labels: list[str] = []
    index = DNS_HEADER_SIZE
    total = len(packet)
    while index < total:
        length = packet[index]
        if length == 0:
            index += 1
            break
        if length & 0xC0:
            return None  # compression pointer in a question is malformed
        index += 1
        if index + length > total:
            return None
        try:
            labels.append(packet[index : index + length].decode("idna"))
        except Exception:  # noqa: BLE001
            labels.append(packet[index : index + length].decode("latin-1"))
        index += length
    return ".".join(labels).lower().rstrip(".") or None


def question_end(packet: bytes) -> int | None:
    """Offset just past the question section (name + type + class)."""
    if len(packet) < DNS_HEADER_SIZE:
        return None
    index = DNS_HEADER_SIZE
    total = len(packet)
    while index < total:
        length = packet[index]
        if length == 0:
            index += 1
            return index + 4 if index + 4 <= total else None
        if length & 0xC0:
            return None
        index += 1 + length
    return None


def make_error_response(query: bytes, rcode: int = RCODE_NXDOMAIN) -> bytes:
    """Build a response for ``query`` carrying ``rcode`` and no records."""
    if len(query) < DNS_HEADER_SIZE:
        return b""
    end = question_end(query)
    if end is None:
        return b""

    query_id = struct.unpack("!H", query[0:2])[0]
    query_flags = struct.unpack("!H", query[2:4])[0]
    # keep opcode + RD, set QR + RA, install the rcode
    flags = (query_flags & 0x7900) | 0x8000 | 0x0080 | (rcode & 0x0F)
    # id, flags, qdcount, ancount, nscount, arcount
    header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
    return header + query[12:end]


def build_query(name: str, qtype: int = 1) -> bytes:
    """Build a minimal A/AAAA-style query (handy for tests)."""
    import random

    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.lower().split(".") if label
    )
    header = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    return header + labels + b"\x00" + struct.pack("!HH", qtype, 1)


# ==========================================================================
# 3. The proxy
# ==========================================================================
@dataclass
class DnsDecision:
    action: str
    reason: str
    domain: str
    pattern: str | None = None


class DnsProxy:
    """Forwards DNS upstream, answering NXDOMAIN for blocked domains."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 53,
        upstreams: tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "9.9.9.9"),
        timeout: float = 3.0,
    ):
        self.host = host
        self.port = port
        self.upstreams = upstreams
        self.timeout = timeout

        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._running = False

        self._rules_lock = threading.Lock()
        self._rules_by_group: dict[int, list[Rule]] = {}
        self._rulesets: dict[int, RuleSet] = {}
        self._rules_loaded = 0.0

        self._mac_lock = threading.Lock()
        self._mac_cache: dict[str, tuple[float, Any]] = {}

        self._log_counter = 0
        self.bound_to: tuple[str, int] | None = None
        self.stats = {"queries": 0, "blocked": 0, "allowed": 0, "errors": 0, "started_at": 0}

    # ---------------------------------------------------------------- setup
    def set_rules(self, rules: Iterable[Rule]) -> None:
        """Install the full rule table, indexed per group.

        Group ``0`` is global and applies to everyone; a device's effective
        rule set is the global rules plus the rules of its own group.
        """
        by_group: dict[int, list[Rule]] = {}
        for rule in rules:
            if not normalise_pattern(rule.pattern):
                continue
            by_group.setdefault(int(rule.group_id), []).append(rule)

        rulesets: dict[int, RuleSet] = {}
        group_ids = set(by_group) | {0}
        for gid in group_ids:
            combined = list(by_group.get(0, []))
            if gid:
                combined += list(by_group.get(gid, []))
            rulesets[gid] = RuleSet(combined)

        with self._rules_lock:
            self._rules_by_group = by_group
            self._rulesets = rulesets
            self._rules_loaded = time.time()

    def refresh_rules_if_stale(self, loader) -> None:
        with self._rules_lock:
            fresh = (time.time() - self._rules_loaded) < _RULES_TTL
        if fresh:
            return
        try:
            self.set_rules(loader() or [])
        except Exception:  # noqa: BLE001
            log.debug("rule refresh failed", exc_info=True)

    def ruleset_for(self, group_id: int | None) -> RuleSet:
        with self._rules_lock:
            return self._rulesets.get(int(group_id or 0)) or self._rulesets.get(0) or RuleSet([])

    # ------------------------------------------------------------ decision
    def device_info(self, ip: str) -> tuple[str | None, int]:
        """Return ``(mac, group_id)`` for a client IP, with caching."""
        now = time.time()
        with self._mac_lock:
            hit = self._mac_cache.get(ip)
            if hit and now - hit[0] < _MAC_TTL:
                return hit[1]

        info: tuple[str | None, int] = (None, 0)
        try:
            from .models import device_for_ip

            device = device_for_ip(ip)
            if device:
                info = (device.get("mac"), int(device.get("group_id") or 0))
        except Exception:  # noqa: BLE001
            log.debug("device lookup failed for %s", ip, exc_info=True)

        with self._mac_lock:
            self._mac_cache[ip] = (now, info)
        return info

    def lookup_mac(self, ip: str) -> str | None:
        return self.device_info(ip)[0]

    def decide(self, domain: str, client_ip: str | None = None) -> DnsDecision:
        mac, group_id = self.device_info(client_ip) if client_ip else (None, 0)
        result = self.ruleset_for(group_id).decide(domain)
        return DnsDecision(
            action=result["action"],
            reason=result["reason"],
            domain=domain,
            pattern=result.get("pattern"),
        )

    def handle_query(self, payload: bytes, client_ip: str | None = None) -> bytes:
        """Decide on a query and return the response bytes to send back."""
        self.refresh_rules_if_stale(_load_rules)
        self.stats["queries"] += 1
        domain = parse_question_name(payload)

        if not domain:
            self.stats["errors"] += 1
            return make_error_response(payload, RCODE_SERVFAIL)

        decision = self.decide(domain, client_ip)
        if decision.action == "blocked":
            self.stats["blocked"] += 1
            self._record(decision, client_ip)
            return make_error_response(payload, RCODE_NXDOMAIN)

        self.stats["allowed"] += 1
        self._record(decision, client_ip)
        return self._forward(payload) or make_error_response(payload, RCODE_SERVFAIL)

    def _forward(self, payload: bytes) -> bytes | None:
        for upstream in self.upstreams:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(payload, (upstream, 53))
                    response, _ = sock.recvfrom(4096)
                    return response
            except (socket.timeout, OSError):
                continue
        self.stats["errors"] += 1
        return None

    def _record(self, decision: DnsDecision, client_ip: str | None) -> None:
        self._log_counter += 1
        if self._log_counter % _LOG_PRUNE_EVERY == 0:
            self._prune()
        # Don't log every allowed query - the interesting ones are the blocks
        # plus a sampled view of what devices look up.
        if decision.action == "allowed" and self._log_counter % 25 != 0:
            return
        try:
            from .db import execute

            execute(
                "INSERT INTO dns_queries (ts, mac, ip, domain, action, reason) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    int(time.time()),
                    self.lookup_mac(client_ip) if client_ip else None,
                    client_ip,
                    decision.domain,
                    decision.action,
                    decision.reason,
                ),
            )
        except Exception:  # noqa: BLE001
            log.debug("could not record dns query", exc_info=True)

    def _prune(self) -> None:
        try:
            from .db import execute

            execute("DELETE FROM dns_queries WHERE ts < ?", (int(time.time()) - 7 * 86400,))
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------ serving
    def _candidates(self) -> list[tuple[str, int]]:
        """Host/port pairs to try, best first.

        Binding ``0.0.0.0:53`` is ideal. Port 53 is very often taken
        (dnsmasq, systemd-resolved, a router's own resolver), so an alternate
        port is tried before giving up - the NAT redirect targets whichever
        port we end up on, so interception still works. ``127.0.0.1`` is a
        last resort: it accepts direct queries but cannot be reached by
        REDIRECT, so filtering would be ineffective.
        """
        lan = [h for h in _bind_candidates() if h != "127.0.0.1"]
        wild = self.host if self.host else "0.0.0.0"

        pairs: list[tuple[str, int]] = [(wild, self.port)]
        pairs += [(h, self.port) for h in lan]

        if self.port == 53:
            for alternate in (5300, 5353, 5400):
                pairs.append((wild, alternate))
                pairs += [(h, alternate) for h in lan]

        # Loopback goes last: only useful if nothing else is available.
        pairs.append(("127.0.0.1", self.port))

        seen: set[tuple[str, int]] = set()
        ordered: list[tuple[str, int]] = []
        for pair in pairs:
            if pair not in seen:
                seen.add(pair)
                ordered.append(pair)
        return ordered

    def start(self) -> bool:
        if self._running:
            return True
        self._stop.clear()

        bound: tuple[str, int] | None = None
        last_error: Exception | None = None
        for host, port in self._candidates():
            udp = tcp = None
            try:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp.bind((host, port))

                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp.bind((host, port))
                tcp.listen(16)
                tcp.settimeout(1.0)

                self._udp, self._tcp = udp, tcp
                bound = (host, port)
                break
            except OSError as exc:
                last_error = exc
                for sock in (udp, tcp):
                    try:
                        if sock:
                            sock.close()
                    except OSError:
                        pass

        if bound is None:
            log.warning(
                "DNS proxy could not bind any of %s - %s",
                self._candidates(), last_error,
            )
            self.stop()
            return False

        self._running = True
        self.bound_to = bound
        self.stats["started_at"] = int(time.time())
        self._threads = [
            threading.Thread(target=self._udp_loop, name="dns-udp", daemon=True),
            threading.Thread(target=self._tcp_loop, name="dns-tcp", daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        if bound[0] == "127.0.0.1":
            log.warning(
                "DNS proxy is bound to loopback only - interception cannot reach it. "
                "Free up port %s (or stop dnsmasq/systemd-resolved) for filtering to work.",
                self.port,
            )
        log.info(
            "DNS proxy listening on %s:%s (upstream %s)",
            bound[0], bound[1], ", ".join(self.upstreams),
        )
        return True

    @property
    def listen_port(self) -> int:
        """The port actually bound (may differ from the configured one)."""
        return self.bound_to[1] if self.bound_to else self.port

    @property
    def interceptable(self) -> bool:
        """False when bound to loopback, where NAT REDIRECT cannot reach us."""
        return bool(self.bound_to) and self.bound_to[0] != "127.0.0.1"

    def stop(self) -> None:
        self._stop.set()
        self._running = False
        for sock in (self._udp, self._tcp):
            try:
                if sock:
                    sock.close()
            except OSError:
                pass
        self._udp = self._tcp = None
        self._threads = []

    def is_running(self) -> bool:
        return self._running

    def _udp_loop(self) -> None:
        sock = self._udp
        while sock and not self._stop.is_set():
            try:
                sock.settimeout(1.0)
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                response = self.handle_query(data, addr[0])
                if response:
                    sock.sendto(response, addr)
            except Exception:  # noqa: BLE001
                log.exception("dns udp handler failed")

    def _tcp_loop(self) -> None:
        sock = self._tcp
        while sock and not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._tcp_handle, args=(conn, addr), daemon=True
            ).start()

    def _tcp_handle(self, conn: socket.socket, addr) -> None:
        try:
            conn.settimeout(self.timeout + 2)
            header = self._recv_exact(conn, 2)
            if not header:
                return
            (length,) = struct.unpack("!H", header)
            payload = self._recv_exact(conn, length)
            if not payload:
                return
            response = self.handle_query(payload, addr[0])
            if response:
                conn.sendall(struct.pack("!H", len(response)) + response)
        except Exception:  # noqa: BLE001
            log.debug("dns tcp handler failed", exc_info=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(conn: socket.socket, count: int) -> bytes:
        buffer = b""
        while len(buffer) < count:
            chunk = conn.recv(count - len(buffer))
            if not chunk:
                return b""
            buffer += chunk
        return buffer


# --------------------------------------------------------------------------
# Module-level singleton
# --------------------------------------------------------------------------
def _bind_candidates() -> list[str]:
    """Hosts worth trying when ``0.0.0.0`` is already taken.

    Order matters: the LAN address first (that is where the REDIRECT sends
    client packets), then loopback.
    """
    hosts: list[str] = []
    try:
        from . import settings as runtime_settings

        info = gateway_interface_address(runtime_settings.lan_iface())
        if info:
            hosts.append(info)
    except Exception:  # noqa: BLE001
        log.debug("could not resolve LAN address", exc_info=True)

    for candidate in ("127.0.0.1",):
        if candidate not in hosts:
            hosts.append(candidate)
    return hosts


def gateway_interface_address(iface: str) -> str | None:
    from .gateway import interface_info

    address = interface_info(iface).get("address")
    return address.split("/")[0] if address else None


def _load_rules() -> list[Rule]:
    """Loader used to keep the proxy's rule cache fresh."""
    try:
        from .models import web_rules_as_objects

        return list(web_rules_as_objects())
    except Exception:  # noqa: BLE001
        log.debug("could not load web rules", exc_info=True)
        return []


_proxy: DnsProxy | None = None
_proxy_lock = threading.Lock()


def get_proxy() -> DnsProxy:
    global _proxy
    with _proxy_lock:
        if _proxy is None:
            from .config import Config

            _proxy = DnsProxy(
                port=Config.DNS_PORT,
                upstreams=tuple(Config.DNS_UPSTREAMS),
                timeout=Config.DNS_TIMEOUT,
            )
        return _proxy
