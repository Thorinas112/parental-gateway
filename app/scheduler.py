"""Background workers.

A single daemon thread drives two periodic jobs:

  * ``reconcile`` - recompute + re-apply the firewall ruleset (fast, cheap)
  * ``scan``      - periodic LAN discovery (optional, off when interval = 0)
"""

from __future__ import annotations

import logging
import threading
import time

from .config import Config
from .db import log_event
from . import engine

log = logging.getLogger("pg.scheduler")

_thread: threading.Thread | None = None
_stop = threading.Event()
_started = False


def _loop() -> None:
    reconcile_every = max(5, Config.RECONCILE_INTERVAL_SECONDS)
    scan_every = max(0, Config.SCAN_INTERVAL_MINUTES) * 60
    usage_every = max(10, Config.USAGE_INTERVAL_SECONDS) if Config.USAGE_ENABLED else 0

    next_reconcile = 0.0
    next_scan = time.time() + 30.0 if scan_every else float("inf")
    next_usage = time.time() + 5.0 if usage_every else float("inf")

    log.info(
        "scheduler started (reconcile every %ss, scan every %ss, usage every %ss)",
        reconcile_every,
        scan_every or "disabled",
        usage_every or "disabled",
    )

    while not _stop.is_set():
        now = time.time()

        if now >= next_reconcile:
            next_reconcile = now + reconcile_every
            try:
                engine.reconcile()
            except Exception:  # noqa: BLE001 - the loop must survive errors
                log.exception("reconcile failed")

        if now >= next_scan:
            next_scan = now + scan_every
            try:
                from .scanner import scan_network

                scan_network()
            except Exception:  # noqa: BLE001
                log.exception("background scan failed")

        if now >= next_usage:
            next_usage = now + usage_every
            try:
                from . import usage

                usage.sample()
            except Exception:  # noqa: BLE001
                log.exception("usage sampling failed")

        _stop.wait(1.0)


def start_scheduler() -> None:
    global _thread, _started
    if _started:
        return
    _started = True
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="pg-scheduler", daemon=True)
    _thread.start()
    log.info("background scheduler thread launched")


def stop_scheduler() -> None:
    global _thread, _started
    if not _started:
        return
    _stop.set()
    if _thread and _thread.is_alive():
        _thread.join(timeout=5)
    _thread = None
    _started = False
    log.info("background scheduler stopped")


def run_scan_now() -> dict:
    """Trigger an immediate scan (used by the dashboard button)."""
    from .scanner import scan_network

    return scan_network()


def kick() -> None:
    """Force an immediate reconcile."""
    result = engine.reconcile(force=True)
    log_event("Firewall rules re-applied manually", source="firewall")
    return result
