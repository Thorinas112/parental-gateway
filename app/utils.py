"""Small shared helpers: MAC normalisation, time parsing, schedule maths."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timedelta
from typing import Iterable

MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
_HHMM_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")

DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


# --------------------------------------------------------------------------
# MAC addresses
# --------------------------------------------------------------------------
def norm_mac(value: str | None) -> str | None:
    """Normalise a MAC address to upper-case colon notation.

    Accepts ``aa:bb:cc:dd:ee:ff``, ``aa-bb-cc-dd-ee-ff`` and ``aabbccddeeff``.
    Returns ``None`` when the value is not a valid MAC.
    """
    if not value:
        return None
    raw = str(value).strip().lower().replace("-", ":").replace(".", "").replace(" ", "")
    if ":" not in raw:
        if len(raw) == 12 and re.fullmatch(r"[0-9a-f]{12}", raw):
            raw = ":".join(raw[i : i + 2] for i in range(0, 12, 2))
        else:
            return None
    parts = raw.split(":")
    if len(parts) != 6 or any(len(p) != 2 or not re.fullmatch(r"[0-9a-f]{2}", p) for p in parts):
        return None
    return ":".join(parts).upper()


def is_valid_mac(value: str | None) -> bool:
    return norm_mac(value) is not None


def short_mac(mac: str) -> str:
    """``AA:BB:CC:DD:EE:FF`` -> ``AABBCCDDEEFF`` (compact display token)."""
    return (mac or "").replace(":", "").upper()


# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------
def now_dt() -> datetime:
    return datetime.now()


def to_ts(value: datetime | None = None) -> int:
    return int((value or now_dt()).timestamp())


def from_ts(value: int | float | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value))
    except (OSError, OverflowError, ValueError):
        return None


def parse_hhmm(value: str | None) -> tuple[int, int] | None:
    if not value:
        return None
    match = _HHMM_RE.match(str(value).strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def format_hhmm(value: str | None) -> str:
    parsed = parse_hhmm(value)
    if not parsed:
        return "00:00"
    return f"{parsed[0]:02d}:{parsed[1]:02d}"


def parse_days(value) -> list[int]:
    """Normalise a days payload into a sorted list of ints 0..6 (Mon=0)."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            value = []
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        return []
    result: set[int] = set()
    for item in value:
        try:
            day = int(item)
        except (TypeError, ValueError):
            continue
        if 0 <= day <= 6:
            result.add(day)
    return sorted(result)


def days_to_json(days) -> str:
    return json.dumps(parse_days(days))


def schedule_active(
    days: Iterable[int],
    start: str,
    end: str,
    when: datetime | None = None,
) -> bool:
    """Return True when ``when`` falls inside a weekly recurring window.

    Supports windows that wrap past midnight (e.g. 21:00 -> 07:00): the rule
    applies if *today* is a selected day and we are after ``start``, or if
    *yesterday* was a selected day and we are still before ``end``.
    """
    when = when or now_dt()
    selected = set(parse_days(days))
    if not selected:
        return False

    start_t = parse_hhmm(start) or (0, 0)
    end_t = parse_hhmm(end) or (0, 0)
    minutes_now = when.hour * 60 + when.minute
    minutes_start = start_t[0] * 60 + start_t[1]
    minutes_end = end_t[0] * 60 + end_t[1]

    today = when.weekday()
    yesterday = (today - 1) % 7

    if minutes_start == minutes_end:
        return False  # zero-length window

    if minutes_start < minutes_end:
        return today in selected and minutes_start <= minutes_now < minutes_end

    # Wrapping window: spans midnight.
    after_start = today in selected and minutes_now >= minutes_start
    before_end = yesterday in selected and minutes_now < minutes_end
    return after_start or before_end


def humanise_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, _ = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h" if hours else f"{days}d"


# --------------------------------------------------------------------------
# Shell helpers
# --------------------------------------------------------------------------
def run_command(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    """Run a host command, never raising on a non-zero exit code."""
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(args, returncode=127, stdout="", stderr=str(exc))
