"""SQLite persistence layer.

A single file database keeps deployment trivial (one volume, no sidecar) and
is more than enough for a home gateway. WAL mode plus a process-wide lock keeps
the web handlers and the background scheduler happy together.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator

from .config import Config

log = logging.getLogger("pg.db")

_lock = threading.RLock()
_initialised = False

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    last_login    INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT    PRIMARY KEY,
    csrf       TEXT    NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    color      TEXT    NOT NULL DEFAULT '#6366f1',
    blocked    INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT    PRIMARY KEY,
    ip          TEXT,
    hostname    TEXT,
    custom_name TEXT,
    group_id    INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    blocked     INTEGER NOT NULL DEFAULT 0,
    approved    INTEGER NOT NULL DEFAULT 1,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    last_ip     TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS pauses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT    NOT NULL CHECK (target_type IN ('device','group','all')),
    target_id   TEXT    NOT NULL,
    kind        TEXT    NOT NULL DEFAULT 'block' CHECK (kind IN ('block','allow')),
    label       TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pauses_expiry ON pauses(expires_at);

CREATE TABLE IF NOT EXISTS schedules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER REFERENCES groups(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL DEFAULT '',
    days_json  TEXT    NOT NULL DEFAULT '[]',
    start_time TEXT    NOT NULL DEFAULT '21:00',
    end_time   TEXT    NOT NULL DEFAULT '07:00',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_schedules_group ON schedules(group_id);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    level      TEXT    NOT NULL DEFAULT 'info',
    source     TEXT    NOT NULL DEFAULT 'system',
    message    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);

-- Traffic accounting -----------------------------------------------------
-- Raw samples are short-lived (detailed graphs); hourly and daily rollups
-- are accumulated incrementally so long ranges stay cheap to query.
CREATE TABLE IF NOT EXISTS usage_samples (
    id  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts  INTEGER NOT NULL,
    mac TEXT    NOT NULL,
    up  INTEGER NOT NULL DEFAULT 0,
    down INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_usage_samples_ts ON usage_samples(ts);
CREATE INDEX IF NOT EXISTS idx_usage_samples_mac ON usage_samples(mac, ts);

CREATE TABLE IF NOT EXISTS usage_hourly (
    mac     TEXT    NOT NULL,
    hour_ts INTEGER NOT NULL,
    up      INTEGER NOT NULL DEFAULT 0,
    down    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mac, hour_ts)
);
CREATE INDEX IF NOT EXISTS idx_usage_hourly_ts ON usage_hourly(hour_ts);

CREATE TABLE IF NOT EXISTS usage_daily (
    mac    TEXT    NOT NULL,
    day_ts INTEGER NOT NULL,
    up     INTEGER NOT NULL DEFAULT 0,
    down   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mac, day_ts)
);
CREATE INDEX IF NOT EXISTS idx_usage_daily_ts ON usage_daily(day_ts);

-- Web filtering ---------------------------------------------------------
-- group_id = 0 means the rule applies to every device; otherwise it applies
-- only to members of that group. Allow rules take precedence over block
-- rules of equal specificity, so you can whitelist a subdomain.
CREATE TABLE IF NOT EXISTS web_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER NOT NULL DEFAULT 0,
    pattern    TEXT    NOT NULL,
    action     TEXT    NOT NULL CHECK (action IN ('block','allow')),
    enabled    INTEGER NOT NULL DEFAULT 1,
    source     TEXT    NOT NULL DEFAULT 'custom',
    created_at INTEGER NOT NULL,
    UNIQUE (group_id, pattern, action)
);
CREATE INDEX IF NOT EXISTS idx_web_rules_group ON web_rules(group_id);

CREATE TABLE IF NOT EXISTS dns_queries (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    mac    TEXT,
    ip     TEXT,
    domain TEXT    NOT NULL,
    action TEXT    NOT NULL CHECK (action IN ('allowed','blocked')),
    reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_queries_ts ON dns_queries(ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(domain, ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_queries_action ON dns_queries(action, ts DESC);
"""


def _connect() -> sqlite3.Connection:
    path = Config.DB_PATH
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    """Context manager yielding a connection that commits on success."""
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring an older database up to the current schema.

    Both changes are additive and safe to re-run.
    """
    # 1. devices.approved - used to hold back newly discovered devices when
    #    "block unknown devices" is switched on.
    try:
        conn.execute("SELECT approved FROM devices LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE devices ADD COLUMN approved INTEGER NOT NULL DEFAULT 1")
        log.info("migrated: added devices.approved")

    # 2. SQLite cannot alter a CHECK constraint in place, so rebuild `pauses`
    #    when the definition predates target_type 'all' (master pause).
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pauses'"
    ).fetchone()
    definition = (row["sql"] if row else "") or ""
    if "'all'" not in definition:
        conn.execute("ALTER TABLE pauses RENAME TO _pauses_legacy")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pauses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT    NOT NULL CHECK (target_type IN ('device','group','all')),
                target_id   TEXT    NOT NULL,
                kind        TEXT    NOT NULL DEFAULT 'block' CHECK (kind IN ('block','allow')),
                label       TEXT,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pauses_expiry ON pauses(expires_at)")
        conn.execute(
            "INSERT INTO pauses (id, target_type, target_id, kind, label, created_at, expires_at) "
            "SELECT id, target_type, target_id, kind, label, created_at, expires_at FROM _pauses_legacy"
        )
        conn.execute("DROP TABLE _pauses_legacy")
        log.info("migrated: rebuilt pauses to allow target_type='all'")


def init_db() -> None:
    global _initialised
    with _lock:
        if _initialised:
            return
        conn = _connect()
        try:
            conn.executescript(SCHEMA)
            _migrate(conn)
            conn.commit()
        finally:
            conn.close()
        _initialised = True
        log.info("database ready at %s", Config.DB_PATH)


# --------------------------------------------------------------------------
# Generic query helpers
# --------------------------------------------------------------------------
def rows(sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
    with db() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def one(sql: str, params: tuple | dict = ()) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None


def execute(sql: str, params: tuple | dict = ()) -> int:
    """Execute a statement, returning ``cursor.lastrowid``."""
    with db() as conn:
        cur = conn.execute(sql, params)
        return int(cur.lastrowid or 0)


def executemany(sql: str, seq: list[tuple]) -> None:
    with db() as conn:
        conn.executemany(sql, seq)


# --------------------------------------------------------------------------
# Event log (shown in the dashboard's activity panel)
# --------------------------------------------------------------------------
def log_event(message: str, level: str = "info", source: str = "system") -> None:
    from .utils import to_ts

    try:
        execute(
            "INSERT INTO events (created_at, level, source, message) VALUES (?, ?, ?, ?)",
            (to_ts(), level, source, message),
        )
    except Exception:  # pragma: no cover - logging must never break the app
        log.debug("could not persist event", exc_info=True)


def recent_events(limit: int = 40) -> list[dict[str, Any]]:
    return rows("SELECT * FROM events ORDER BY created_at DESC, id DESC LIMIT ?", (int(limit),))
