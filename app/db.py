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
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    last_ip     TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS pauses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT    NOT NULL CHECK (target_type IN ('device','group')),
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


def init_db() -> None:
    global _initialised
    with _lock:
        if _initialised:
            return
        conn = _connect()
        try:
            conn.executescript(SCHEMA)
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
