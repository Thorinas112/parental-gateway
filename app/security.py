"""Authentication: users, session tokens, CSRF and login throttling."""

from __future__ import annotations

import functools
import logging
import secrets
import threading
import time
from typing import Any, Callable

from flask import g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from .config import Config
from .db import db, one
from .utils import to_ts

log = logging.getLogger("pg.auth")

SESSION_COOKIE = Config.SESSION_COOKIE_NAME

_attempts: dict[str, dict[str, Any]] = {}
_attempts_lock = threading.Lock()


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------
def create_user(username: str, password: str) -> int:
    username = (username or "").strip()
    if not username or not password:
        raise ValueError("username and password are required")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), to_ts()),
        )
        return int(cur.lastrowid or 0)


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    username = (username or "").strip()
    user = one("SELECT * FROM users WHERE username = ?", (username,))
    if not user:
        # Constant-ish work factor to avoid trivially revealing missing users.
        generate_password_hash(password or "x")
        return None
    if not check_password_hash(user["password_hash"], password or ""):
        return None
    return user


def count_users() -> int:
    row = one("SELECT COUNT(*) AS n FROM users")
    return int(row["n"]) if row else 0


def setup_required() -> bool:
    """True while no administrator account exists yet.

    The first-run wizard is the only thing allowed to run in this state, so a
    brand-new install can never be left with a guessable default password.
    """
    return count_users() == 0


def set_user_password(user_id: int, password: str) -> None:
    if not password:
        raise ValueError("password is required")
    with db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(password), int(user_id)),
        )


def ensure_admin_user() -> None:
    """Provision the bootstrap administrator for unattended installs.

    When ``ADMIN_PASSWORD`` is unset the application is left with no users,
    which makes ``setup_required()`` return True and launches the first-run
    setup wizard instead of creating a guessable default account.
    """
    from .db import one as _one

    existing = _one("SELECT * FROM users WHERE username = ?", (Config.ADMIN_USERNAME,))
    if not existing:
        password = Config.ADMIN_PASSWORD
        # Treat the old documented placeholder as "not configured" so legacy
        # .env files get the wizard rather than a publicly known password.
        if Config.REQUIRE_SETUP_WIZARD or not password or password == "change-me-please":
            log.info("no administrator configured - first-run setup wizard enabled")
            return
        create_user(Config.ADMIN_USERNAME, password)
        log.info("created bootstrap user %r from environment", Config.ADMIN_USERNAME)
        return

    # If the operator rotated ADMIN_PASSWORD in the environment, honour it.
    if Config.ADMIN_PASSWORD and Config.ADMIN_PASSWORD != "change-me-please":
        if not check_password_hash(existing["password_hash"], Config.ADMIN_PASSWORD):
            with db() as conn:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(Config.ADMIN_PASSWORD), existing["id"]),
                )
            log.info("password for %r updated from environment", Config.ADMIN_USERNAME)


# --------------------------------------------------------------------------
# Login throttling
# --------------------------------------------------------------------------
def _client_key() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def throttled() -> bool:
    key = _client_key()
    now = time.time()
    with _attempts_lock:
        entry = _attempts.get(key)
        if not entry:
            return False
        if now - entry["first"] > Config.LOGIN_LOCKOUT_SECONDS:
            _attempts.pop(key, None)
            return False
        return entry["count"] >= Config.MAX_LOGIN_ATTEMPTS


def record_failure() -> None:
    key = _client_key()
    now = time.time()
    with _attempts_lock:
        entry = _attempts.get(key)
        if not entry or now - entry["first"] > Config.LOGIN_LOCKOUT_SECONDS:
            _attempts[key] = {"first": now, "count": 1}
        else:
            entry["count"] += 1


def record_success() -> None:
    with _attempts_lock:
        _attempts.pop(_client_key(), None)


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------
def create_session(user_id: int) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = to_ts()
    expires = now + Config.SESSION_TTL_HOURS * 3600
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, csrf, user_id, created_at, expires_at, ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                token,
                csrf,
                user_id,
                now,
                expires,
                request.remote_addr if request else None,
                (request.headers.get("User-Agent", "")[:200] if request else None),
            ),
        )
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))
    return {"token": token, "csrf": csrf, "expires_at": expires}


def get_session(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    now = to_ts()
    row = one(
        "SELECT s.*, u.username FROM sessions s "
        "JOIN users u ON u.id = s.user_id "
        "WHERE s.token = ? AND s.expires_at > ?",
        (token, now),
    )
    return row


def destroy_session(token: str | None) -> None:
    if not token:
        return
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def purge_expired_sessions() -> None:
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (to_ts(),))


def current_token() -> str | None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        return token
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


# --------------------------------------------------------------------------
# Request decorators
# --------------------------------------------------------------------------
def api_auth(fn: Callable):
    """Require a valid session and (for mutations) a matching CSRF token.

    While the install is unconfigured every protected endpoint is refused so
    the first-run setup wizard is the only reachable surface.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if setup_required():
            return jsonify({"error": "setup required", "setup_required": True}), 428

        token = current_token()
        session = get_session(token)
        if not session:
            return jsonify({"error": "unauthenticated"}), 401

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            supplied = request.headers.get("X-CSRF-Token", "")
            if not supplied or not secrets.compare_digest(supplied, session["csrf"] or ""):
                return jsonify({"error": "csrf token missing or invalid"}), 403

        g.session = session
        g.user = {"id": session["user_id"], "username": session["username"]}
        g.csrf = session["csrf"]
        return fn(*args, **kwargs)

    return wrapper
