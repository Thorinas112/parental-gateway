"""Central configuration for the Parental Gateway application.

Every value can be overridden with an environment variable so the same image
works unchanged on Docker, LXC or bare metal.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


DATA_DIR = Path(os.environ.get("DATA_DIR") or (BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

SECRET_FILE = DATA_DIR / "secret.key"


def _load_secret_key() -> str:
    """Use SECRET_KEY if provided, otherwise persist a generated one.

    Persisting the generated key keeps users logged in across restarts.
    """
    env = os.environ.get("SECRET_KEY", "").strip()
    if env:
        return env
    try:
        if SECRET_FILE.exists():
            existing = SECRET_FILE.read_text(encoding="utf-8").strip()
            if existing:
                return existing
    except OSError:
        pass

    generated = secrets.token_hex(32)
    try:
        SECRET_FILE.write_text(generated, encoding="utf-8")
        try:
            os.chmod(SECRET_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        pass
    return generated


class Config:
    # --- application -----------------------------------------------------
    SECRET_KEY = _load_secret_key()
    DB_PATH = os.environ.get("DB_PATH") or str(DATA_DIR / "app.db")

    HOST = os.environ.get("HOST") or "0.0.0.0"
    PORT = _int(os.environ.get("WEB_PORT") or os.environ.get("PORT"), 8080)

    # --- sessions --------------------------------------------------------
    SESSION_COOKIE_NAME = "pg_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool(os.environ.get("SESSION_COOKIE_SECURE"), False)
    SESSION_TTL_HOURS = _int(os.environ.get("SESSION_TTL_HOURS"), 12)

    # --- bootstrap credentials ------------------------------------------
    # Leave ADMIN_PASSWORD empty to launch the first-run setup wizard, which
    # creates the administrator interactively. Set it to auto-provision an
    # account for unattended installs (CI, docker-compose automation).
    ADMIN_USERNAME = (os.environ.get("ADMIN_USERNAME") or "admin").strip()
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or ""

    # Force the setup wizard even when ADMIN_PASSWORD is provided.
    REQUIRE_SETUP_WIZARD = _bool(os.environ.get("REQUIRE_SETUP_WIZARD"), False)

    # A password this short is refused by the setup wizard.
    MIN_PASSWORD_LENGTH = _int(os.environ.get("MIN_PASSWORD_LENGTH"), 8)

    # --- networking ------------------------------------------------------
    LAN_IFACE = os.environ.get("LAN_IFACE") or "eth0"
    WAN_IFACE = os.environ.get("WAN_IFACE") or os.environ.get("LAN_IFACE") or "eth0"
    LAN_SUBNET = (os.environ.get("LAN_SUBNET") or "").strip()
    LAN_IP_CIDR = (os.environ.get("LAN_IP_CIDR") or "").strip()
    GATEWAY_MODE = _bool(os.environ.get("GATEWAY_MODE"), True)

    # --- behaviour -------------------------------------------------------
    SCAN_INTERVAL_MINUTES = _int(os.environ.get("SCAN_INTERVAL_MINUTES"), 10)
    RECONCILE_INTERVAL_SECONDS = max(5, _int(os.environ.get("RECONCILE_INTERVAL_SECONDS"), 20))
    ONLINE_WINDOW_MINUTES = _int(os.environ.get("ONLINE_WINDOW_MINUTES"), 5)

    # auto | force | off
    FIREWALL_MODE = (os.environ.get("FIREWALL_MODE") or "auto").strip().lower()
    FIREWALL_CHAIN = (os.environ.get("FIREWALL_CHAIN") or "PCTRL").strip() or "PCTRL"

    LOG_LEVEL = (os.environ.get("LOG_LEVEL") or "INFO").strip().upper()

    # --- security --------------------------------------------------------
    MAX_LOGIN_ATTEMPTS = _int(os.environ.get("MAX_LOGIN_ATTEMPTS"), 8)
    LOGIN_LOCKOUT_SECONDS = _int(os.environ.get("LOGIN_LOCKOUT_SECONDS"), 300)

    JSON_SORT_KEYS = False
