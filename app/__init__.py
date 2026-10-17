"""Flask application factory for the Parental Gateway."""

from __future__ import annotations

import atexit
import logging
import os

from flask import Flask, jsonify, request, url_for

from .config import Config
from .db import init_db, log_event
from .security import ensure_admin_user


def _configure_logging() -> None:
    level = getattr(logging, Config.LOG_LEVEL, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)-14s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("werkzeug").setLevel(max(level, logging.INFO))
    # scapy is chatty at INFO on some platforms
    logging.getLogger("scapy").setLevel(logging.WARNING)


def create_app(config_object=Config) -> Flask:
    _configure_logging()
    log = logging.getLogger("pg")

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_object)
    app.config["SESSION_COOKIE_NAME"] = Config.SESSION_COOKIE_NAME
    app.config["SESSION_COOKIE_HTTPONLY"] = Config.SESSION_COOKIE_HTTPONLY
    app.config["SESSION_COOKIE_SAMESITE"] = Config.SESSION_COOKIE_SAMESITE
    app.config["SESSION_COOKIE_SECURE"] = Config.SESSION_COOKIE_SECURE

    # Never cache the API or the dashboard shell. Static assets are served with
    # long-lived caching, but every reference is versioned with a content hash
    # (see the `asset` template helper) so a change is picked up immediately.
    @app.after_request
    def _no_cache(response):
        if request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif response.mimetype in ("text/html", "application/json"):
            response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response

    # ---- cache-busting asset URLs -------------------------------------
    # `{{ asset('css/app.css') }}` -> /static/css/app.css?v=<content hash>
    asset_versions: dict[str, str] = {}

    def _asset_version(filename: str) -> str:
        cached = asset_versions.get(filename)
        if cached is None:
            import hashlib

            try:
                with open(os.path.join(app.static_folder, filename), "rb") as handle:
                    cached = hashlib.sha256(handle.read()).hexdigest()[:10]
            except OSError:
                cached = "0"
            asset_versions[filename] = cached
        return cached

    @app.context_processor
    def _asset_helper():
        def asset(filename: str) -> str:
            return url_for("static", filename=filename, v=_asset_version(filename))

        return {"asset": asset}

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    # --- persistence -----------------------------------------------------
    init_db()
    ensure_admin_user()

    # --- blueprints ------------------------------------------------------
    from .routes.api import bp as api_bp
    from .routes.web import bp as web_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    # --- background workers ---------------------------------------------
    from . import gateway, scheduler

    try:
        summary = gateway.bootstrap()
        log.info("gateway bootstrap: %s", summary)
    except Exception:  # noqa: BLE001
        log.exception("gateway bootstrap failed")

    scheduler.start_scheduler()
    atexit.register(scheduler.stop_scheduler)

    log_event("Parental Gateway started", source="system")
    log.info(
        "ready - listening on %s:%s (firewall mode=%s)",
        Config.HOST,
        Config.PORT,
        Config.FIREWALL_MODE,
    )
    return app


def main() -> None:
    """Entry point used by ``python -m app``."""
    app = create_app()

    # Use a real WSGI server: no debug reloader (which would double-start the
    # background scheduler) and sane defaults for a LAN appliance.
    from waitress import serve

    serve(
        app,
        host=Config.HOST,
        port=Config.PORT,
        threads=int(os.environ.get("WEB_THREADS", "8")),
        ident="parental-gateway",
    )


if __name__ == "__main__":
    main()
