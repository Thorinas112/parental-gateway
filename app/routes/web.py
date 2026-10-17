"""HTML routes: first-run setup, login, dashboard and the documentation."""

from __future__ import annotations

from flask import Blueprint, abort, redirect, render_template, url_for

from ..docs import DEFAULT_PAGE, render_page
from ..security import current_token, get_session, setup_required

bp = Blueprint("web", __name__)


@bp.get("/setup")
def setup_page():
    if not setup_required():
        return redirect(url_for("web.dashboard"))
    return render_template("setup.html")


@bp.get("/login")
def login_page():
    if setup_required():
        return redirect(url_for("web.setup_page"))
    if get_session(current_token()):
        return redirect(url_for("web.dashboard"))
    return render_template("login.html")


@bp.get("/")
def dashboard():
    if setup_required():
        return redirect(url_for("web.setup_page"))
    if not get_session(current_token()):
        return redirect(url_for("web.login_page"))
    return render_template("dashboard.html")


@bp.get("/logout")
def logout_page():
    return redirect(url_for("web.login_page"))


# --------------------------------------------------------------------------
# Documentation
#
# Deliberately unauthenticated: the pages are the project's own static docs and
# contain no user data. Being able to read the deployment guide *during* the
# setup wizard (before any account exists) is the whole point.
# --------------------------------------------------------------------------
@bp.get("/docs")
def docs_index():
    return redirect(url_for("web.doc_page", slug=DEFAULT_PAGE))


@bp.get("/docs/<slug>")
def doc_page(slug: str):
    html = render_page(slug)
    if html is None:
        abort(404)
    return html
