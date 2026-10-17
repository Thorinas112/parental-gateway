"""Render the project's Markdown documentation as styled HTML.

Two consumers share this single code path:

* the ``/docs`` routes in the web UI, and
* ``scripts/build_docs.py``, which writes standalone ``docs/*.html`` files.

Pages are cached against the source file's mtime, so editing a Markdown file
takes effect on the next request without restarting.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger("pg.docs")

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# Only these files are ever served. No user input reaches the filesystem.
PAGES: dict[str, dict[str, str]] = {
    "how-it-works": {
        "file": "docs/HOW_IT_WORKS.md",
        "output": "docs/HOW_IT_WORKS.html",
        "title": "How It Works",
        "tab": "How it works",
        "summary": "Architecture, policy engine, firewall and request lifecycle",
    },
    "deployment": {
        "file": "docs/DEPLOYMENT.md",
        "output": "docs/DEPLOYMENT.html",
        "title": "Deployment Guide",
        "tab": "Deployment",
        "summary": "Docker, Proxmox LXC, DHCP routing and hardening",
    },
    "readme": {
        "file": "README.md",
        "output": "docs/README.html",
        "title": "README",
        "tab": "Reference",
        "summary": "Features, configuration reference and API table",
    },
}

DEFAULT_PAGE = "how-it-works"

_EXTENSIONS = ["tables", "fenced_code", "toc", "sane_lists", "attr_list", "nl2br"]

_CACHE: dict[str, tuple[int, str]] = {}

# Inline brand mark so the page is self-contained (works via file:// too).
_ICON = (
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' "
    "fill='none' stroke='%236ee7b7' stroke-width='1.7' stroke-linecap='round' "
    "stroke-linejoin='round'%3E%3Cpath d='M12 2.5 4.5 6v5.6c0 4.6 3.1 8.5 7.5 9.9 "
    "4.4-1.4 7.5-5.3 7.5-9.9V6L12 2.5Z' fill='%230f172a'/%3E%3Cpath d='M9.2 12.1 "
    "11.3 14l3.6-3.9'/%3E%3C/svg%3E"
)

_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>__TITLE__ · Parental Gateway</title>
<link rel="icon" href="__ICON__" type="image/svg+xml">
<style>
__CSS__
</style>
</head>
<body class="docs-body">

<header class="docs-topbar">
  <span class="docs-brand"><span class="mark">
    <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
         stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 2.5 4.5 6v5.6c0 4.6 3.1 8.5 7.5 9.9 4.4-1.4 7.5-5.3 7.5-9.9V6L12 2.5Z"/>
      <path d="M9.2 12.1 11.3 14l3.6-3.9"/>
    </svg>
  </span>Parental Gateway</span>
  <nav class="docs-tabs">__TABS__</nav>
  <div class="spacer"></div>
  __BACK__
</header>

<div class="docs-layout">
  <aside class="docs-toc">
    <h4>On this page</h4>
    __TOC__
  </aside>
  <article class="docs-content">
__BODY__
  </article>
</div>

<footer class="docs-foot">
  __FOOT__
</footer>

</body>
</html>
"""


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------
def _load_source(slug: str) -> tuple[str, int] | None:
    meta = PAGES.get(slug)
    if not meta:
        return None
    path = ROOT / meta["file"]
    try:
        stat = path.stat()
    except OSError:
        log.warning("doc source missing: %s", path)
        return None
    try:
        return path.read_text(encoding="utf-8"), int(stat.st_mtime)
    except OSError:
        return None


def _style_toc(toc_html: str) -> str:
    """Tag each TOC entry with its nesting level so CSS can indent it."""
    if not toc_html.strip():
        return '<p class="toc-empty">No sections</p>'

    depth = 0
    parts: list[str] = []
    for token in re.split(r"(<ul>|</ul>)", toc_html):
        if token == "<ul>":
            depth += 1
            parts.append(token)
        elif token == "</ul>":
            depth = max(1, depth - 1)
            parts.append(token)
        else:
            parts.append(re.sub(r"<li>", f'<li class="toc-l{max(depth, 1)}">', token))
    return "".join(parts)


def render_markdown(text: str) -> tuple[str, str]:
    """Return ``(body_html, toc_html)`` for a Markdown document."""
    import markdown

    md = markdown.Markdown(extensions=_EXTENSIONS)
    body = md.convert(text)
    toc = _style_toc(md.toc)
    return body, toc


# --------------------------------------------------------------------------
# Page shell
# --------------------------------------------------------------------------
def _tabs(active: str) -> str:
    items = []
    for slug, meta in PAGES.items():
        cls = "docs-tab active" if slug == active else "docs-tab"
        items.append(f'<a class="{cls}" href="/docs/{slug}">{meta["tab"]}</a>')
    return "\n      ".join(items)


def _foot(standalone: bool) -> str:
    parts = ["<span>Parental Gateway documentation</span>"]
    for slug, meta in PAGES.items():
        name = Path(meta["output"]).name
        href = name if standalone else f"/docs/{slug}"
        parts.append(f'<a href="{href}">{meta["title"]}</a>')
    if not standalone:
        parts.append('<a href="/">Back to dashboard</a>')
    return "\n  ".join(parts)


def render_page(slug: str, standalone: bool = False) -> str | None:
    """Return the full HTML document for a doc page, or ``None`` if unknown."""
    source = _load_source(slug)
    if source is None:
        return None
    text, mtime = source

    cache_key = f"{slug}:{int(standalone)}:{mtime}"
    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached[1]

    body, toc = render_markdown(text)
    meta = PAGES[slug]

    try:
        css = (STATIC_DIR / "css" / "docs.css").read_text(encoding="utf-8")
    except OSError:
        css = "/* docs.css missing */"

    back = (
        ""
        if standalone
        else '<a class="docs-back" href="/">\n    <svg viewBox="0 0 24 24" width="15" height="15" fill="none"'
        ' stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg>Dashboard</a>'
    )

    html = (
        _SHELL.replace("__TITLE__", meta["title"])
        .replace("__ICON__", _ICON)
        .replace("__CSS__", css)
        .replace("__TABS__", _tabs(slug))
        .replace("__BACK__", back)
        .replace("__TOC__", toc)
        .replace("__BODY__", body)
        .replace("__FOOT__", _foot(standalone))
    )

    # Keep a couple of generations so an edit is picked up without leaking.
    if len(_CACHE) > 8:
        _CACHE.clear()
    _CACHE[cache_key] = (mtime, html)
    return html


def page_index() -> list[dict[str, Any]]:
    """Metadata for the doc index, including whether the source is present."""
    result = []
    for slug, meta in PAGES.items():
        path = ROOT / meta["file"]
        result.append(
            {
                "slug": slug,
                "title": meta["title"],
                "summary": meta["summary"],
                "available": path.exists(),
            }
        )
    return result
