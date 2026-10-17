"""Render the Markdown docs to standalone, self-contained HTML files.

The output is fully offline - CSS and icons are inlined - so the files can be
double-clicked from a file manager or emailed to someone.

    python scripts/build_docs.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.docs import PAGES, render_page  # noqa: E402


def main() -> int:
    print("== Parental Gateway - documentation build ==")
    failed = 0

    for slug, meta in PAGES.items():
        source = ROOT / meta["file"]
        if not source.exists():
            print(f"  SKIP {meta['title']:<20} (source missing: {meta['file']})")
            failed += 1
            continue

        html = render_page(slug, standalone=True)
        if not html:
            print(f"  FAIL {meta['title']:<20} (render failed)")
            failed += 1
            continue

        out = ROOT / meta["output"]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        size_kb = out.stat().st_size / 1024
        print(f"  ok   {meta['title']:<20} -> {out.relative_to(ROOT)}  ({size_kb:.1f} KB)")

    total = len(PAGES)
    print(f"\n== {total - failed} of {total} document(s) written ==")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
