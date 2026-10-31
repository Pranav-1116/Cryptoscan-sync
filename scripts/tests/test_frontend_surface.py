"""Every console page is reachable from the router, or from another page.

The complement of the route contract: that one asks whether a page's backend path
exists, this asks whether the page itself can be opened. An orphan page is the
same failure from the operator's side — the code ships, the component is tested in
isolation, and there is no URL that renders it.

A page counts as reachable when `App.tsx` routes it (directly or through `lazy`)
**or** another page renders it as a section. The second case is real here:
`NotificationReceipts` is a page file that `Notifications.tsx` embeds rather than
routes, and calling it an orphan would be a false positive that teaches people to
ignore this test.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGES = ROOT / "frontend" / "src" / "pages"
APP = ROOT / "frontend" / "src" / "App.tsx"


def _page_files() -> set[str]:
    return {path.stem for path in PAGES.glob("*.tsx") if ".test." not in path.name and ".spec." not in path.name}


def _named_in(path: Path) -> set[str]:
    """Page module names this file imports, whether from `pages/` or from a page."""
    source = path.read_text(encoding="utf-8", errors="replace")
    # only relative modules: `from "react"` is a package, not a page
    found = set(re.findall(r'from\s+"\./(?:pages/)?([A-Za-z0-9_]+)(?:\.js)?"', source))
    found |= set(re.findall(r'import\("\./(?:pages/)?([A-Za-z0-9_]+)(?:\.js)?"\)', source))
    return found


def _graph() -> dict[str, set[str]]:
    """Page → the pages it imports, for every page file."""
    graph: dict[str, set[str]] = {}
    for page in PAGES.glob("*.tsx"):
        if ".test." in page.name or ".spec." in page.name:
            continue
        graph[page.stem] = _named_in(page) & _page_files()
    return graph


@pytest.fixture(scope="module")
def referenced() -> set[str]:
    """Pages reachable from the router, following page-to-page imports.

    Transitive on purpose: a page imported *only* by an orphan is not reachable
    either, and a one-hop check would call it fine.
    """
    graph = _graph()
    roots = _named_in(APP) & set(graph)
    seen: set[str] = set()
    queue = list(roots)
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        queue.extend(graph.get(name, set()) - seen)
    return seen


def test_there_are_pages_to_check():
    files = _page_files()
    assert len(files) >= 60, f"only {len(files)} page files found — did the directory move?"


def test_every_page_is_routed_or_embedded(referenced):
    files = _page_files()
    orphans = sorted(files - referenced)
    assert orphans == [], (
        "page files no router and no other page renders: the component ships and there is no URL "
        f"that opens it: {orphans}"
    )


def test_every_page_import_resolves_to_a_file(referenced):
    files = _page_files()
    missing = sorted(name for name in referenced if name not in files)
    assert missing == [], f"App.tsx imports pages that do not exist: {missing}"


def test_the_router_still_declares_paths():
    """A page can be imported and never routed; the two checks above would both pass."""
    source = APP.read_text(encoding="utf-8")
    paths = re.findall(r'path="([^"]+)"', source)
    concrete = [path for path in paths if "*" not in path]
    assert len(concrete) >= 40, f"only {len(concrete)} routed paths in App.tsx"
    # `*` is allowed twice: a nested catch-all inside a layout and the top-level one.
    duplicates = sorted({path for path in concrete if concrete.count(path) > 1})
    assert duplicates == [], f"the same path is routed twice in App.tsx: {duplicates}"
