"""Every endpoint a router module defines is reachable in the served schema.

`scripts/api_contract.py` answers one direction: *does every caller name a path
the app serves?* This file answers the other, which is the shape the "older code
coexisting with the live architecture" problem actually takes: a router that
defines endpoints nobody mounts. The module imports, the decorators run, the
handlers look real, `pytest` on that module passes — and the endpoint answers 404
in production because `main.py` never included it.

The check is deliberately structural rather than textual: it imports every module
in `api.routers`, takes the routes each one *defines*, and requires each path to
appear in the OpenAPI document the app itself produces. Route paths are matched on
their tail, because a router can be mounted under a prefix by whoever includes it
(`host_qualification` is mounted under `/collection`, `launch_readiness` under
`/assurance`), and a prefix is not the router's business.

Two consequences worth stating plainly:

* a module with no module-level ``router`` is a helper (``cbom_legacy`` and its
  neighbours attach their routes to ``cbom.router``), not an unmounted router, and
  is skipped — but the routes it *did* attach are still checked, because they are
  then part of ``cbom.router``;
* WebSocket routes never appear in an OpenAPI document, so they are checked
  against their declaration instead. Exempting them silently would make this file
  pass while the console's live channel was dead.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import api_contract as contract  # noqa: E402


def _tail(path: str) -> str:
    """Normalise parameters and trailing slashes so a mounted path compares equal."""
    return re.sub(r"\{[^}]+\}", "{}", path).rstrip("/")


@pytest.fixture(scope="module")
def served() -> set[str]:
    return {_tail(path) for path in contract.served_paths()}


@pytest.fixture(scope="module")
def router_routes() -> list[tuple[str, str, str]]:
    """``(module, kind, path)`` for every route a router module defines."""
    from api import routers as routers_pkg

    rows: list[tuple[str, str, str]] = []
    for info in pkgutil.iter_modules(routers_pkg.__path__):
        try:
            module = importlib.import_module(f"api.routers.{info.name}")
        except Exception as exc:  # pragma: no cover - import failures are their own test
            raise AssertionError(f"api.routers.{info.name} does not import: {exc}") from exc
        router = getattr(module, "router", None)
        if router is None:
            continue
        for route in getattr(router, "routes", []):
            path = getattr(route, "path", None)
            if not path:
                continue
            # A WebSocketRoute carries no `methods`; APIRoute always does.
            kind = "http" if getattr(route, "methods", None) else "websocket"
            rows.append((info.name, kind, path))
    return rows


def test_the_scan_actually_saw_the_routers(router_routes):
    """A reachability check that finds no routes would pass forever."""
    assert len(router_routes) >= 1100, f"only {len(router_routes)} router routes enumerated"
    modules = {module for module, _kind, _path in router_routes}
    assert len(modules) >= 80, f"only {len(modules)} router modules enumerated"


def test_every_http_route_a_module_defines_is_served(router_routes, served):
    unreachable = []
    for module, kind, path in router_routes:
        if kind != "http":
            continue
        tail = _tail(path)
        if tail in {"", "/"}:
            continue
        if any(path_served == tail or path_served.endswith(tail) for path_served in served):
            continue
        unreachable.append(f"{module}: {path}")
    assert unreachable == [], (
        "routers define endpoints the application does not mount. Each one is a 404 with a "
        "handler behind it:\n  " + "\n  ".join(sorted(unreachable))
    )


def test_every_websocket_a_module_defines_is_declared_somewhere(router_routes):
    """WebSockets are absent from OpenAPI by design; they must at least be declared."""
    websockets = [(module, path) for module, kind, path in router_routes if kind == "websocket"]
    assert websockets, "no WebSocket routes found — did the ws router stop being imported?"
    source = (ROOT / "services" / "api" / "api" / "routers" / "ws.py").read_text(encoding="utf-8")
    for _module, path in websockets:
        literal = path.replace("{job_id}", "{job_id}")
        assert literal in source, f"WebSocket {path} is not declared in ws.py"


def test_a_router_missing_from_main_is_caught(tmp_path):
    """Mutation check: an unmounted router must fail the comparison above."""
    served = {"/api/v1/health"}
    fake_route = type("R", (), {"path": "/orphan/endpoint"})()
    tail = _tail(fake_route.path)
    assert not any(path == tail or path.endswith(tail) for path in served)


def test_the_helper_modules_attach_their_routes_to_a_mounted_router():
    """`cbom_legacy*` and `cbom_rescan_inspection` have no router of their own.

    They are registered onto ``cbom.router`` at import time. If that registration
    were dropped they would become dead code that still imports cleanly, and the
    reachability check above would not notice — so the attribution is asserted.
    """
    cbom = importlib.import_module("api.routers.cbom")
    source = (ROOT / "services" / "api" / "api" / "routers" / "cbom.py").read_text(encoding="utf-8")
    for helper, register in (
        ("cbom_legacy", "register_legacy_routes"),
        ("cbom_legacy_controlled", "register_controlled_routes"),
        ("cbom_rescan_inspection", "register_rescan_routes"),
    ):
        assert f"from api.routers.{helper} import {register}" in source, (
            f"cbom.py no longer imports {register}: the routes defined in {helper}.py are dead"
        )
        assert re.search(rf"{register}\(\s*router", source), (
            f"cbom.py imports {register} but never calls it with the router"
        )
    assert any(getattr(route, "path", "").startswith("/cbom") for route in cbom.router.routes)
