"""Bolt connectivity probe."""

from __future__ import annotations

from typing import Any

from graph_engine.config.settings import get_graph_settings
from graph_engine.connection.neo4j_driver import get_driver
from graph_engine.queries.reachability import PING


def probe_neo4j(driver=None) -> dict[str, Any]:
    settings = get_graph_settings()
    payload = {
        "configured": settings.enabled,
        "uri": settings.uri or None,
        "database": settings.NEO4J_DATABASE,
        "ok": False,
        "backend": "memory",
        "error": None,
    }
    handle = driver if driver is not None else get_driver()
    if handle is None:
        payload["error"] = "neo4j_not_configured" if not settings.enabled else "neo4j_unreachable"
        return payload
    try:
        with handle.session(database=settings.NEO4J_DATABASE) as session:
            record = session.run(PING).single()
            payload["ok"] = bool(record and (record.get("ok") == 1 or record["ok"] == 1))
            payload["backend"] = "neo4j" if payload["ok"] else "memory"
    except Exception as exc:
        payload["error"] = str(exc)
        payload["backend"] = "memory"
    return payload
