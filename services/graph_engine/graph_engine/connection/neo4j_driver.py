"""Official Neo4j driver factory. Optional — import/connect failures stay fail-open."""

from __future__ import annotations

import logging
from typing import Any

from graph_engine.config.settings import get_graph_settings, reset_graph_settings

logger = logging.getLogger(__name__)

_driver: Any = None
_failed: bool = False


def _import_graphdatabase():
    from neo4j import GraphDatabase  # type: ignore

    return GraphDatabase


def create_driver(uri: str, user: str, password: str):
    GraphDatabase = _import_graphdatabase()
    return GraphDatabase.driver(uri, auth=(user, password))


def get_driver(*, force: bool = False):
    """Return a live driver or None. Cached after the first successful connect."""
    global _driver, _failed
    if force:
        close_driver()
    if _driver is not None:
        return _driver
    if _failed and not force:
        return None
    settings = get_graph_settings()
    if not settings.enabled:
        return None
    try:
        driver = create_driver(settings.uri, *settings.auth)
        driver.verify_connectivity()
        _driver = driver
        _failed = False
        logger.info("neo4j_connected", extra={"uri": settings.uri})
        return _driver
    except Exception as exc:
        _failed = True
        logger.warning("neo4j_unavailable", extra={"uri": settings.uri, "error": str(exc)})
        if settings.NEO4J_REQUIRED:
            raise
        return None


def close_driver() -> None:
    global _driver, _failed
    if _driver is not None:
        try:
            _driver.close()
        except Exception:
            logger.debug("neo4j_close_failed", exc_info=True)
    _driver = None
    _failed = False


def reset_driver_state() -> None:
    close_driver()
    reset_graph_settings()
