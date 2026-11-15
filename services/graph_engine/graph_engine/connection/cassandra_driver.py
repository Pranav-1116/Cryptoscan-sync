"""Cassandra cluster/session factory for the dependency-edge history store.

Optional — import/connect failures stay fail-open exactly like the Neo4j
driver: an unconfigured or unreachable Cassandra must never fabricate a
dependency timeline. PostgreSQL remains the authoritative record; this
connection only serves the rebuildable history projection.
"""

from __future__ import annotations

import logging
from typing import Any

from graph_engine.config.settings import get_graph_settings, reset_graph_settings

logger = logging.getLogger(__name__)

_cluster: Any = None
_session: Any = None
_failed: bool = False


def _import_cluster():
    from cassandra.cluster import Cluster  # type: ignore

    return Cluster


def create_cluster(contact_points: list[str], port: int, username: str = "", password: str = ""):
    Cluster = _import_cluster()
    kwargs: dict[str, Any] = {"port": port}
    if username:
        kwargs["auth_provider"] = _PlainTextAuthProvider(username, password)
    return Cluster(contact_points, **kwargs)


class _PlainTextAuthProvider:
    """Lazy PlainTextAuthProvider wrapper so auth stays optional."""

    def __init__(self, username: str, password: str) -> None:
        from cassandra.auth import PlainTextAuthProvider  # type: ignore

        self._provider = PlainTextAuthProvider(username=username, password=password)

    def new_authenticator(self, *args, **kwargs):  # pragma: no cover - driver hook
        return self._provider.new_authenticator(*args, **kwargs)


def get_session(*, force: bool = False):
    """Return a live session or None. Cached after the first successful connect."""
    global _cluster, _session, _failed
    if force:
        _cluster = None
        _session = None
        _failed = False
    if _session is not None:
        return _session
    if _failed and not force:
        return None
    settings = get_graph_settings()
    if not settings.cassandra_enabled:
        return None
    try:
        _cluster = create_cluster(
            settings.contact_points,
            settings.CASSANDRA_PORT,
            settings.CASSANDRA_USERNAME,
            settings.cassandra_password,
        )
        _session = _cluster.connect()
    except Exception:
        logger.debug("cassandra_connect_failed", exc_info=True)
        _failed = True
        _cluster = None
        _session = None
    return _session


def reset_session_cache() -> None:
    global _cluster, _session, _failed
    _cluster = None
    _session = None
    _failed = False
    reset_graph_settings()
