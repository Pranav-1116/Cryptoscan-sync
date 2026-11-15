"""Elasticsearch client factory for the dependency search store.

Optional — import/connect failures stay fail-open exactly like the Neo4j and
Cassandra factories: an unconfigured or unreachable Elasticsearch must never
fabricate dependency search results. PostgreSQL remains the authoritative
record; this connection only serves the rebuildable search projection.
"""

from __future__ import annotations

import logging
from typing import Any

from graph_engine.config.settings import get_graph_settings, reset_graph_settings

logger = logging.getLogger(__name__)

_client: Any = None
_failed: bool = False


def _import_elasticsearch():
    from elasticsearch import Elasticsearch  # type: ignore

    return Elasticsearch


def create_client(url: str, username: str = "", password: str = ""):
    Elasticsearch = _import_elasticsearch()
    if username:
        return Elasticsearch(url, basic_auth=(username, password), request_timeout=5)
    return Elasticsearch(url, request_timeout=5)


def get_client(*, force: bool = False):
    """Return a pinged client or None. Cached after the first success."""
    global _client, _failed
    if force:
        _client = None
        _failed = False
    if _client is not None:
        return _client
    if _failed and not force:
        return None
    settings = get_graph_settings()
    if not settings.elastic_enabled:
        return None
    try:
        client = create_client(
            settings.ELASTICSEARCH_URL.strip(),
            settings.ELASTICSEARCH_USERNAME,
            settings.elastic_password,
        )
        if client.ping():
            _client = client
        else:
            _failed = True
    except Exception:
        logger.debug("elasticsearch_connect_failed", exc_info=True)
        _failed = True
        _client = None
    return _client


def reset_client_cache() -> None:
    global _client, _failed
    _client = None
    _failed = False
    reset_graph_settings()
