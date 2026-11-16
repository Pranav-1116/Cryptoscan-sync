"""Cassandra + Elasticsearch dependency stores: resolvers, one-way sync, health.

PostgreSQL — the relational inventory — is the authoritative source of truth
for every asset and relationship record. Cassandra holds the append-only
dependency-edge timeline; Elasticsearch the dependency search projection.
Both are rebuilt from the authoritative payload: projection flows one way
(inventory -> stores), stores never write back, and every write is
tenant-stamped at one point, mirroring ``Neo4jGraphStore._sync_tenant``.

Tenant isolation is enforced by the query layer and authorization on both
stores — never assumed from Cassandra partition keys or index layout.
"""

from __future__ import annotations

import logging
from typing import Any

from graph_engine.config.settings import get_graph_settings
from graph_engine.connection.cassandra_driver import get_session as get_cassandra_session
from graph_engine.connection.elastic_driver import get_client as get_elastic_client
from graph_engine.history.edge_history import CassandraEdgeHistory
from graph_engine.search.dependency_search import ElasticDependencySearch

logger = logging.getLogger(__name__)


def sync_tenant() -> str:
    """The tenant this sync writes as ('platform' without a tenant plane)."""
    try:
        from db.tenancy import current_tenant

        return current_tenant() or "platform"
    except Exception:
        return "platform"


def edge_history_store(session: Any = None) -> CassandraEdgeHistory | None:
    """The Cassandra edge-history projection, or None when unconfigured."""
    handle = session if session is not None else get_cassandra_session()
    if handle is None:
        return None
    return CassandraEdgeHistory(handle, get_graph_settings().CASSANDRA_KEYSPACE)


def dependency_search_store(client: Any = None) -> ElasticDependencySearch | None:
    """The Elasticsearch dependency-search projection, or None when unconfigured."""
    handle = client if client is not None else get_elastic_client()
    if handle is None:
        return None
    return ElasticDependencySearch(handle, get_graph_settings().ELASTICSEARCH_INDEX)


def _edge_event(edge: dict[str, Any], *, tenant: str, now: Any) -> dict[str, Any]:
    """One append-only timeline event derived from an authoritative edge row."""
    event = {
        "subject": edge.get("subject") or edge.get("from") or edge.get("parent_id"),
        "object": edge.get("object") or edge.get("to") or edge.get("child_id"),
        "relation": edge.get("relation") or edge.get("label"),
        "event_type": "OBSERVED",
        "occurred_at": edge.get("observed_at") or edge.get("last_seen") or now,
    }
    for field in ("lifecycle_state", "lifecycle_revision", "lifecycle_reason",
                  "lifecycle_source", "lifecycle_evidence_ref", "detail"):
        if edge.get(field) is not None:
            event[field] = edge.get(field)
    return event


def sync_dependency_stores(
    payload: dict[str, Any],
    *,
    history: Any = None,
    search: Any = None,
    tenant_id: str | None = None,
    now: Any = None,
) -> dict[str, Any]:
    """Project the authoritative payload into both stores. One way only.

    The payload is never mutated (it is the authoritative side of the
    boundary); stores receive fresh derived documents. Edge identities come
    from the engine's canonical view — the same universe the Neo4j plane
    projects, derived USES edges included — so the three stores expose the
    same graph without holding duplicate authoritative records.

    Stores that are unconfigured or unreachable are reported, never faked.
    """
    from shared_models.relationship_lifecycle import clock, utc

    from graph_engine.core.engine import GraphEngine
    from graph_engine.history.edge_history import edge_key

    tenant = tenant_id or sync_tenant()
    when = now or clock()
    report: dict[str, Any] = {"tenant": tenant, "synced": False}

    history_store = history if history is not None else edge_history_store()
    search_store = search if search is not None else dependency_search_store()

    vis = GraphEngine().build(**payload).to_vis()
    observed: dict[str, Any] = {}
    for row in payload.get("edges") or []:
        key = edge_key(
            row.get("subject") or row.get("from") or row.get("parent_id"),
            row.get("relation") or row.get("label"),
            row.get("object") or row.get("to") or row.get("child_id"),
        )
        stamp = row.get("observed_at") or row.get("last_seen")
        if stamp:
            observed[key] = stamp

    if history_store is None:
        report["history"] = {"written": 0, "reason": "cassandra_unconfigured"}
    else:
        written = 0
        try:
            for edge in vis.get("edges") or []:
                event = _edge_event(edge, tenant=tenant, now=when)
                stamp = observed.get(edge_key(edge.get("from"), edge.get("label"), edge.get("to")))
                if stamp:
                    event["occurred_at"] = stamp
                history_store.append_event(tenant, event)
                written += 1
            report["history"] = {"written": written}
        except Exception as exc:
            logger.debug("edge_history_sync_failed", exc_info=True)
            report["history"] = {"written": written, "error": str(exc)}

    if search_store is None:
        report["search"] = {"reason": "elasticsearch_unconfigured"}
    else:
        counts = {"systems": 0, "assets": 0, "edges": 0}
        try:
            for system in payload.get("systems") or []:
                search_store.index_system(tenant, system)
                counts["systems"] += 1
            for asset in payload.get("assets") or []:
                search_store.index_asset(tenant, asset)
                counts["assets"] += 1
            for edge in vis.get("edges") or []:
                search_store.index_edge(tenant, edge)
                counts["edges"] += 1
            report["search"] = counts
            # Watermark: when this projection last synced and the newest
            # authoritative observation the payload carried — the pair a
            # lag gauge computes now - source_as_of from. Bookkeeping must
            # never fail the sync itself.
            newest_epoch: float | None = None
            newest_stamp: Any = None
            for stamp in observed.values():
                try:
                    epoch = stamp if isinstance(stamp, (int, float)) \
                        else utc(stamp).timestamp()
                except Exception:  # noqa: BLE001 - unparseable stamp, skip
                    continue
                if newest_epoch is None or epoch > newest_epoch:
                    newest_epoch = epoch
                    newest_stamp = stamp
            source_as_of = newest_stamp if newest_epoch is not None else when
            try:
                search_store.index_watermark(
                    tenant,
                    source_as_of=source_as_of,
                    synced_at=when,
                    counts=counts,
                )
                report["search"]["watermark"] = {
                    "source_as_of": str(source_as_of),
                    "synced_at": str(when),
                }
            except Exception as wm_exc:  # noqa: BLE001 - bookkeeping only
                logger.debug("projection_watermark_write_failed", exc_info=True)
                report["search"]["watermark"] = {
                    "error": type(wm_exc).__name__,
                }
        except Exception as exc:
            logger.debug("dependency_search_sync_failed", exc_info=True)
            report["search"] = {**counts, "error": str(exc)}

    history_report = report.get("history") or {}
    search_report = report.get("search") or {}
    report["synced"] = bool(
        history_report.get("written") or (
            search_report.get("edges") is not None and "error" not in search_report
        )
    )
    return report


def dependency_stores_health(*, history: Any = None, search: Any = None) -> dict[str, Any]:
    """Configured + reachable for both projections. Never faked."""
    settings = get_graph_settings()
    out: dict[str, Any] = {}
    history_store = history if history is not None else edge_history_store()
    search_store = search if search is not None else dependency_search_store()
    out["cassandra"] = {
        "configured": settings.cassandra_enabled or history is not None,
        "ok": bool(history_store is not None and history_store.ping()),
        "backend": "cassandra" if history_store is not None else "none",
        "required": settings.CASSANDRA_REQUIRED,
    }
    out["elasticsearch"] = {
        "configured": settings.elastic_enabled or search is not None,
        "ok": bool(search_store is not None and search_store.ping()),
        "backend": "elasticsearch" if search_store is not None else "none",
        "required": settings.ELASTICSEARCH_REQUIRED,
    }
    return out
