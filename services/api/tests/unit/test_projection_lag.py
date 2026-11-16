"""Projection lag: a gauge backed by a watermark, never by hope.

The 50k-asset scale receipt recorded projection lag from row-count
deltas because no ``projection_lag_seconds`` gauge existed. This file pins
the build-side fix: every successful search-projection sync writes a
watermark (newest authoritative observation + sync time) that the metrics
surface turns into ``cryptoscan_graph_projection_lag_seconds``. Absent —
never a fabricated zero — before the first sync.
"""

from __future__ import annotations

import time

from graph_engine.core.dependency_stores import sync_dependency_stores
from graph_engine.search.dependency_search import ElasticDependencySearch
from graph_engine.testing.fake_elastic import FakeElasticClient


def _search() -> ElasticDependencySearch:
    store = ElasticDependencySearch(FakeElasticClient())
    store.apply_schema()
    return store


def _payload_with_stamps() -> dict:
    return {
        "systems": [{"id": "payments-api", "name": "Payments API"}],
        "assets": [],
        "edges": [
            {"parent_id": "payments-api", "child_id": "ledger-db",
             "relation": "CALLS", "observed_at": "2026-10-16T10:00:00+00:00"},
            {"parent_id": "payments-api", "child_id": "fraud-svc",
             "relation": "CALLS", "last_seen": "2026-10-16T10:05:00+00:00"},
        ],
    }


def test_sync_watermark_carries_the_newest_observation_stamp():
    search = _search()
    report = sync_dependency_stores(
        _payload_with_stamps(), history=None, search=search,
        tenant_id="t1", now="2026-10-16T10:06:00+00:00")

    watermark = search.read_watermark("t1")
    assert watermark is not None
    assert watermark["kind"] == "watermark"
    # The newest stamp in the payload (10:05) — not the sync clock (10:06).
    from datetime import datetime, timezone
    expected = datetime(2026, 10, 16, 10, 5, tzinfo=timezone.utc).timestamp()
    assert abs(watermark["source_as_of_epoch"] - expected) < 1.0
    assert report["search"]["watermark"]["source_as_of"].startswith("2026-10-16T10:05")


def test_unstamped_payload_falls_back_to_sync_time():
    search = _search()
    sync_dependency_stores(
        {"systems": [], "assets": [], "edges": []},
        history=None, search=search, tenant_id="t1",
        now="2026-10-16T10:06:00+00:00")
    watermark = search.read_watermark("t1")
    from datetime import datetime, timezone
    expected = datetime(2026, 10, 16, 10, 6, tzinfo=timezone.utc).timestamp()
    assert abs(watermark["source_as_of_epoch"] - expected) < 1.0


def test_watermark_is_bookkeeping_not_content():
    search = _search()
    sync_dependency_stores(
        _payload_with_stamps(), history=None, search=search, tenant_id="t1",
        now="2026-10-16T10:06:00+00:00")
    # The watermark never inflates the document gauge or leaks into search.
    # Content docs: one system + two edges.
    assert search.count("t1") == 3
    hits = search.search("t1", "")["hits"]
    assert hits and all(row.get("kind") != "watermark" for row in hits)
    assert search.read_watermark("other-tenant") is None


def test_metrics_expose_projection_lag_seconds(monkeypatch):
    import api.routers.metrics as metrics_mod

    search = _search()
    search.index_watermark(
        "t1",
        source_as_of=time.time() - 90.0,
        synced_at=time.time(),
        counts={"systems": 1, "assets": 0, "edges": 2},
    )
    import graph_engine.core.dependency_stores as stores_mod
    monkeypatch.setattr(
        stores_mod, "dependency_search_store", lambda client=None: search)
    monkeypatch.setattr(stores_mod, "sync_tenant", lambda: "t1")
    monkeypatch.setattr(
        stores_mod, "dependency_stores_health",
        lambda **kw: {
            "cassandra": {"ok": False, "configured": False},
            "elasticsearch": {"ok": True, "configured": True},
        })

    rendered = "".join(metrics_mod._projection_lines())
    assert 'cryptoscan_graph_projection_lag_seconds{projection="elasticsearch"}' in rendered
    lag = float(rendered.split(
        'cryptoscan_graph_projection_lag_seconds{projection="elasticsearch"} '
    )[1].split("\n")[0])
    assert 85.0 <= lag < 95.0


def test_metrics_lag_gauge_absent_before_first_sync(monkeypatch):
    import api.routers.metrics as metrics_mod

    search = _search()
    import graph_engine.core.dependency_stores as stores_mod
    monkeypatch.setattr(
        stores_mod, "dependency_search_store", lambda client=None: search)
    monkeypatch.setattr(stores_mod, "sync_tenant", lambda: "t1")
    monkeypatch.setattr(
        stores_mod, "dependency_stores_health",
        lambda **kw: {
            "cassandra": {"ok": False, "configured": False},
            "elasticsearch": {"ok": True, "configured": True},
        })

    rendered = "".join(metrics_mod._projection_lines())
    assert "cryptoscan_graph_projection_documents" in rendered
    assert "cryptoscan_graph_projection_lag_seconds" not in rendered


def test_watermark_failure_never_fails_the_sync():
    class ExplodingWatermark(ElasticDependencySearch):
        def index_watermark(self, tenant_id, **kwargs):
            raise RuntimeError("watermark write down")

    search = ExplodingWatermark(FakeElasticClient())
    search.apply_schema()
    report = sync_dependency_stores(
        _payload_with_stamps(), history=None, search=search, tenant_id="t1",
        now="2026-10-16T10:06:00+00:00")
    assert report["synced"] is True
    assert report["search"]["edges"] == 2
    assert report["search"]["watermark"]["error"] == "RuntimeError"
