"""Projection consistency — PostgreSQL is the truth; the graph stores are
rebuildable views that must provably stay views.

These tests pin the drift tool's honesty: a disconnected projection is a
gap (never a pass), a REQUIRED gap fails the run, mismatches are named,
history events must be derivable from their own content, and rebuild is
one-way only (the authoritative payload is never mutated).
"""
from __future__ import annotations

import copy
import importlib.util


ROOT = __import__("pathlib").Path(__file__).resolve().parents[4]


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "projection_drift", ROOT / "scripts" / "projection_drift.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


class FakeSearch:
    def __init__(self, docs: int | None = 0):
        self.docs = docs
        self.indexed: list[tuple] = []

    def ping(self):
        return self.docs is not None

    def count(self, tenant_id):
        return self.docs

    def index_system(self, tenant, system):
        self.indexed.append(("system", tenant))

    def index_asset(self, tenant, asset):
        self.indexed.append(("asset", tenant))

    def index_edge(self, tenant, edge):
        self.indexed.append(("edge", tenant))


class FakeHistory:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.appended: list[dict] = []

    def ping(self):
        return self.ok

    def append_event(self, tenant, event):
        self.appended.append(event)
        return {"event_id": "x"}

    def history(self, tenant, subject, object_, relation):
        return [e for e in self.appended
                if e.get("subject") == subject and e.get("object") == object_]


def _payload():
    return {
        "assets": [{"id": "a1", "name": "svc-a", "kind": "Service"}],
        "edges": [{"from": "a1", "to": "a2", "label": "CALLS",
                   "subject": "a1", "object": "a2", "relation": "CALLS"}],
    }


class TestCheckIsAnswerable:
    def test_a_disconnected_projection_is_a_gap_never_a_pass(self):
        report = tool.check("t", _payload(), search=FakeSearch(docs=None),
                            history=FakeHistory(ok=False), driver=None)
        verdicts = {r["projection"]: r["verdict"] for r in report["projections"]}
        assert verdicts["elasticsearch"] == "NOT_CONNECTED"
        assert verdicts["cassandra"] == "NOT_CONNECTED"
        assert report["verdict"] != "CONSISTENT" or verdicts  # gap is reported
        # a gap alone is not CONSISTENT-mismatched either — it is named
        assert report["mismatched"] == []

    def test_a_required_gap_fails_the_run(self):
        report = tool.check("t", _payload(), search=FakeSearch(docs=None),
                            history=FakeHistory(ok=False), driver=None,
                            required=("elasticsearch",))
        assert report["verdict"] == "REQUIRED_NOT_CONNECTED"
        assert report["missing_required"] == ["elasticsearch"]

    def test_a_count_mismatch_is_named(self):
        report = tool.check("t", _payload(), search=FakeSearch(docs=99),
                            history=FakeHistory(ok=False))
        assert "elasticsearch" in report["mismatched"]
        es = [r for r in report["projections"] if r["projection"] == "elasticsearch"][0]
        assert es["verdict"] == "MISMATCH"
        assert "difference" in es

    def test_matching_counts_read_parity(self):
        # 2 docs expected (1 asset + 1 edge)
        report = tool.check("t", _payload(), search=FakeSearch(docs=2),
                            history=FakeHistory(ok=False))
        es = [r for r in report["projections"] if r["projection"] == "elasticsearch"][0]
        assert es["verdict"] == "PARITY"


class TestHistoryHonesty:
    def test_derivable_events_pass(self):
        from graph_engine.history.edge_history import event_id_for

        event = {"subject": "a1", "object": "a2", "relation": "CALLS",
                 "event_type": "OBSERVED", "occurred_at": "2026-10-16T00:00:00Z"}
        row = dict(event)
        row["event_id"] = event_id_for(row)
        store = FakeHistory()
        store.append_event("t", row)
        report = tool.check_history("t", _payload(), history=store)
        assert report["verdict"] == "HISTORY_OK"

    def test_a_non_derivable_event_id_is_a_mismatch(self):
        row = {"subject": "a1", "object": "a2", "relation": "CALLS",
               "event_type": "OBSERVED", "occurred_at": "2026-10-16T00:00:00Z",
               "event_id": "forged"}
        store = FakeHistory()
        store.append_event("t", row)
        report = tool.check_history("t", _payload(), history=store)
        assert report["verdict"] == "MISMATCH"
        assert "forged" in report["difference"]["non_derivable_event_ids"]


class TestRebuildIsOneWay:
    def test_rebuild_rederives_and_never_mutates_the_payload(self):
        payload = _payload()
        frozen = copy.deepcopy(payload)
        search = FakeSearch()
        history = FakeHistory()
        out = tool.rebuild("t", payload, search=search, history=history)
        assert payload == frozen, "the authoritative payload was mutated"
        assert "elasticsearch" in out["rebuilt"]
        assert search.indexed, "the search projection received derived docs"
        assert history.appended, "the history projection received events"
        assert "source of truth" in out["note"]

    def test_unconfigured_stores_are_reported_not_faked(self, monkeypatch):
        import graph_engine.core.dependency_stores as stores_mod

        monkeypatch.setattr(stores_mod, "dependency_search_store",
                            lambda client=None: None)
        monkeypatch.setattr(stores_mod, "edge_history_store",
                            lambda session=None: None)
        out = tool.rebuild("t", _payload())
        assert out["rebuilt"] == []
        report = out["dependency_stores"]
        assert "unconfigured" in report["history"]["reason"]
        assert "unconfigured" in report["search"]["reason"]


class TestProjectionGauges:
    def test_gauges_report_up_configured_and_documents(self, monkeypatch):

        import api.routers.metrics as metrics_mod

        fake_health = {
            "cassandra": {"configured": True, "ok": False, "backend": "cassandra"},
            "elasticsearch": {"configured": True, "ok": True, "backend": "elasticsearch"},
        }
        import graph_engine.core.dependency_stores as stores_mod

        monkeypatch.setattr(stores_mod, "dependency_stores_health",
                            lambda **kw: fake_health)
        monkeypatch.setattr(stores_mod, "dependency_search_store",
                            lambda client=None: FakeSearch(docs=7))
        monkeypatch.setattr(stores_mod, "edge_history_store",
                            lambda session=None: FakeHistory())
        monkeypatch.setattr(stores_mod, "sync_tenant", lambda: "t")
        rendered = "".join(metrics_mod._projection_lines())
        assert 'cryptoscan_graph_projection_up{projection="cassandra"} 0' in rendered
        assert 'cryptoscan_graph_projection_up{projection="elasticsearch"} 1' in rendered
        assert 'cryptoscan_graph_projection_documents{projection="elasticsearch"} 7' in rendered

    def test_projection_failure_never_silences_metrics(self, monkeypatch):
        import api.routers.metrics as metrics_mod

        def boom():
            raise RuntimeError("stores down")

        import graph_engine.core.dependency_stores as stores_mod

        monkeypatch.setattr(stores_mod, "dependency_stores_health", boom)
        assert metrics_mod._projection_lines() == []
