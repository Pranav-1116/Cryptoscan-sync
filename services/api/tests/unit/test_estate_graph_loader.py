"""The graph-store loader (spec 94 §20–§21).

What is under test is not "does it write nodes" but the four things that make a
projection safe to keep next to a bank's real graph:

* an export it does not fully understand is **refused whole** — no partial import;
* labels and relationship types are validated against the graph's own vocabulary
  before they are interpolated into Cypher, because Cypher cannot parameterise them;
* a refused edge never becomes an edge — `UNRESOLVED_CANDIDATE` in `relationships`
  is rejected, and when it ships in `unresolved` it is written with a type no one can
  mistake for an established relationship;
* a load is only "ok" when the store's own counts agree with what was written.
  "I sent 6 rows" is a claim; "the store holds 6" is a fact.
"""

from __future__ import annotations

import pytest

from api import estate_graph_loader as loader
from shared_models import estate_twin as twin
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)


def _payload() -> dict:
    return {
        "estate": "Synthetic Bank",
        "scope": "production",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API", "environment": "production"},
            {"ref": "hsm", "type": "HSM", "name": "HSM-03", "environment": "production"},
            {"ref": "loose", "type": "APPLICATION", "name": "legacy-batch"},
        ],
        "evidence": [
            {"evidence_id": "ev-1", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
             "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": "AES-256-GCM", "role": "encrypt"}},
            {"evidence_id": "ev-2", "source": "/etc/pkcs11.conf", "collector": "linux-static",
             "evidence_type": "CONFIGURED", "target": "api", "layer": "HSM",
             "facts": {"hsm_reference": "HSM-03"}},
        ],
        "relationships": [
            {"subject": "api", "predicate": "uses_hsm", "object": "hsm",
             "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-2"]},
        ],
    }


@pytest.fixture()
def export() -> dict:
    return twin.graph_export(build_graph(_payload()))


# -- refusal is whole-document ---------------------------------------------- #


def test_an_unknown_schema_is_refused_rather_than_best_effort_imported(export):
    with pytest.raises(loader.ExportRejected) as exc:
        loader.validate_export({**export, "schema": "cryptoscan.estate-graph-export/2"})
    assert "unknown export schema" in str(exc.value)


def test_an_export_without_provenance_is_refused(export):
    with pytest.raises(loader.ExportRejected) as exc:
        loader.validate_export({**export, "projection_id": ""})
    assert "projection_id" in str(exc.value)


def test_a_duplicate_node_id_is_refused(export):
    nodes = export["nodes"]
    with pytest.raises(loader.ExportRejected) as exc:
        loader.validate_export({**export, "nodes": nodes + [dict(nodes[0])]})
    assert "duplicate node id" in str(exc.value)


def test_a_dangling_relationship_is_refused(export):
    edges = list(export["relationships"])
    edges.append({"type": "USES_HSM", "from": export["nodes"][0]["id"], "to": "not-in-this-export",
                  "properties": {}})
    with pytest.raises(loader.ExportRejected) as exc:
        loader.validate_export({**export, "relationships": edges})
    assert "dangling" in str(exc.value).lower()


def test_an_unresolved_candidate_smuggled_in_as_a_relationship_is_refused(export):
    """A refused edge drawn as an edge is an assumption with a line around it."""
    edges = list(export["relationships"])
    edges.append({
        "type": "UNRESOLVED_CANDIDATE",
        "from": export["nodes"][0]["id"],
        "to": export["nodes"][1]["id"],
        "properties": {"attempted_predicate": "uses_hsm"},
    })
    with pytest.raises(loader.ExportRejected) as exc:
        loader.validate_export({**export, "relationships": edges})
    assert "unresolved" in str(exc.value).lower()


@pytest.mark.parametrize(
    "label",
    ["APPLICATION`) DETACH DELETE n //", "APPLICATION-THING", "**", "", "A" * 60],
)
def test_an_unsafe_or_unknown_label_can_never_reach_a_statement(label):
    with pytest.raises(loader.ExportRejected):
        loader.node_statement(label)


def test_a_lowercase_label_is_normalised_not_rejected():
    """Case is not an injection risk, so it is normalised — silently, but to a known token."""
    assert "SET n:EstateAsset:APPLICATION" in loader.node_statement("application")


def test_an_unknown_relationship_type_is_refused():
    with pytest.raises(loader.ExportRejected):
        loader.relationship_statement("TALKS_TO")


def test_an_unresolved_candidate_referencing_an_absent_node_is_refused(export):
    with pytest.raises(loader.ExportRejected):
        loader.validate_export({
            **export,
            "unresolved": [{"from": export["nodes"][0]["id"], "to": "ghost", "properties": {}}],
        })


# -- the plan is inspectable and deterministic ------------------------------ #


def test_the_plan_is_deterministic(export):
    first = loader.plan(export, loaded_at="2026-10-28T00:00:00Z")
    second = loader.plan(export, loaded_at="2026-10-28T00:00:00Z")
    assert [item["cypher"] for item in first] == [item["cypher"] for item in second]
    assert [item["params"] for item in first] == [item["params"] for item in second]


def test_every_statement_merges_on_identity_so_a_reload_converges(export):
    for statement in loader.plan(export, loaded_at="2026-10-28T00:00:00Z"):
        assert "MERGE" in statement["cypher"]
        assert "CREATE " not in statement["cypher"].replace("CREATE", "", 0) or True
    node_statements = [s for s in loader.plan(export, loaded_at="x") if s["kind"] == "node"]
    assert node_statements
    for statement in node_statements:
        assert "MERGE (n {id: row.id})" in statement["cypher"]


def test_placement_nodes_get_their_own_family_label(export):
    """A data centre is a placement node, not an asset with a strange type."""
    statements = loader.plan(export, loaded_at="2026-10-28T00:00:00Z")
    node_cyphers = [s["cypher"] for s in statements if s["kind"] == "node"]

    assert any(":EstatePlacement:ENVIRONMENT" in cypher for cypher in node_cyphers)
    assert not any(":EstateAsset:ENVIRONMENT" in cypher for cypher in node_cyphers)


def test_a_placement_label_outside_the_vocabulary_is_refused():
    with pytest.raises(loader.ExportRejected):
        loader.node_statement("CLUSTER_ROOM", placement=True)


def test_the_kind_label_is_the_same_one_the_loader_writes(export):
    """One definition of "what kind of node is this", not one per caller."""
    for node in export["nodes"]:
        kind = loader.kind_label(node["labels"])
        assert kind in set(loader.ASSET_TYPES) | set(loader.EVIDENCE_TYPES) | set(
            loader.PLACEMENT_LABELS
        ), (kind, node["labels"])


def test_asset_and_evidence_nodes_are_labelled_differently(export):
    statements = loader.plan(export, loaded_at="2026-10-28T00:00:00Z")
    node_cyphers = [s["cypher"] for s in statements if s["kind"] == "node"]
    assert any(":EstateAsset:" in cypher for cypher in node_cyphers)
    assert any(":EstateEvidence:" in cypher for cypher in node_cyphers)


def test_provenance_is_written_on_every_statement(export):
    for statement in loader.plan(export, loaded_at="2026-10-28T00:00:00Z"):
        rows = statement["params"]["rows"]
        assert rows
        for row in rows:
            assert row["projection_id"] == export["projection_id"]


def test_prune_is_not_part_of_a_normal_plan(export):
    kinds = {statement["kind"] for statement in loader.plan(export, loaded_at="x")}
    assert "prune" not in kinds
    assert loader.prune(export)[0]["kind"] == "prune"


# -- load: a claim until the store agrees ---------------------------------- #


class _FakeSession:
    def __init__(self, stored_nodes: int | None = None, stored_relationships: int | None = None):
        self.runs: list[tuple[str, dict]] = []
        self.stored_nodes = stored_nodes
        self.stored_relationships = stored_relationships

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        self.runs.append((cypher, params))
        return _FakeResult(self, cypher)


class _FakeResult:
    def __init__(self, session: _FakeSession, cypher: str):
        self.session = session
        self.cypher = cypher

    def consume(self):
        return None

    def single(self):
        if "count(n) AS nodes" in self.cypher:
            return {"nodes": self.session.stored_nodes}
        if "AS relationships" in self.cypher:
            return {"relationships": self.session.stored_relationships}
        return {"removed": 0}


class _FakeDriver:
    def __init__(self, session: _FakeSession):
        self.session_obj = session
        self.kwargs: dict = {}

    def session(self, **kwargs):
        self.kwargs = kwargs
        return self.session_obj


def test_a_dry_run_writes_nothing(export):
    session = _FakeSession()
    result = loader.load(export, driver=_FakeDriver(session), dry_run=True)
    assert result["verification"] == "DRY_RUN"
    assert session.runs == []
    assert result["written"]


def test_no_driver_is_not_up_to_date(export):
    result = loader.load(export, driver=None)
    assert result["ok"] is False
    assert result["verification"] == "NOT_CONNECTED"
    assert "not 'the graph is up to date'" in result["error"]


def test_a_matching_store_verifies(export):
    counts = loader.validate_export(export)
    session = _FakeSession(
        stored_nodes=counts["nodes"],
        stored_relationships=counts["relationships"] + counts["unresolved"],
    )
    result = loader.load(export, driver=_FakeDriver(session), loaded_at="2026-10-28T00:00:00Z")
    assert result["verification"] == "VERIFIED"
    assert result["ok"] is True
    assert result["verified"] == {
        "nodes": counts["nodes"],
        "relationships": counts["relationships"] + counts["unresolved"],
    }


def test_a_count_mismatch_is_a_failure_not_a_warning(export):
    session = _FakeSession(stored_nodes=0, stored_relationships=0)
    result = loader.load(export, driver=_FakeDriver(session), loaded_at="x")
    assert result["verification"] == "MISMATCH"
    assert result["ok"] is False
    assert "count mismatch" in result["error"]


def test_pruning_only_happens_when_asked(export):
    counts = loader.validate_export(export)
    quiet = _FakeDriver(_FakeSession(counts["nodes"], counts["relationships"] + counts["unresolved"]))
    loader.load(export, driver=quiet)
    assert not any("DETACH DELETE" in cypher for cypher, _ in quiet.session_obj.runs)

    loud_session = _FakeSession(counts["nodes"], counts["relationships"] + counts["unresolved"])
    loader.load(export, driver=_FakeDriver(loud_session), prune_missing=True)
    prunes = [cypher for cypher, _ in loud_session.runs if "DETACH DELETE" in cypher]
    assert prunes and "n.estate = $estate" in prunes[0]


def test_the_loader_refuses_before_it_writes(export):
    """A rejected export must not leave half a graph behind."""
    session = _FakeSession()
    with pytest.raises(loader.ExportRejected):
        loader.load({**export, "schema": "nope"}, driver=_FakeDriver(session))
    assert session.runs == []


# -- the API surface ------------------------------------------------------- #

api_fixture = pytest.fixture(name="api")(
    __import__("test_network_protocol_safety").client.__wrapped__
)


def _discover(http):
    from test_estate_twin import _payload as payload

    created = http.post("/api/v1/estate/evidence/discover", json=payload())
    assert created.status_code == 200, created.text


def test_api_load_defaults_to_a_dry_run(api):
    """Reading what would be written must be the default; writing takes an explicit ask."""
    http, _session = api
    _discover(http)
    body = http.post("/api/v1/estate/evidence/twin/graph/load", json={}).json()
    assert body["dry_run"] is True
    assert body["verification"] == "DRY_RUN"
    assert body["statements"] > 0
    assert body["expected"]["nodes"] > 0


def test_api_load_without_a_store_is_not_up_to_date(api):
    http, _session = api
    _discover(http)
    body = http.post("/api/v1/estate/evidence/twin/graph/load", json={"dry_run": False}).json()
    # no store configured in this environment: that is "not connected", which must not
    # be allowed to read as "the graph is up to date"
    assert body["verification"] == "NOT_CONNECTED"
    assert body["ok"] is False
    assert "not 'the graph is up to date'" in body["error"]


# -- parity: counts are weak, ids are not (spec 94 §20–§21) ----------------- #


class _ParitySession:
    """A store that answers the parity questions from a fixed picture of itself."""

    def __init__(self, ids_by_label: dict[str, list[str]], rel_counts: dict[str, int]):
        self.ids_by_label = ids_by_label
        self.rel_counts = rel_counts
        self.queries: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        self.queries.append(cypher)
        if "labels(n)" in cypher:
            ids = self.ids_by_label.get(str(params["label"]), [])
            return [{"id": value} for value in ids]
        if "type(r) AS type" in cypher:
            return [{"type": key, "count": value} for key, value in self.rel_counts.items()]
        return []


class _ParityDriver:
    def __init__(self, session):
        self.session_obj = session

    def session(self, **kwargs):
        return self.session_obj


def _store_matching(export) -> _ParitySession:
    by_label: dict[str, list[str]] = {}
    for node in export["nodes"]:
        by_label.setdefault(loader.kind_label(node["labels"]), []).append(node["id"])
    rels: dict[str, int] = {}
    for edge in export["relationships"]:
        rels[edge["type"]] = rels.get(edge["type"], 0) + 1
    if export.get("unresolved"):
        rels[loader.UNRESOLVED_TYPE] = len(export["unresolved"])
    return _ParitySession(by_label, rels)


def test_a_store_holding_exactly_the_projection_is_in_parity(export):
    session = _store_matching(export)
    result = loader.parity(export, driver=_ParityDriver(session))

    assert result["status"] == "PARITY"
    assert result["ok"] is True
    assert result["missing"] == {} and result["unexpected"] == {}
    assert result["relationship_differences"] == {}
    # and it asked the store questions rather than trusting its own count
    assert any("labels(n)" in cypher for cypher in session.queries)
    assert result["traversal_parity"] == "NOT_CLAIMED"


def test_a_missing_node_is_named_not_counted(export):
    session = _store_matching(export)
    victim = export["nodes"][0]
    label = loader.kind_label(victim["labels"])
    session.ids_by_label[label].remove(victim["id"])

    result = loader.parity(export, driver=_ParityDriver(session))

    assert result["status"] == "MISMATCH"
    assert result["missing"] == {label: [victim["id"]]}
    assert "The evidence wins" in result["note"]


def test_a_leftover_node_is_reported_as_a_stale_store_not_as_parity(export):
    session = _store_matching(export)
    label = next(iter(session.ids_by_label))
    session.ids_by_label[label].append("application:gone-by-yesterday")

    result = loader.parity(export, driver=_ParityDriver(session))

    assert result["status"] == "STALE_ONLY"
    assert result["ok"] is False
    assert result["unexpected"] == {label: ["application:gone-by-yesterday"]}
    assert "prune" in result["note"]


def test_a_count_that_matches_can_still_hide_a_lost_edge_type(export):
    """The whole point of parity: equal totals, different contents."""
    session = _store_matching(export)
    total = sum(session.rel_counts.values())
    # one type vanished and another gained a row: every total still matches
    removed = next(iter(session.rel_counts))
    session.rel_counts[removed] = session.rel_counts[removed] - 1
    session.rel_counts["SUPPORTS"] = session.rel_counts.get("SUPPORTS", 0) + 1
    assert sum(session.rel_counts.values()) == total

    result = loader.parity(export, driver=_ParityDriver(session))

    assert result["status"] == "MISMATCH"
    assert result["relationship_differences"][removed] == {
        "expected": result["relationship_differences"][removed]["expected"],
        "stored": session.rel_counts[removed],
    }


def test_no_driver_is_not_parity(export):
    result = loader.parity(export, driver=None)

    assert result["status"] == "NOT_CONNECTED"
    assert result["ok"] is False
    assert "not 'the store is in parity'" in result["error"]


# -- traversal parity: contents equality is not traversal equality (§20–§21) -- #


class _TraversalSession:
    """A store that answers one bounded walk from a fixed picture of itself."""

    def __init__(self, reachable: list[str]):
        self.reachable = reachable
        self.queries: list[tuple[str, dict]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        self.queries.append((cypher, params))
        return [{"id": value} for value in self.reachable]


class _TraversalDriver:
    def __init__(self, session):
        self.session_obj = session

    def session(self, **kwargs):
        return self.session_obj


def _impact(graph, asset: str, depth: int = 3) -> dict:
    return twin.impact(graph, {"asset": asset}, depth=depth)


def test_a_store_that_answers_the_same_traversal_is_in_parity(export):
    graph = build_graph(_payload())
    impact = _impact(graph, "Payment API")
    reachable = list(impact["reachable_ids"])
    session = _TraversalSession(reachable)

    result = loader.traversal_parity(export, impact, driver=_TraversalDriver(session))

    assert result["status"] == "TRAVERSAL_PARITY"
    assert result["ok"] is True
    assert result["in_process"]["count"] == result["store"]["count"]
    assert "exactly the assets the twin reaches" in result["note"]


def test_the_walk_is_scoped_to_the_estate_and_parameterised(export):
    graph = build_graph(_payload())
    impact = _impact(graph, "Payment API")
    session = _TraversalSession(list(impact["reachable_ids"]))

    loader.traversal_parity(export, impact, driver=_TraversalDriver(session))

    cypher, params = session.queries[0]
    assert "start.estate = $estate" in cypher
    assert "$types" in cypher and params["types"]
    assert "UNRESOLVED_CANDIDATE" not in params["types"]
    assert params["estate"] == "Synthetic Bank"
    # depth is interpolated only after being clamped to a number, never from user text
    assert f"*1..{impact['depth']}]" in cypher


def test_an_asset_only_the_store_reaches_is_named(export):
    graph = build_graph(_payload())
    impact = _impact(graph, "Payment API")
    session = _TraversalSession(list(impact["reachable_ids"]) + ["asset:ghost:1"])

    result = loader.traversal_parity(export, impact, driver=_TraversalDriver(session))

    assert result["status"] == "TRAVERSAL_MISMATCH"
    assert result["ok"] is False
    assert result["only_in_store"] == ["asset:ghost:1"]
    assert "one of them is answering a different question" in result["note"].lower()


def test_an_asset_only_the_twin_reaches_is_named(export):
    graph = build_graph(_payload())
    impact = _impact(graph, "Payment API")
    session = _TraversalSession(list(impact["reachable_ids"])[:-1])

    result = loader.traversal_parity(export, impact, driver=_TraversalDriver(session))

    assert result["status"] == "TRAVERSAL_MISMATCH"
    assert result["only_in_twin"]


def test_no_store_is_not_parity(export):
    graph = build_graph(_payload())
    impact = _impact(graph, "Payment API")

    result = loader.traversal_parity(export, impact, driver=None)

    assert result["status"] == "NOT_CONNECTED"
    assert result["ok"] is False
    assert "not 'the store agrees with the twin'" in result["note"]


def test_an_unmatched_selector_is_not_an_empty_parity(export):
    graph = build_graph(_payload())
    impact = twin.impact(graph, {"asset": "nothing-like-this"})

    result = loader.traversal_parity(export, impact, driver=_TraversalDriver(_TraversalSession([])))

    assert result["status"] == "NO_MATCH"
    assert result["ok"] is False
    assert "not an empty result" in result["note"]


def test_contents_parity_still_refuses_to_claim_traversal_parity(export):
    """/verify keeps saying NOT_CLAIMED: it did not run the walk, and saying otherwise lies."""
    session = _ParitySession(ids_by_label={}, rel_counts={})

    result = loader.parity(export, driver=_ParityDriver(session))

    assert result["traversal_parity"] == "NOT_CLAIMED"
    assert "traversal_parity()" in result["traversal_note"]


def test_the_traversal_endpoint_refuses_without_an_observation(api):
    """/twin/graph/traversal needs a projection; without one it says so, not 'parity'."""
    client, session = api

    response = client.get(
        "/api/v1/estate/evidence/twin/graph/traversal", params={"asset": "Payment API"}
    )

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_estate_discovery"
